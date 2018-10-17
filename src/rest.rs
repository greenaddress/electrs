use bitcoin::util::hash::{Sha256dHash,HexError};
use bitcoin::network::serialize::serialize;
use bitcoin::{Script,network,BitcoinHash};
use config::Config;
use elements::{TxIn,TxOut,OutPoint,Transaction};
use elements::confidential::{Value,Asset};
use errors;
use hex::{self, FromHexError};
use hyper::{Body, Response, Server, Method, Request, StatusCode};
use hyper::service::service_fn_ok;
use hyper::rt::{self, Future};
use query::Query;
use serde_json;
use serde::Serialize;
use std::collections::{HashMap,BTreeMap};
use std::error::Error;
use std::num::ParseIntError;
use std::thread;
use std::sync::Arc;
use url::form_urlencoded;
use daemon::Network;
use util::{HeaderEntry, BlockHeaderMeta, script_to_address};

const TX_LIMIT: usize = 50;

#[derive(Serialize, Deserialize)]
struct BlockValue {
    id: String,
    height: u32,
    timestamp: u32,
    tx_count: u32,
    size: u32,
    weight: u32,
    previousblockhash: Option<String>,
}

impl From<BlockHeaderMeta> for BlockValue {
    fn from(blockhm: BlockHeaderMeta) -> Self {
        let header = blockhm.header_entry.header();
        BlockValue {
            id: header.bitcoin_hash().be_hex_string(),
            height: blockhm.header_entry.height() as u32,
            timestamp: header.time,
            tx_count: blockhm.meta.tx_count,
            size: blockhm.meta.size,
            weight: blockhm.meta.weight,
            previousblockhash: if &header.prev_blockhash != &Sha256dHash::default() { Some(header.prev_blockhash.be_hex_string()) }
                               else { None },
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TransactionValue {
    txid: Sha256dHash,
    vin: Vec<TxInValue>,
    vout: Vec<TxOutValue>,
    size: u32,
    weight: u32,
}

impl From<Transaction> for TransactionValue {
    fn from(tx: Transaction) -> Self {
        let vin = tx.input.iter().map(|el| TxInValue::from(el.clone())).collect();
        let vout = tx.output.iter().map(|el| TxOutValue::from(el.clone())).collect();
        let bytes = serialize(&tx).unwrap();

        TransactionValue {
            txid: tx.txid(),
            vin,
            vout,
            size: bytes.len() as u32,
            weight: tx.get_weight() as u32,
        }
    }
}

#[derive(Serialize, Deserialize)]
struct TxInValue {
    outpoint: OutPoint,
    prevout: Option<TxOutValue>,
    scriptsig_hex: Script,
    scriptsig_asm: String,
    is_coinbase: bool,
}

impl From<TxIn> for TxInValue {
    fn from(txin: TxIn) -> Self {
        let is_coinbase = txin.is_coinbase();
        let script = txin.script_sig;
        let script_asm = format!("{:?}",script);

        TxInValue {
            outpoint: txin.previous_output,
            prevout: None, // added later
            scriptsig_asm: (&script_asm[7..script_asm.len()-1]).to_string(),
            scriptsig_hex: script,
            is_coinbase,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
struct TxOutValue {
    scriptpubkey_hex: Script,
    scriptpubkey_asm: String,
    scriptpubkey_address: Option<String>,
    asset: Option<String>,
    assetcommitment: Option<String>,
    value: Option<u64>,
    scriptpubkey_type: String,
}

impl From<TxOut> for TxOutValue {
    fn from(txout: TxOut) -> Self {
        let asset = match txout.asset {
            Asset::Explicit(value) => Some(value.be_hex_string()),
            _ => None
        };
        let assetcommitment = match txout.asset {
            Asset::Confidential(..) => Some(hex::encode(serialize(&txout.asset).unwrap())),
            _ => None
        };
        let value = match txout.value {
            Value::Explicit(value) => Some(value),
            _ => None,
        };
        let is_fee = txout.is_fee();
        let script = txout.script_pubkey;
        let script_asm = format!("{:?}",script);

        // TODO should the following something to put inside rust-elements lib?
        let script_type = if is_fee {
            "fee"
        } else if script.is_op_return() {
            "op_return"
        } else if script.is_p2pk() {
            "p2pk"
        } else if script.is_p2pkh() {
            "p2pkh"
        } else if script.is_p2sh() {
            "p2sh"
        } else if script.is_v0_p2wpkh() {
            "v0_p2wpkh"
        } else if script.is_v0_p2wsh() {
            "v0_p2wsh"
        } else if script.is_provably_unspendable() {
            "provably_unspendable"
        } else {
            "unknown"
        };

        TxOutValue {
            scriptpubkey_hex: script,
            scriptpubkey_asm: (&script_asm[7..script_asm.len()-1]).to_string(),
            scriptpubkey_address: None, // added later
            asset,
            assetcommitment,
            value,
            scriptpubkey_type: script_type.to_string(),
        }
    }
}


fn attach_tx_data(tx: TransactionValue, network: &Network, query: &Arc<Query>) -> TransactionValue {
    let mut txs = vec![tx];
    attach_txs_data(&mut txs, network, query);
    txs.remove(0)
}

fn attach_txs_data(txs: &mut Vec<TransactionValue>, network: &Network, query: &Arc<Query>) {
    // a map of prev txids/vouts to lookup, with a reference to the "next in" that spends them
    let mut lookups: BTreeMap<Sha256dHash, Vec<(u32, &mut TxInValue)>> = BTreeMap::new();
    // using BTreeMap ensures the txid keys are in order. querying the db with keys in order leverage memory
    // locality from empirical test up to 2 or 3 times faster

    for mut tx in txs.iter_mut() {
        // collect lookups
        for mut vin in tx.vin.iter_mut() {
            if !vin.is_coinbase && !vin.outpoint.is_pegin {
                lookups.entry(vin.outpoint.txid).or_insert(vec![]).push((vin.outpoint.vout, vin));
            }
        }
        // attach encoded address (should ideally happen in TxOutValue::from(), but it cannot
        // easily access the network)
        for mut vout in tx.vout.iter_mut() {
            vout.scriptpubkey_address = script_to_address(&vout.scriptpubkey_hex, &network);
        }
    }

    // fetch prevtxs and attach prevouts to nextins
    for (prev_txid, prev_vouts) in lookups {
        let prevtx = query.txstore_get(&prev_txid).unwrap();
        for (prev_out_idx, ref mut nextin) in prev_vouts {
            let mut prevout = TxOutValue::from(prevtx.output[prev_out_idx as usize].clone());
            prevout.scriptpubkey_address = script_to_address(&prevout.scriptpubkey_hex, &network);
            nextin.prevout = Some(prevout);
        }
    }

}


pub fn run_server(config: &Config, query: Arc<Query>) {
    let addr = ([127, 0, 0, 1], 3000).into();  // TODO take from config
    info!("REST server running on {}", addr);

    let network = config.network_type;

    let new_service = move || {

        let query = query.clone();

        service_fn_ok(move |req: Request<Body>| {
            match handle_request(req,&query,&network) {
                Ok(response) => response,
                Err(e) => {
                    warn!("{:?}",e);
                    bad_request()
                },
            }
        })
    };

    let server = Server::bind(&addr)
        .serve(new_service)
        .map_err(|e| eprintln!("server error: {}", e));

    thread::spawn(move || {
        rt::run(server);
    });
}

fn handle_request(req: Request<Body>, query: &Arc<Query>, network: &Network) -> Result<Response<Body>, StringError> {
    // TODO it looks hyper does not have routing and query parsing :(
    let uri = req.uri();
    let path: Vec<&str> = uri.path().split('/').skip(1).collect();
    let query_params = match uri.query() {
        Some(value) => form_urlencoded::parse(&value.as_bytes()).into_owned().collect::<HashMap<String, String>>(),
        None => HashMap::new(),
    };
    info!("path {:?} params {:?}", path, query_params);
    match (req.method(), path.get(0), path.get(1), path.get(2)) {
        (&Method::GET, Some(&"blocks"), None, None) => {
            let limit = query_params.get("limit")
                .map_or(10u32,|el| el.parse().unwrap_or(10u32) )
                .min(30u32);
            match query_params.get("start_height") {
                Some(height) => {
                    let height = height.parse::<usize>()?;
                    let headers = query.get_headers(&[height]);
                    match headers.get(0) {
                        None => Ok(http_message(StatusCode::NOT_FOUND, format!("can't find header at height {}", height))),
                        Some(val) => blocks(&query, &val, limit)
                    }
                },
                None => last_blocks(&query, limit),
            }
        },
        (&Method::GET, Some(&"block-height"), Some(height), None) => {
            let height = height.parse::<usize>()?;
            match query.get_headers(&[height]).get(0) {
                None => Ok(http_message(StatusCode::NOT_FOUND, format!("can't find header at height {}", height))),
                Some(val) => Ok(redirect(StatusCode::TEMPORARY_REDIRECT, format!("/block/{}", val.hash())))
            }
        },
        (&Method::GET, Some(&"block"), Some(hash), None) => {
            let hash = Sha256dHash::from_hex(hash)?;
            let blockhm = query.get_block_header_with_meta(&hash)?;
            let block_value = BlockValue::from(blockhm);
            json_response(block_value)
        },
        (&Method::GET, Some(&"block"), Some(hash), Some(&"txs")) => {
            let hash = Sha256dHash::from_hex(hash)?;
            let block = query.get_block(&hash)?;

            // @TODO optimization: skip deserializing transactions outside of range
            let mut start = query_params.get("start_index")
                .map_or(0u32, |el| el.parse().unwrap_or(0))
                .max(0u32) as usize;

            if start >= block.txdata.len() {
                return Ok(http_message(StatusCode::NOT_FOUND, "start index out of range".to_string()));
            } else if start % TX_LIMIT != 0 {
                return Ok(http_message(StatusCode::BAD_REQUEST, format!("start index must be a multipication of {}", TX_LIMIT)));
            }

            let mut txs = block.txdata.iter().skip(start).take(TX_LIMIT).map(|tx| TransactionValue::from(tx.clone())).collect();
            attach_txs_data(&mut txs, network, query);
            json_response(txs)
        },
        (&Method::GET, Some(&"tx"), Some(hash), None) => {
            let hash = Sha256dHash::from_hex(hash)?;
            let transaction = query.txstore_get(&hash)?;
            let mut value = TransactionValue::from(transaction);
            let value = attach_tx_data(value, network, query);
            json_response(value)
        },
        (&Method::GET, Some(&"tx"), Some(hash), Some(&"hex")) => {
            let hash = Sha256dHash::from_hex(hash)?;
            match query.txstore_get_raw(&hash) {
                Some(rawtx) => Ok(http_message(StatusCode::OK, hex::encode(rawtx))),
                None => Ok(http_message(StatusCode::NOT_FOUND, "Not Found".to_string())),
            }
        },
        _ => {
            Err(StringError(format!("endpoint does not exist {:?}",uri.path())))
        }
    }
}

fn http_message(status: StatusCode, message: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Content-Type", "text/plain")
        .header("Access-Control-Allow-Origin", "*")
        .body(Body::from(message))
        .unwrap()
}

fn bad_request() -> Response<Body> {
    // TODO should handle hyper unwrap but it's Error type is private, not sure
    http_message(StatusCode::BAD_REQUEST, "400 Bad Request".to_string())
}

fn json_response<T: Serialize>(value : T) -> Result<Response<Body>,StringError> {
    let value = serde_json::to_string(&value)?;
    Ok(Response::builder()
        .header("Content-type","application/json")
        .header("Access-Control-Allow-Origin", "*")
        .body(Body::from(value)).unwrap())
}

fn redirect(status: StatusCode, path: String) -> Response<Body> {
    Response::builder()
        .status(status)
        .header("Location", path.clone())
        .header("Content-Type", "text/plain")
        .header("Access-Control-Allow-Origin", "*")
        .body(Body::from(format!("See {}\n", path)))
        .unwrap()
}

fn last_blocks(query: &Arc<Query>, limit: u32) -> Result<Response<Body>,StringError> {
    let header_entry : HeaderEntry = query.get_best_header()?;
    blocks(query,&header_entry,limit)
}

fn blocks(query: &Arc<Query>, header_entry: &HeaderEntry, limit: u32)
    -> Result<Response<Body>,StringError> {
    let mut values = Vec::new();
    let mut current_hash = header_entry.hash().clone();
    let zero = [0u8;32];
    for _ in 0..limit {
        let blockhm = query.get_block_header_with_meta(&current_hash)?;
        current_hash = blockhm.header_entry.header().prev_blockhash.clone();
        values.push(BlockValue::from(blockhm));

        if &current_hash[..] == &zero[..] {
            break;
        }
    }
    json_response(values)
}

#[derive(Debug)]
struct StringError(String);

// TODO boilerplate conversion, use macros or other better error handling
impl From<ParseIntError> for StringError {
    fn from(e: ParseIntError) -> Self {
        StringError(e.description().to_string())
    }
}
impl From<HexError> for StringError {
    fn from(e: HexError) -> Self {
        StringError(e.description().to_string())
    }
}
impl From<FromHexError> for StringError {
    fn from(e: FromHexError) -> Self {
        StringError(e.description().to_string())
    }
}
impl From<errors::Error> for StringError {
    fn from(e: errors::Error) -> Self {
        StringError(e.description().to_string())
    }
}
impl From<serde_json::Error> for StringError {
    fn from(e: serde_json::Error) -> Self {
        StringError(e.description().to_string())
    }
}
impl From<network::serialize::Error> for StringError {
    fn from(e: network::serialize::Error) -> Self {
        StringError(e.description().to_string())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_fakestore() {
        let x = "a b c d  as asfas ";
        let y : Vec<&str> = x.split(' ').collect();
        println!("{:?}", y);
        let y : Vec<&str> = x.split(' ').filter(|el| !el.is_empty() ).collect();
        println!("{:?}", y);
    }

    #[test]
    fn test_opts() {
        let val = None.map(|el : u32| Some(1));
        println!("{:?}",val);
        let val = Some("1000").map(|el| el.parse().unwrap_or(10u32) )
            .min(Some(30u32)).unwrap();
        println!("{:?}",val);
        let val = None.map_or(10u32,|el: &str| el.parse().unwrap_or(10u32) )
            .min(30u32);
        println!("{:?}",val);
    }
}


