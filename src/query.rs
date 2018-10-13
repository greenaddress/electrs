use bitcoin::blockdata::block::Block;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::network::serialize::deserialize;
use bitcoin::util::hash::Sha256dHash;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use bincode;

use app::App;
use index::{compute_script_hash, TxInRow, TxOutRow, TxRow, RawTxRow};
use mempool::Tracker;
use metrics::Metrics;
use serde_json::Value;
use store::{ReadStore, Row};
use util::{FullHash, HashPrefix, HeaderEntry, Bytes, BlockMeta, BlockHeaderMeta, BlockStatus};

use errors::*;

pub struct FundingOutput {
    pub txn_id: Sha256dHash,
    pub height: u32,
    pub output_index: usize,
    pub value: u64,
}

type OutPoint = (Sha256dHash, usize); // (txid, output_index)

struct SpendingInput {
    txn_id: Sha256dHash,
    height: u32,
    funding_output: OutPoint,
    value: u64,
}

pub struct Status {
    confirmed: (Vec<FundingOutput>, Vec<SpendingInput>),
    mempool: (Vec<FundingOutput>, Vec<SpendingInput>),
}

fn calc_balance((funding, spending): &(Vec<FundingOutput>, Vec<SpendingInput>)) -> i64 {
    let funded: u64 = funding.iter().map(|output| output.value).sum();
    let spent: u64 = spending.iter().map(|input| input.value).sum();
    funded as i64 - spent as i64
}

impl Status {
    fn funding(&self) -> impl Iterator<Item = &FundingOutput> {
        self.confirmed.0.iter().chain(self.mempool.0.iter())
    }

    fn spending(&self) -> impl Iterator<Item = &SpendingInput> {
        self.confirmed.1.iter().chain(self.mempool.1.iter())
    }

    pub fn confirmed_balance(&self) -> i64 {
        calc_balance(&self.confirmed)
    }

    pub fn mempool_balance(&self) -> i64 {
        calc_balance(&self.mempool)
    }

    pub fn history(&self) -> Vec<(i32, Sha256dHash)> {
        let mut txns_map = HashMap::<Sha256dHash, i32>::new();
        for f in self.funding() {
            txns_map.insert(f.txn_id, f.height as i32);
        }
        for s in self.spending() {
            txns_map.insert(s.txn_id, s.height as i32);
        }
        let mut txns: Vec<(i32, Sha256dHash)> =
            txns_map.into_iter().map(|item| (item.1, item.0)).collect();
        txns.sort_unstable();
        txns
    }

    pub fn unspent(&self) -> Vec<&FundingOutput> {
        let mut outputs_map = HashMap::<OutPoint, &FundingOutput>::new();
        for f in self.funding() {
            outputs_map.insert((f.txn_id, f.output_index), f);
        }
        for s in self.spending() {
            if let None = outputs_map.remove(&s.funding_output) {
                warn!("failed to remove {:?}", s.funding_output);
            }
        }
        let mut outputs = outputs_map
            .into_iter()
            .map(|item| item.1) // a reference to unspent output
            .collect::<Vec<&FundingOutput>>();
        outputs.sort_unstable_by_key(|out| out.height);
        outputs
    }

    pub fn hash(&self) -> Option<FullHash> {
        let txns = self.history();
        if txns.is_empty() {
            None
        } else {
            let mut hash = FullHash::default();
            let mut sha2 = Sha256::new();
            for (height, txn_id) in txns {
                let part = format!("{}:{}:", txn_id.be_hex_string(), height);
                sha2.input(part.as_bytes());
            }
            sha2.result(&mut hash);
            Some(hash)
        }
    }
}

struct TxnHeight {
    txn: Transaction,
    height: u32,
}

fn merklize(left: Sha256dHash, right: Sha256dHash) -> Sha256dHash {
    let data = [&left[..], &right[..]].concat();
    Sha256dHash::from_data(&data)
}

// TODO: the functions below can be part of ReadStore.
fn txrow_by_txid(store: &ReadStore, txid: &Sha256dHash) -> Option<TxRow> {
    let key = TxRow::filter_full(&txid);
    let value = store.get(&key)?;
    Some(TxRow::from_row(&Row { key, value }))
}

fn rawtxrow_by_txid(store: &ReadStore, txid: &Sha256dHash) -> Option<RawTxRow> {
    let key = RawTxRow::filter_full(&txid);
    let value = store.get(&key)?;
    Some(RawTxRow::from_row(&Row { key, value }))
}

fn txrows_by_prefix(store: &ReadStore, txid_prefix: &HashPrefix) -> Vec<TxRow> {
    store
        .scan(&TxRow::filter_prefix(&txid_prefix))
        .iter()
        .map(|row| TxRow::from_row(row))
        .collect()
}

fn txids_by_script_hash(store: &ReadStore, script_hash: &[u8]) -> Vec<HashPrefix> {
    store
        .scan(&TxOutRow::filter(script_hash))
        .iter()
        .map(|row| TxOutRow::from_row(row).txid_prefix)
        .collect()
}

fn txids_by_funding_output(
    store: &ReadStore,
    txn_id: &Sha256dHash,
    output_index: usize,
) -> Vec<HashPrefix> {
    store
        .scan(&TxInRow::filter(&txn_id, output_index))
        .iter()
        .map(|row| TxInRow::from_row(row).txid_prefix)
        .collect()
}

pub fn get_block_meta(store: &ReadStore, blockhash: &Sha256dHash) -> Option<BlockMeta> {
    let key = [b"M", &blockhash[..]].concat();
    let value = store.get(&key)?;
    let meta: BlockMeta = bincode::deserialize(&value).unwrap();
    Some(meta)
}

struct TransactionCache {
    map: RwLock<HashMap<Sha256dHash, Transaction>>,
}

impl TransactionCache {
    fn new() -> TransactionCache {
        TransactionCache {
            map: RwLock::new(HashMap::new()),
        }
    }

    fn get_or_else<F>(&self, txid: &Sha256dHash, load_txn_func: F) -> Result<Transaction>
    where
        F: FnOnce() -> Result<Transaction>,
    {
        if let Some(txn) = self.map.read().unwrap().get(txid) {
            return Ok(txn.clone());
        }
        let txn = load_txn_func()?;
        self.map.write().unwrap().insert(*txid, txn.clone());
        Ok(txn)
    }
}

pub struct Query {
    app: Arc<App>,
    tracker: RwLock<Tracker>,
    tx_cache: TransactionCache,
}

impl Query {
    pub fn new(app: Arc<App>, metrics: &Metrics) -> Arc<Query> {
        Arc::new(Query {
            app,
            tracker: RwLock::new(Tracker::new(metrics)),
            tx_cache: TransactionCache::new(),
        })
    }

    fn load_txns_by_prefix(
        &self,
        store: &ReadStore,
        prefixes: Vec<HashPrefix>,
    ) -> Result<Vec<TxnHeight>> {
        let mut txns = vec![];
        for txid_prefix in prefixes {
            for tx_row in txrows_by_prefix(store, &txid_prefix) {
                let txid: Sha256dHash = deserialize(&tx_row.key.txid).unwrap();
                let txn = self
                    .tx_cache
                    .get_or_else(&txid, || self.load_txn(&txid, tx_row.height))?;
                txns.push(TxnHeight {
                    txn,
                    height: tx_row.height,
                })
            }
        }
        Ok(txns)
    }

    fn find_spending_input(
        &self,
        store: &ReadStore,
        funding: &FundingOutput,
    ) -> Result<Option<SpendingInput>> {
        let spending_txns: Vec<TxnHeight> = self.load_txns_by_prefix(
            store,
            txids_by_funding_output(store, &funding.txn_id, funding.output_index),
        )?;
        let mut spending_inputs = vec![];
        for t in &spending_txns {
            for input in t.txn.input.iter() {
                if input.previous_output.txid == funding.txn_id
                    && input.previous_output.vout == funding.output_index as u32
                {
                    spending_inputs.push(SpendingInput {
                        txn_id: t.txn.txid(),
                        height: t.height,
                        funding_output: (funding.txn_id, funding.output_index),
                        value: funding.value,
                    })
                }
            }
        }
        assert!(spending_inputs.len() <= 1);
        Ok(if spending_inputs.len() == 1 {
            Some(spending_inputs.remove(0))
        } else {
            None
        })
    }

    fn find_funding_outputs(&self, t: &TxnHeight, script_hash: &[u8]) -> Vec<FundingOutput> {
        let mut result = vec![];
        let txn_id = t.txn.txid();
        for (index, output) in t.txn.output.iter().enumerate() {
            if compute_script_hash(&output.script_pubkey[..]) == script_hash {
                result.push(FundingOutput {
                    txn_id: txn_id,
                    height: t.height,
                    output_index: index,
                    value: output.value,
                })
            }
        }
        result
    }

    fn confirmed_status(
        &self,
        script_hash: &[u8],
    ) -> Result<(Vec<FundingOutput>, Vec<SpendingInput>)> {
        let mut funding = vec![];
        let mut spending = vec![];
        let read_store = self.app.read_store();
        let txid_prefixes = txids_by_script_hash(read_store, script_hash);
        for t in self.load_txns_by_prefix(read_store, txid_prefixes)? {
            funding.extend(self.find_funding_outputs(&t, script_hash));
        }
        for funding_output in &funding {
            if let Some(spent) = self.find_spending_input(read_store, &funding_output)? {
                spending.push(spent);
            }
        }
        Ok((funding, spending))
    }

    fn mempool_status(
        &self,
        script_hash: &[u8],
        confirmed_funding: &[FundingOutput],
    ) -> Result<(Vec<FundingOutput>, Vec<SpendingInput>)> {
        let mut funding = vec![];
        let mut spending = vec![];
        let tracker = self.tracker.read().unwrap();
        let txid_prefixes = txids_by_script_hash(tracker.index(), script_hash);
        for t in self.load_txns_by_prefix(tracker.index(), txid_prefixes)? {
            funding.extend(self.find_funding_outputs(&t, script_hash));
        }
        // // TODO: dedup outputs (somehow) both confirmed and in mempool (e.g. reorg?)
        for funding_output in funding.iter().chain(confirmed_funding.iter()) {
            if let Some(spent) = self.find_spending_input(tracker.index(), &funding_output)? {
                spending.push(spent);
            }
        }
        Ok((funding, spending))
    }

    pub fn status(&self, script_hash: &[u8]) -> Result<Status> {
        let confirmed = self
            .confirmed_status(script_hash)
            .chain_err(|| "failed to get confirmed status")?;
        let mempool = self
            .mempool_status(script_hash, &confirmed.0)
            .chain_err(|| "failed to get mempool status")?;
        Ok(Status { confirmed, mempool })
    }

    fn lookup_confirmed_blockhash(
        &self,
        tx_hash: &Sha256dHash,
        block_height: Option<u32>,
    ) -> Result<Option<Sha256dHash>> {
        let blockhash = if self.tracker.read().unwrap().get_txn(&tx_hash).is_some() {
            None // found in mempool (as unconfirmed transaction)
        } else {
            // Lookup in confirmed transactions' index
            let height = match block_height {
                Some(height) => height,
                None => {
                    txrow_by_txid(self.app.read_store(), &tx_hash)
                        .chain_err(|| format!("not indexed tx {}", tx_hash))?
                        .height
                }
            };
            let header = self
                .app
                .index()
                .get_header(height as usize)
                .chain_err(|| format!("missing header at height {}", height))?;
            Some(*header.hash())
        };
        Ok(blockhash)
    }

    // Internal API for transaction retrieval
    fn load_txn(&self, tx_hash: &Sha256dHash, block_height: u32) -> Result<Transaction> {
        let blockhash = self.lookup_confirmed_blockhash(tx_hash, Some(block_height))?;
        self.app.daemon().gettransaction(tx_hash, blockhash)
    }

    // Read from txstore, fallback to reading from bitcoind rpc
    pub fn txstore_get(&self, txid: &Sha256dHash) -> Result<Transaction> {
        match rawtxrow_by_txid(self.app.read_store(), txid) {
            Some(row) => Ok(deserialize(&row.rawtx).chain_err(|| "cannot parse tx")?),
            None => {
                debug!("missing tx {} in txstore, asking node", txid);
                self.app.daemon().gettransaction(txid, self.lookup_confirmed_blockhash(txid, None)?)
            }
        }
    }

    // Get raw transaction from txstore, no bitcoind fallback
    pub fn txstore_get_raw(&self, txid: &Sha256dHash) -> Option<Bytes> {
        Some(rawtxrow_by_txid(self.app.read_store(), txid)?.rawtx)
    }

    // Public API for transaction retrieval (for Electrum RPC)
    // Fetched from bitcoind, includes tx confirmation information (number of confirmations and block hash)
    pub fn get_transaction(&self, tx_hash: &Sha256dHash, verbose: bool) -> Result<Value> {
        let blockhash = self.lookup_confirmed_blockhash(tx_hash, /*block_height*/ None)?;
        self.app
            .daemon()
            .gettransaction_raw(tx_hash, blockhash, verbose)
    }

    pub fn get_block(&self, blockhash: &Sha256dHash) -> Result<Block> {
        self.app
            .daemon()
            .getblock(blockhash)
    }

    pub fn get_block_header_with_meta(&self, blockhash: &Sha256dHash) -> Result<BlockHeaderMeta> {
        let header_entry = self.get_header_by_hash(blockhash)?;
        let meta = get_block_meta(self.app.read_store(), blockhash).ok_or("cannot load block meta")?;
        Ok(BlockHeaderMeta { header_entry, meta })
    }

    pub fn get_headers(&self, heights: &[usize]) -> Vec<HeaderEntry> {
        let index = self.app.index();
        heights
            .iter()
            .filter_map(|height| index.get_header(*height))
            .collect()
    }

    pub fn get_header_by_hash(&self, hash: &Sha256dHash) -> Result<HeaderEntry> {
        let header = self.app.index().get_header_by_hash(hash);
        Ok(header.chain_err(|| "no header found")?.clone())
    }

    pub fn get_best_header(&self) -> Result<HeaderEntry> {
        let last_header = self.app.index().best_header();
        Ok(last_header.chain_err(|| "no headers indexed")?.clone())
    }

    pub fn get_block_status(&self, hash: &Sha256dHash) -> BlockStatus {
        // get_header_by_hash looks up the height first, then fetches the header by that.
        // if the block is no longer the best block at this height, it'll return None.
        match self.app.index().get_header_by_hash(hash) {
            Some(header) => BlockStatus {
                in_best_chain: true,
                next_best: self.app.index().get_header(header.height() + 1).map(|h| h.hash().clone())
            },
            None => BlockStatus {
                in_best_chain: false,
                next_best: None,
            },
        }
    }

    pub fn get_merkle_proof(
        &self,
        tx_hash: &Sha256dHash,
        height: usize,
    ) -> Result<(Vec<Sha256dHash>, usize)> {
        let header_entry = self
            .app
            .index()
            .get_header(height)
            .chain_err(|| format!("missing block #{}", height))?;
        let block: Block = self.app.daemon().getblock(&header_entry.hash())?;
        let mut txids: Vec<Sha256dHash> = block.txdata.iter().map(|tx| tx.txid()).collect();
        let pos = txids
            .iter()
            .position(|txid| txid == tx_hash)
            .chain_err(|| format!("missing txid {}", tx_hash))?;
        let mut merkle = vec![];
        let mut index = pos;
        while txids.len() > 1 {
            if txids.len() % 2 != 0 {
                let last = txids.last().unwrap().clone();
                txids.push(last);
            }
            index = if index % 2 == 0 { index + 1 } else { index - 1 };
            merkle.push(txids[index]);
            index = index / 2;
            txids = txids
                .chunks(2)
                .map(|pair| merklize(pair[0], pair[1]))
                .collect()
        }
        Ok((merkle, pos))
    }

    pub fn broadcast(&self, txn: &Transaction) -> Result<Sha256dHash> {
        self.app.daemon().broadcast(txn)
    }

    pub fn update_mempool(&self) -> Result<()> {
        self.tracker.write().unwrap().update(self.app.daemon())
    }

    /// Returns [vsize, fee_rate] pairs (measured in vbytes and satoshis).
    pub fn get_fee_histogram(&self) -> Vec<(f32, u32)> {
        self.tracker.read().unwrap().fee_histogram().clone()
    }

    // Fee rate [BTC/kB] to be confirmed in `blocks` from now.
    pub fn estimate_fee(&self, blocks: usize) -> f32 {
        let mut total_vsize = 0u32;
        let mut last_fee_rate = 0.0;
        let blocks_in_vbytes = (blocks * 1_000_000) as u32; // assume ~1MB blocks
        for (fee_rate, vsize) in self.tracker.read().unwrap().fee_histogram() {
            last_fee_rate = *fee_rate;
            total_vsize += vsize;
            if total_vsize >= blocks_in_vbytes {
                break; // under-estimate the fee rate a bit
            }
        }
        last_fee_rate * 1e-5 // [BTC/kB] = 10^5 [sat/B]
    }
}
