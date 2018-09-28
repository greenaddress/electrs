use bitcoin::util::hash::Sha256dHash;
use bitcoin::Transaction;
use bitcoin::BitcoinHash;
use bitcoin::network::serialize::serialize;
use bitcoin::network::encodable::{ConsensusEncodable, ConsensusDecodable};
use bitcoin::network::serialize::{SimpleEncoder, SimpleDecoder};
use bitcoin::network::serialize::Error;
use bitcoin::util::hash::Sha256dEncoder;

/// A block header, which contains all the block's information except
/// the actual transactions
#[derive(Copy, PartialEq, Eq, Clone)]
pub struct SignetBlockHeader {
    /// The protocol version. Should always be 1.
    pub version: u32,
    /// Reference to the previous block in the chain
    pub prev_blockhash: Sha256dHash,
    /// The root hash of the merkle tree of transactions in the block
    pub merkle_root: Sha256dHash,
    /// The timestamp of the block, as claimed by the miner
    pub time: u32,
    /// The target value below which the blockhash must lie, encoded as a
    /// a float (with well-defined rounding, of course)
    pub bits: u32,
    /// The nonce, selected to obtain a low enough blockhash
    pub nonce: u32,
    pub signature: PaddedSignature,
}

/// A Bitcoin block, which is a collection of transactions with an attached
/// proof of work.
#[derive(PartialEq, Eq, Clone)]
pub struct SignetBlock {
    /// The block header
    pub header: SignetBlockHeader,
    /// List of transactions contained in the block
    pub txdata: Vec<Transaction>
}


impl BitcoinHash for SignetBlockHeader {
    fn bitcoin_hash(&self) -> Sha256dHash {
        // Everything except signature goes into the hash
        let mut enc = Sha256dEncoder::new();
        self.version.consensus_encode(&mut enc).unwrap();
        self.prev_blockhash.consensus_encode(&mut enc).unwrap();
        self.merkle_root.consensus_encode(&mut enc).unwrap();
        self.time.consensus_encode(&mut enc).unwrap();
        self.bits.consensus_encode(&mut enc).unwrap();
        self.nonce.consensus_encode(&mut enc).unwrap();
        enc.into_hash()
    }
}


impl BitcoinHash for SignetBlock {
    fn bitcoin_hash(&self) -> Sha256dHash {
        Sha256dHash::from_data(&serialize(&self.header).unwrap())
    }
}

pub struct PaddedSignature([u8;77]);


impl<S: SimpleEncoder> ConsensusEncodable<S> for PaddedSignature {
    fn consensus_encode(&self, s: &mut S) -> Result <(), Error> {
        for el in self.0.iter() {
            s.emit_u8(*el).unwrap();
        }
        Ok(())
    }
}
impl<D: SimpleDecoder> ConsensusDecodable<D> for PaddedSignature {
    fn consensus_decode(d: &mut D) -> Result<PaddedSignature, Error> {
        let mut buffer = [0u8;77];
        for i in 0..77 {
            buffer[i]=d.read_u8()?;
        }
        Ok(PaddedSignature(buffer))
    }
}


macro_rules! impl_index_newtype {
    ($thing:ident, $ty:ty) => {
        impl ::std::ops::Index<::std::ops::Range<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::Range<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeTo<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::RangeTo<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeFrom<usize>> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, index: ::std::ops::RangeFrom<usize>) -> &[$ty] {
                &self.0[index]
            }
        }

        impl ::std::ops::Index<::std::ops::RangeFull> for $thing {
            type Output = [$ty];

            #[inline]
            fn index(&self, _: ::std::ops::RangeFull) -> &[$ty] {
                &self.0[..]
            }
        }

    }
}


macro_rules! impl_consensus_encoding {
    ($thing:ident, $($field:ident),+) => (
        impl<S: SimpleEncoder> ConsensusEncodable<S> for $thing {
            #[inline]
            fn consensus_encode(&self, s: &mut S) -> Result<(), Error> {
                $( self.$field.consensus_encode(s)?; )+
                Ok(())
            }
        }

        impl<D: SimpleDecoder> ConsensusDecodable<D> for $thing {
            #[inline]
            fn consensus_decode(d: &mut D) -> Result<$thing, Error> {
                Ok($thing {
                    $( $field: ConsensusDecodable::consensus_decode(d)?, )+
                })
            }
        }
    );
}

macro_rules! impl_array_newtype {
    ($thing:ident, $ty:ty, $len:expr) => {
        impl $thing {
            #[inline]
            /// Converts the object to a raw pointer
            pub fn as_ptr(&self) -> *const $ty {
                let &$thing(ref dat) = self;
                dat.as_ptr()
            }

            #[inline]
            /// Converts the object to a mutable raw pointer
            pub fn as_mut_ptr(&mut self) -> *mut $ty {
                let &mut $thing(ref mut dat) = self;
                dat.as_mut_ptr()
            }

            #[inline]
            /// Returns the length of the object as an array
            pub fn len(&self) -> usize { $len }

            #[inline]
            /// Returns whether the object, as an array, is empty. Always false.
            pub fn is_empty(&self) -> bool { false }

            #[inline]
            /// Returns the underlying bytes.
            pub fn as_bytes(&self) -> &[$ty; $len] { &self.0 }

            #[inline]
            /// Returns the underlying bytes.
            pub fn to_bytes(&self) -> [$ty; $len] { self.0.clone() }

            #[inline]
            /// Returns the underlying bytes.
            pub fn into_bytes(self) -> [$ty; $len] { self.0 }
        }

        impl<'a> From<&'a [$ty]> for $thing {
            fn from(data: &'a [$ty]) -> $thing {
                assert_eq!(data.len(), $len);
                let mut ret = [0; $len];
                ret.copy_from_slice(&data[..]);
                $thing(ret)
            }
        }

        impl ::std::ops::Index<usize> for $thing {
            type Output = $ty;

            #[inline]
            fn index(&self, index: usize) -> &$ty {
                let &$thing(ref dat) = self;
                &dat[index]
            }
        }

        impl_index_newtype!($thing, $ty);

        impl PartialEq for $thing {
            #[inline]
            fn eq(&self, other: &$thing) -> bool {
                &self[..] == &other[..]
            }
        }

        impl Eq for $thing {}

        impl PartialOrd for $thing {
            #[inline]
            fn partial_cmp(&self, other: &$thing) -> Option<::std::cmp::Ordering> {
                Some(self.cmp(&other))
            }
        }

        impl Ord for $thing {
            #[inline]
            fn cmp(&self, other: &$thing) -> ::std::cmp::Ordering {
                // manually implement comparison to get little-endian ordering
                // (we need this for our numeric types; non-numeric ones shouldn't
                // be ordered anyway except to put them in BTrees or whatever, and
                // they don't care how we order as long as we're consisistent).
                for i in 0..$len {
                    if self[$len - 1 - i] < other[$len - 1 - i] { return ::std::cmp::Ordering::Less; }
                    if self[$len - 1 - i] > other[$len - 1 - i] { return ::std::cmp::Ordering::Greater; }
                }
                ::std::cmp::Ordering::Equal
            }
        }

        #[cfg_attr(feature = "clippy", allow(expl_impl_clone_on_copy))] // we don't define the `struct`, we have to explicitly impl
        impl Clone for $thing {
            #[inline]
            fn clone(&self) -> $thing {
                $thing::from(&self[..])
            }
        }

        impl Copy for $thing {}

        impl ::std::hash::Hash for $thing {
            #[inline]
            fn hash<H>(&self, state: &mut H)
                where H: ::std::hash::Hasher
            {
                (&self[..]).hash(state);
            }

            fn hash_slice<H>(data: &[$thing], state: &mut H)
                where H: ::std::hash::Hasher
            {
                for d in data.iter() {
                    (&d[..]).hash(state);
                }
            }
        }


    }
}


impl_consensus_encoding!(SignetBlockHeader, version, prev_blockhash, merkle_root, time, bits, nonce, signature);
impl_consensus_encoding!(SignetBlock, header, txdata);

impl_array_newtype!(PaddedSignature, u8, 77);
