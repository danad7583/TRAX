//! Count-bound variable Merkle trees for logical transmissions.
//!
//! V2 domains, indexed leaves and recursive split shape are independent of the
//! legacy fixed-cadence roots. The streaming accumulator retains only hashes.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512_256};

use crate::config::HashAlgorithm;
use crate::TraxError;

pub type Hash = [u8; 32];
pub const MAX_MERKLE_LEAVES: usize = 1_048_576;
const MAX_DEPTH: usize = 20;
const LEAF_DOMAIN: &[u8] = b"TRAX:MERKLE:LEAF:V2\0";
const NODE_DOMAIN: &[u8] = b"TRAX:MERKLE:NODE:V2\0";
const ROOT_DOMAIN: &[u8] = b"TRAX:MERKLE:ROOT:V2\0";

/// Hashes a domain and borrowed parts incrementally, without concatenating data.
pub fn hash_v2(
    algorithm: HashAlgorithm,
    domain: &[u8],
    parts: &[&[u8]],
) -> Result<Hash, TraxError> {
    match algorithm {
        HashAlgorithm::Sha512256 => {
            let mut hasher = Sha512_256::new();
            hasher.update(domain);
            for part in parts {
                hasher.update(part);
            }
            Ok(hasher.finalize().into())
        }
        HashAlgorithm::Blake3 => {
            #[cfg(feature = "hash-blake3")]
            {
                let mut hasher = blake3::Hasher::new();
                hasher.update(domain);
                for part in parts {
                    hasher.update(part);
                }
                Ok(*hasher.finalize().as_bytes())
            }
            #[cfg(not(feature = "hash-blake3"))]
            {
                Err(TraxError::UnsupportedAlgorithm)
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct MerkleAccumulatorV2 {
    algorithm: HashAlgorithm,
    count: usize,
    frontier: [Option<Hash>; MAX_DEPTH + 1],
}

impl MerkleAccumulatorV2 {
    pub fn new(algorithm: HashAlgorithm) -> Result<Self, TraxError> {
        hash_v2(algorithm, b"", &[])?;
        Ok(Self {
            algorithm,
            count: 0,
            frontier: [None; MAX_DEPTH + 1],
        })
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Adds one indexed leaf. Hashing and bound checks finish before mutation.
    pub fn push(&mut self, data: &[u8]) -> Result<(), TraxError> {
        if self.count >= MAX_MERKLE_LEAVES {
            return Err(TraxError::InvalidSegmentSize);
        }
        let mut carry = leaf_hash(self.algorithm, self.count, data)?;
        let mut occupied = self.count;
        let mut height = 0;
        while occupied & 1 != 0 {
            let left = self.frontier[height].ok_or(TraxError::InvalidSegmentSize)?;
            carry = inner_hash(self.algorithm, &left, &carry)?;
            height += 1;
            occupied >>= 1;
        }
        for node in &mut self.frontier[..height] {
            *node = None;
        }
        self.frontier[height] = Some(carry);
        self.count += 1;
        Ok(())
    }

    pub fn root(&self) -> Result<Hash, TraxError> {
        validate_count(self.count)?;
        // Frontier entries are left-to-right subtrees in decreasing height.
        // Fold right-to-left to reproduce the largest-power-of-two split.
        let mut tree = None;
        for left in self.frontier.iter().flatten() {
            tree = Some(match tree {
                Some(right) => inner_hash(self.algorithm, left, &right)?,
                None => *left,
            });
        }
        count_root(
            self.algorithm,
            self.count,
            &tree.ok_or(TraxError::InvalidSegmentSize)?,
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InclusionProofV2 {
    pub leaf_index: u32,
    pub leaf_count: u32,
    /// Bottom-up siblings. Each hash is a fixed 32-byte CBOR byte string.
    #[serde(with = "hash_list")]
    pub siblings: Vec<Hash>,
}

pub fn merkle_root_v2(algorithm: HashAlgorithm, messages: &[Vec<u8>]) -> Result<Hash, TraxError> {
    validate_count(messages.len())?;
    let mut accumulator = MerkleAccumulatorV2::new(algorithm)?;
    for message in messages {
        accumulator.push(message)?;
    }
    accumulator.root()
}

pub fn merkle_root_and_proofs_v2(
    algorithm: HashAlgorithm,
    messages: &[Vec<u8>],
) -> Result<(Hash, Vec<InclusionProofV2>), TraxError> {
    validate_count(messages.len())?;
    hash_v2(algorithm, b"", &[])?;
    let count = u32::try_from(messages.len()).map_err(|_| TraxError::ArithmeticOverflow)?;
    let leaves = messages
        .iter()
        .enumerate()
        .map(|(index, message)| leaf_hash(algorithm, index, message))
        .collect::<Result<Vec<_>, _>>()?;
    let mut proofs = (0..count)
        .map(|index| InclusionProofV2 {
            leaf_index: index,
            leaf_count: count,
            siblings: Vec::new(),
        })
        .collect::<Vec<_>>();
    let tree = build_proofs(algorithm, &leaves, &mut proofs)?;
    Ok((count_root(algorithm, messages.len(), &tree)?, proofs))
}

pub fn verify_merkle_inclusion_v2(
    algorithm: HashAlgorithm,
    message: &[u8],
    proof: &InclusionProofV2,
    expected_root: &Hash,
) -> Result<bool, TraxError> {
    let count = proof.leaf_count as usize;
    let index = proof.leaf_index as usize;
    validate_count(count)?;
    if index >= count || proof.siblings.len() > MAX_DEPTH {
        return Err(TraxError::InvalidSegmentSize);
    }
    let leaf = leaf_hash(algorithm, index, message)?;
    let mut consumed = 0;
    let tree = reconstruct(
        algorithm,
        leaf,
        index,
        count,
        &proof.siblings,
        &mut consumed,
    )?;
    if consumed != proof.siblings.len() {
        return Err(TraxError::InvalidSegmentSize);
    }
    Ok(count_root(algorithm, count, &tree)? == *expected_root)
}

fn validate_count(count: usize) -> Result<(), TraxError> {
    if count == 0 || count > MAX_MERKLE_LEAVES {
        return Err(TraxError::InvalidSegmentSize);
    }
    Ok(())
}

fn leaf_hash(algorithm: HashAlgorithm, index: usize, data: &[u8]) -> Result<Hash, TraxError> {
    let index = u64::try_from(index)
        .map_err(|_| TraxError::ArithmeticOverflow)?
        .to_be_bytes();
    let length = u64::try_from(data.len())
        .map_err(|_| TraxError::ArithmeticOverflow)?
        .to_be_bytes();
    hash_v2(algorithm, LEAF_DOMAIN, &[&index, &length, data])
}

fn inner_hash(algorithm: HashAlgorithm, left: &Hash, right: &Hash) -> Result<Hash, TraxError> {
    hash_v2(algorithm, NODE_DOMAIN, &[left, right])
}

fn count_root(algorithm: HashAlgorithm, count: usize, tree: &Hash) -> Result<Hash, TraxError> {
    let count = u64::try_from(count)
        .map_err(|_| TraxError::ArithmeticOverflow)?
        .to_be_bytes();
    hash_v2(algorithm, ROOT_DOMAIN, &[&count, tree])
}

// Every caller supplies a bounded count greater than one, so this cannot
// overflow and is the largest power of two strictly smaller than count.
fn split(count: usize) -> usize {
    count.next_power_of_two() / 2
}

fn build_proofs(
    algorithm: HashAlgorithm,
    leaves: &[Hash],
    proofs: &mut [InclusionProofV2],
) -> Result<Hash, TraxError> {
    if leaves.len() == 1 {
        return Ok(leaves[0]);
    }
    let at = split(leaves.len());
    let (left_proofs, right_proofs) = proofs.split_at_mut(at);
    let left = build_proofs(algorithm, &leaves[..at], left_proofs)?;
    let right = build_proofs(algorithm, &leaves[at..], right_proofs)?;
    for proof in left_proofs {
        proof.siblings.push(right);
    }
    for proof in right_proofs {
        proof.siblings.push(left);
    }
    inner_hash(algorithm, &left, &right)
}

fn reconstruct(
    algorithm: HashAlgorithm,
    leaf: Hash,
    index: usize,
    count: usize,
    siblings: &[Hash],
    consumed: &mut usize,
) -> Result<Hash, TraxError> {
    if count == 1 {
        return Ok(leaf);
    }
    let at = split(count);
    let subtree = if index < at {
        reconstruct(algorithm, leaf, index, at, siblings, consumed)?
    } else {
        reconstruct(algorithm, leaf, index - at, count - at, siblings, consumed)?
    };
    let sibling = siblings
        .get(*consumed)
        .ok_or(TraxError::InvalidSegmentSize)?;
    *consumed += 1;
    if index < at {
        inner_hash(algorithm, &subtree, sibling)
    } else {
        inner_hash(algorithm, sibling, &subtree)
    }
}

mod hash_list {
    use super::{Hash, MAX_DEPTH};
    use serde::de::{Error, SeqAccess, Visitor};
    use serde::ser::SerializeSeq;
    use serde::{Deserialize, Deserializer, Serializer};
    use std::fmt;

    pub fn serialize<S: Serializer>(hashes: &[Hash], serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(hashes.len()))?;
        for hash in hashes {
            sequence.serialize_element(serde_bytes::Bytes::new(hash))?;
        }
        sequence.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Hash>, D::Error> {
        struct Hashes;
        impl<'de> Visitor<'de> for Hashes {
            type Value = Vec<Hash>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("at most 20 fixed-size hash byte strings")
            }
            fn visit_seq<A: SeqAccess<'de>>(
                self,
                mut sequence: A,
            ) -> Result<Self::Value, A::Error> {
                let mut hashes = Vec::new();
                while let Some(hash) = sequence.next_element::<HashBytes>()? {
                    if hashes.len() == MAX_DEPTH {
                        return Err(A::Error::custom("too many Merkle siblings"));
                    }
                    hashes.push(hash.0);
                }
                Ok(hashes)
            }
        }
        deserializer.deserialize_seq(Hashes)
    }

    struct HashBytes(Hash);
    impl<'de> Deserialize<'de> for HashBytes {
        fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
            struct Bytes;
            impl Visitor<'_> for Bytes {
                type Value = HashBytes;
                fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                    formatter.write_str("a 32-byte hash byte string")
                }
                fn visit_bytes<E: Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
                    bytes
                        .try_into()
                        .map(HashBytes)
                        .map_err(|_| E::custom("expected 32-byte hash"))
                }
            }
            deserializer.deserialize_bytes(Bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_accumulator_fails_before_mutating() {
        let mut accumulator = MerkleAccumulatorV2::new(HashAlgorithm::Sha512256).unwrap();
        accumulator.count = MAX_MERKLE_LEAVES;
        let before = accumulator.frontier;
        assert!(accumulator.push(b"over limit").is_err());
        assert_eq!(accumulator.len(), MAX_MERKLE_LEAVES);
        assert_eq!(accumulator.frontier, before);
    }
}
