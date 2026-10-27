//! Count-bound variable Merkle trees for complete logical transmissions.
//!
//! Leaves bind their index and byte length. Tree shape follows the largest
//! power-of-two split; the outer root binds the exact leaf count. The streaming
//! accumulator retains O(log N) hashes and never copies payloads.

use crate::config::HashAlgorithm;
use crate::crypto::{hash_domain, Hash};
use crate::TraxError;

pub const MAX_MERKLE_LEAVES: usize = 1_048_576;
const MAX_DEPTH: usize = 20;
// These wire-domain identifiers are preserved from the reviewed protocol.
const LEAF_DOMAIN: &[u8] = b"TRAX:MERKLE:LEAF:V2\0";
const NODE_DOMAIN: &[u8] = b"TRAX:MERKLE:NODE:V2\0";
const ROOT_DOMAIN: &[u8] = b"TRAX:MERKLE:ROOT:V2\0";
#[derive(Debug, Clone)]
pub struct MerkleAccumulator {
    algorithm: HashAlgorithm,
    count: usize,
    frontier: [Option<Hash>; MAX_DEPTH + 1],
}

impl MerkleAccumulator {
    pub fn new(algorithm: HashAlgorithm) -> Result<Self, TraxError> {
        hash_domain(algorithm, b"", &[])?;
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
            return Err(TraxError::MerkleLeafCount);
        }
        let mut carry = leaf_hash(self.algorithm, self.count, data)?;
        let mut occupied = self.count;
        let mut height = 0;
        while occupied & 1 != 0 {
            let left = self.frontier[height].ok_or(TraxError::MerkleLeafCount)?;
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
            &tree.ok_or(TraxError::MerkleLeafCount)?,
        )
    }
}

pub fn merkle_root(algorithm: HashAlgorithm, messages: &[Vec<u8>]) -> Result<Hash, TraxError> {
    validate_count(messages.len())?;
    let mut accumulator = MerkleAccumulator::new(algorithm)?;
    for message in messages {
        accumulator.push(message)?;
    }
    accumulator.root()
}

fn validate_count(count: usize) -> Result<(), TraxError> {
    if count == 0 || count > MAX_MERKLE_LEAVES {
        return Err(TraxError::MerkleLeafCount);
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
    hash_domain(algorithm, LEAF_DOMAIN, &[&index, &length, data])
}

fn inner_hash(algorithm: HashAlgorithm, left: &Hash, right: &Hash) -> Result<Hash, TraxError> {
    hash_domain(algorithm, NODE_DOMAIN, &[left, right])
}

fn count_root(algorithm: HashAlgorithm, count: usize, tree: &Hash) -> Result<Hash, TraxError> {
    let count = u64::try_from(count)
        .map_err(|_| TraxError::ArithmeticOverflow)?
        .to_be_bytes();
    hash_domain(algorithm, ROOT_DOMAIN, &[&count, tree])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exhausted_accumulator_fails_before_mutating() {
        let mut accumulator = MerkleAccumulator::new(HashAlgorithm::Sha512256).unwrap();
        accumulator.count = MAX_MERKLE_LEAVES;
        let before = accumulator.frontier;
        assert!(accumulator.push(b"over limit").is_err());
        assert_eq!(accumulator.len(), MAX_MERKLE_LEAVES);
        assert_eq!(accumulator.frontier, before);
    }
}
