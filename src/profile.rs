//! Runtime-selected cryptography for explicitly negotiated graph profiles.
//!
//! SHA-512/256 is always available. BLAKE3 requires the `hash-blake3` feature;
//! unsupported selections fail rather than falling back to another algorithm.

use crate::config::{HashAlgorithm, ProtocolConfig, SegmentConfig};
use crate::errors::TraxError;
use sha2::{Digest, Sha512_256};

pub type Hash = [u8; 32];
const LEAF_DOMAIN: &[u8] = b"TRAX:SEGMENT:LEAF:V1\0";
const NODE_DOMAIN: &[u8] = b"TRAX:SEGMENT:NODE:V1\0";

pub fn hash_bytes(algorithm: HashAlgorithm, data: &[u8]) -> Result<Hash, TraxError> {
    hash_parts(algorithm, &[data])
}

/// Hashes a domain prefix and bytes incrementally without cloning the payload.
pub fn domain_hash(config: ProtocolConfig, domain: &[u8], bytes: &[u8]) -> Result<Hash, TraxError> {
    config.validate()?;
    hash_parts(config.hash_algorithm(), &[domain, bytes])
}

/// Computes only the root for exactly the negotiated K ordered messages.
///
/// Leaves and parents have separate domain prefixes. At each level an unpaired
/// final node is promoted unchanged, with no padding or duplicated leaf.
/// Payloads are hashed by reference;
/// only one vector of hashes is allocated and reduced in place. No inclusion
/// proofs or copied payload vector is constructed.
pub fn merkle_root(config: ProtocolConfig, messages: &[Vec<u8>]) -> Result<Hash, TraxError> {
    merkle_root_for_count(config, config.k(), messages)
}

/// Computes an exact positive leaf count under a validated shared profile.
/// This lets a detached K-1 prefix reuse the profile without inventing a
/// second negotiated configuration or relaxing the shared-profile minimum K.
pub(crate) fn merkle_root_for_count(
    config: ProtocolConfig,
    count: usize,
    messages: &[Vec<u8>],
) -> Result<Hash, TraxError> {
    config.validate()?;
    SegmentConfig::new(count)?;
    if messages.len() != count {
        return Err(TraxError::InvalidSegmentSize);
    }
    let mut level = messages
        .iter()
        .map(|message| hash_parts(config.hash_algorithm(), &[LEAF_DOMAIN, message]))
        .collect::<Result<Vec<_>, _>>()?;
    while level.len() > 1 {
        let width = level.len();
        let mut output = 0;
        for input in (0..width).step_by(2) {
            let left = level[input];
            level[output] = if input + 1 < width {
                let right = level[input + 1];
                hash_parts(config.hash_algorithm(), &[NODE_DOMAIN, &left, &right])?
            } else {
                left
            };
            output += 1;
        }
        level.truncate(output);
    }
    Ok(level[0])
}

fn hash_parts(algorithm: HashAlgorithm, parts: &[&[u8]]) -> Result<Hash, TraxError> {
    match algorithm {
        HashAlgorithm::Blake3 => {
            #[cfg(feature = "hash-blake3")]
            {
                let mut hasher = blake3::Hasher::new();
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
        HashAlgorithm::Sha512256 => {
            let mut hasher = Sha512_256::new();
            for part in parts {
                hasher.update(part);
            }
            Ok(hasher.finalize().into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::SigningAlgorithm;

    #[test]
    fn prefix_count_does_not_change_the_negotiated_profile() {
        let config =
            ProtocolConfig::new(5, SigningAlgorithm::Ed25519, HashAlgorithm::Sha512256).unwrap();
        let messages = vec![b"prefix".to_vec(); 4];
        assert!(merkle_root_for_count(config, 4, &messages).is_ok());
        assert!(merkle_root(config, &messages).is_err());
        assert!(merkle_root_for_count(config, 0, &[]).is_err());
        assert!(merkle_root_for_count(config, 3, &messages).is_err());
    }
}
