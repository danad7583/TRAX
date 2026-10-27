//! Strict Ed25519 signatures and explicit domain-separated hashing.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use sha2::{Digest, Sha512_256};

use crate::config::HashAlgorithm;
use crate::TraxError;

pub type Hash = [u8; 32];

/// Hashes a domain and borrowed parts incrementally, without concatenating data.
///
/// The caller must provide an unambiguous domain and framing for variable-sized
/// parts. An unavailable algorithm is rejected, never replaced by another hash.
pub fn hash_domain(
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

/// Signs the exact caller-provided transcript; protocol callers supply their
/// complete domain-separated, canonical commitment.
pub fn ed25519_sign(key: &SigningKey, message: &[u8]) -> Vec<u8> {
    key.sign(message).to_bytes().to_vec()
}

/// Rejects malformed signatures and non-strict Ed25519 encodings/weak points.
pub fn ed25519_verify(key: &VerifyingKey, message: &[u8], signature: &[u8]) -> bool {
    Signature::from_slice(signature)
        .is_ok_and(|signature| key.verify_strict(message, &signature).is_ok())
}
