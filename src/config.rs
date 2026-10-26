//! Explicit application-selected segment cadence.

use crate::errors::TraxError;
use serde::{Deserialize, Serialize};

/// Cadence selected by `ProtocolConfig::with_default_k`, recorded explicitly
/// in the resulting configuration and serialized genesis.
pub const DEFAULT_K: usize = 8;

/// A positive segment size representable by the signed commitment's `u32` K.
///
/// No implicit cadence is selected: applications must construct this value and
/// keep the same configuration at signing and receiving boundaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SegmentConfig {
    k: usize,
}

impl SegmentConfig {
    pub fn new(k: usize) -> Result<Self, TraxError> {
        if k == 0 || u32::try_from(k).is_err() {
            return Err(TraxError::InvalidSegmentSize);
        }
        Ok(Self { k })
    }

    pub const fn k(self) -> usize {
        self.k
    }
}

/// Signing algorithms understood by this protocol version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    #[serde(rename = "ed25519")]
    Ed25519,
}

/// Runtime-selected graph hashing; this is independent of the legacy hash32
/// helper's compile-time profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    #[serde(rename = "blake3")]
    Blake3,
    #[serde(rename = "sha512-256")]
    Sha512256,
}

/// Explicit shared configuration to bind into negotiated genesis state.
///
/// Fields cannot be changed independently. Deserialization takes the same
/// validation path as construction, including build-feature availability;
/// callers may also call `validate` when accepting a configuration boundary.
/// Algorithms are always explicit. `with_default_k` selects `DEFAULT_K` at
/// construction; serialized configurations must still include K.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, try_from = "ProtocolConfigWire")]
pub struct ProtocolConfig {
    k: usize,
    signing_algorithm: SigningAlgorithm,
    hash_algorithm: HashAlgorithm,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ProtocolConfigWire {
    k: usize,
    signing_algorithm: SigningAlgorithm,
    hash_algorithm: HashAlgorithm,
}

impl TryFrom<ProtocolConfigWire> for ProtocolConfig {
    type Error = TraxError;

    fn try_from(wire: ProtocolConfigWire) -> Result<Self, Self::Error> {
        Self::new(wire.k, wire.signing_algorithm, wire.hash_algorithm)
    }
}

impl ProtocolConfig {
    pub fn with_default_k(
        signing_algorithm: SigningAlgorithm,
        hash_algorithm: HashAlgorithm,
    ) -> Result<Self, TraxError> {
        Self::new(DEFAULT_K, signing_algorithm, hash_algorithm)
    }

    pub fn new(
        k: usize,
        signing_algorithm: SigningAlgorithm,
        hash_algorithm: HashAlgorithm,
    ) -> Result<Self, TraxError> {
        let config = Self {
            k,
            signing_algorithm,
            hash_algorithm,
        };
        config.validate()?;
        Ok(config)
    }

    pub const fn k(self) -> usize {
        self.k
    }

    pub const fn segment(self) -> SegmentConfig {
        SegmentConfig { k: self.k }
    }

    pub const fn signing_algorithm(self) -> SigningAlgorithm {
        self.signing_algorithm
    }

    pub const fn hash_algorithm(self) -> HashAlgorithm {
        self.hash_algorithm
    }

    pub fn validate(self) -> Result<(), TraxError> {
        SegmentConfig::new(self.k)?;
        if self.k <= 4 {
            return Err(TraxError::InvalidSegmentSize);
        }
        match self.signing_algorithm {
            SigningAlgorithm::Ed25519 if !cfg!(feature = "crypto-ed25519") => {
                return Err(TraxError::UnsupportedAlgorithm);
            }
            SigningAlgorithm::Ed25519 => {}
        }
        match self.hash_algorithm {
            HashAlgorithm::Blake3 if !cfg!(feature = "hash-blake3") => {
                return Err(TraxError::UnsupportedAlgorithm);
            }
            HashAlgorithm::Blake3 | HashAlgorithm::Sha512256 => {}
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn segment_size_is_explicit_positive_and_representable() {
        assert!(SegmentConfig::new(0).is_err());
        for k in [1, 3, 4, 5, 8, 14] {
            assert_eq!(SegmentConfig::new(k).unwrap().k(), k);
        }
        assert_eq!(
            SegmentConfig::new(u32::MAX as usize).unwrap().k(),
            u32::MAX as usize
        );
        if let Ok(too_large) = usize::try_from(u64::from(u32::MAX) + 1) {
            assert!(SegmentConfig::new(too_large).is_err());
        }
    }
}
