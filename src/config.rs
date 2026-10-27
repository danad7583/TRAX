//! Explicit cryptographic profile and bounded transmission resources.

use crate::TraxError;
use serde::{Deserialize, Serialize};

/// Wire schema retained by the three-record authenticated genesis.
pub const GENESIS_SCHEMA_VERSION: u8 = 2;
/// Wire schema for continuous relationship sessions.
pub const SESSION_SCHEMA_VERSION: u8 = 3;
pub const MAX_TRANSMISSION_PACKETS: u32 = 1_048_576;
pub const MAX_TRANSMISSION_PAYLOAD_BYTES: u64 = 256 * 1024 * 1024;
pub const MAX_WIRE_PACKET_BYTES: u32 = 1024 * 1024;
pub const MAX_TRANSMISSION_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SigningAlgorithm {
    #[serde(rename = "ed25519")]
    Ed25519,
}

/// SHA-512/256 is always available; BLAKE3 requires its explicit build feature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    #[serde(rename = "blake3")]
    Blake3,
    #[serde(rename = "sha512-256")]
    Sha512256,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransmissionLimits {
    pub max_packets: u32,
    pub max_payload_bytes: u64,
    pub max_packet_payload_bytes: u32,
    pub max_wire_packet_bytes: u32,
    pub timeout_ms: u64,
}

impl Default for TransmissionLimits {
    fn default() -> Self {
        Self {
            max_packets: 16_384,
            max_payload_bytes: 16 * 1024 * 1024,
            max_packet_payload_bytes: 1400,
            max_wire_packet_bytes: 4096,
            timeout_ms: 30_000,
        }
    }
}

impl TransmissionLimits {
    pub fn validate(&self) -> Result<(), TraxError> {
        if self.max_packets == 0 || self.max_packets > MAX_TRANSMISSION_PACKETS {
            return Err(TraxError::InvalidInput(
                "packet-count limit is out of bounds",
            ));
        }
        if self.max_payload_bytes == 0 || self.max_payload_bytes > MAX_TRANSMISSION_PAYLOAD_BYTES {
            return Err(TraxError::InvalidInput(
                "transmission payload limit is out of bounds",
            ));
        }
        if self.max_wire_packet_bytes == 0 || self.max_wire_packet_bytes > MAX_WIRE_PACKET_BYTES {
            return Err(TraxError::InvalidInput(
                "encoded-packet limit is out of bounds",
            ));
        }
        if self.max_packet_payload_bytes == 0
            || u64::from(self.max_packet_payload_bytes) > self.max_payload_bytes
            || self.max_packet_payload_bytes > self.max_wire_packet_bytes
        {
            return Err(TraxError::InvalidInput(
                "per-packet payload limit is out of bounds",
            ));
        }
        if self.timeout_ms == 0 || self.timeout_ms > MAX_TRANSMISSION_TIMEOUT_MS {
            return Err(TraxError::InvalidInput(
                "provisional timeout is out of bounds",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransmissionProfile {
    pub version: u8,
    pub signing_algorithm: SigningAlgorithm,
    pub hash_algorithm: HashAlgorithm,
    pub limits: TransmissionLimits,
}

impl Default for TransmissionProfile {
    fn default() -> Self {
        Self {
            version: GENESIS_SCHEMA_VERSION,
            signing_algorithm: SigningAlgorithm::Ed25519,
            hash_algorithm: HashAlgorithm::Sha512256,
            limits: TransmissionLimits::default(),
        }
    }
}

impl TransmissionProfile {
    pub fn validate(&self) -> Result<(), TraxError> {
        if self.version != GENESIS_SCHEMA_VERSION {
            return Err(TraxError::InvalidInput(
                "unsupported transmission profile version",
            ));
        }
        match self.signing_algorithm {
            SigningAlgorithm::Ed25519 => {}
        }
        match self.hash_algorithm {
            HashAlgorithm::Blake3 if !cfg!(feature = "hash-blake3") => {
                return Err(TraxError::UnsupportedAlgorithm);
            }
            HashAlgorithm::Blake3 | HashAlgorithm::Sha512256 => {}
        }
        self.limits.validate()
    }
}
