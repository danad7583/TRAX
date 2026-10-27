//! Authenticated relationships with continuous, mirrored cryptographic history.
//!
//! [`Relationship`] owns three-node genesis, ordered sessions, variable-length
//! transmissions and initiator closure. [`DurableRelationship`] synchronizes
//! verified history before trusted payload release. Applications own transport,
//! trust policy, routing, model execution and transactional application effects.

pub mod config;
pub mod crypto;
pub mod encoding;
pub mod errors;
pub mod genesis;
pub mod merkle;
pub mod session;
pub mod storage;
pub mod transmission;

#[cfg(feature = "python")]
mod python;

pub use config::{HashAlgorithm, SigningAlgorithm, TransmissionLimits, TransmissionProfile};
pub use crypto::Hash;
pub use errors::TraxError;
pub use genesis::VerifiedGenesis;
pub use session::{Relationship, Session};
pub use storage::DurableRelationship;
