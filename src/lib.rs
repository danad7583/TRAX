//! TRAX DAG parsing, immutable insertion, traversal and cryptographic verification.
//!
//! The K-free [`transmission::SessionV2`] profile authenticates entire logical
//! requests/responses after a three-node, explicitly authorized genesis.
//! [`transmission_storage::DurableSessionV2`] synchronizes before trusted release.
//! Legacy shared DAG state uses [`ProtocolConfig`]; [`SegmentConfig`] configures
//! legacy same-author windows. TRAX owns no sockets or model/network policy.

pub mod admission;
pub mod admission_dag;
pub mod config;
pub mod crypto;
pub mod dag;
pub mod encoding;
pub mod errors;
pub mod exchange;
pub mod genesis;
pub mod graph;
pub mod profile;
pub mod rate;
pub mod replay;
pub mod rotation;
pub mod session;
pub mod storage;
pub mod transmission;
pub mod transmission_crypto;
pub mod transmission_storage;
pub mod types;

#[cfg(feature = "python")]
mod python;
#[cfg(feature = "python")]
mod python_transmission;

pub use config::{HashAlgorithm, ProtocolConfig, SegmentConfig, SigningAlgorithm, DEFAULT_K};
pub use errors::TraxError;
pub use types::*;
