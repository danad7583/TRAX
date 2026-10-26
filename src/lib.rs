//! TRAX DAG parsing, immutable insertion, traversal and cryptographic verification.
//!
//! Applications negotiate an explicit [`ProtocolConfig`] before constructing
//! shared DAG state. [`SegmentConfig`] configures the separate same-author
//! session-window primitives. TRAX owns no sockets or model/network policy.

pub mod admission;
pub mod admission_dag;
pub mod config;
pub mod crypto;
pub mod dag;
pub mod encoding;
pub mod errors;
pub mod exchange;
pub mod graph;
pub mod profile;
pub mod rate;
pub mod replay;
pub mod rotation;
pub mod session;
pub mod storage;
pub mod types;

#[cfg(feature = "python")]
mod python;

pub use config::{HashAlgorithm, ProtocolConfig, SegmentConfig, SigningAlgorithm, DEFAULT_K};
pub use errors::TraxError;
pub use types::*;
