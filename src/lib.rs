//! TRAX v1.1.0 Core Library
//!
//! Implements canonical encoding (CBOR+COSE_Sign1), handshake/session binding,
//! DAG node + segment proofs, key rotation/quarantine, replay protection, and
//! rate limiting per the TRAX RFC v1.1.0.
//!
//! NOTE: Some parts are reference implementations; tune for your threat model.

pub mod types;
pub mod encoding;
pub mod crypto;
pub mod session;
pub mod dag;
pub mod replay;
pub mod rotation;
pub mod rate;
pub mod errors;

pub use types::*;
pub use errors::TraxError;
