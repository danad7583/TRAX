use thiserror::Error;

#[derive(Debug, Error)]
pub enum TraxError {
    #[error("CBOR encoding/decoding error")]
    Cbor,
    #[error("COSE error")]
    Cose,
    #[error("Crypto error")]
    Crypto,
    #[error("Invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("Bad signature")]
    BadSignature,
    #[error("Stale counter")]
    StaleCounter,
    #[error("Tip mismatch")]
    TipMismatch,
    #[error("Fork suspected")]
    ForkSuspected,
    #[error("Rate limited")]
    RateLimited,
}
