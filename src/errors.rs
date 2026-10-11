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
    #[error("Invalid segment size")]
    InvalidSegmentSize,
    #[error("Segment signature verification failed")]
    SegmentSignatureFailure,
    #[error("Segment Merkle root mismatch")]
    SegmentRootMismatch,
    #[error("Segment context mismatch")]
    SegmentContextMismatch,
    #[error("Counter discontinuity")]
    CounterDiscontinuity,
    #[error("Provisional tip mismatch")]
    ProvisionalTipMismatch,
    #[error("Session mismatch")]
    SessionMismatch,
    #[error("Receiver mismatch")]
    ReceiverMismatch,
    #[error("Payload hash mismatch")]
    PayloadHashMismatch,
    #[error("Segment already complete")]
    SegmentAlreadySealed,
    #[error("Incomplete segment")]
    IncompleteSegment,
}
