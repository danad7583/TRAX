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
    #[error("Unsupported signing or hash algorithm")]
    UnsupportedAlgorithm,
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
    #[error("Arithmetic overflow")]
    ArithmeticOverflow,
    #[error("Unknown DAG node or parent")]
    UnknownNode,
    #[error("Unknown branch")]
    UnknownBranch,
    #[error("Branch already exists")]
    BranchExists,
    #[error("Node does not extend the branch tip")]
    BranchTipMismatch,
    #[error("Unknown relationship participant")]
    UnknownParticipant,
    #[error("Signing key has been retired")]
    RetiredKey,
    #[error("Key epoch or rotation reference is not current")]
    AuthorityMismatch,
    #[error("Key has already been used in this relationship")]
    KeyReuse,
    #[error("DAG or configuration mismatch")]
    GraphContextMismatch,
    #[error("Duplicate DAG node")]
    DuplicateNode,
    #[error("Checkpoint signer coverage mismatch")]
    SignerMismatch,
    #[error("Storage error: {0}")]
    Storage(#[from] std::io::Error),
    #[error("Journal is incomplete or corrupt")]
    CorruptJournal,
    #[error("Journal write failed; reopen and inspect before further writes")]
    JournalPoisoned,
    #[error("Transmission exceeds the negotiated resource limit")]
    TransmissionLimit,
    #[error("Transmission expired; provisional data discarded")]
    TransmissionExpired,
    #[error("Unexpected session or transmission lifecycle state")]
    UnexpectedState,
}
