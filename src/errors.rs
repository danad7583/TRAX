use thiserror::Error;

#[derive(Debug, Error)]
pub enum TraxError {
    #[error("Invalid or noncanonical CBOR")]
    Cbor,
    #[error("Invalid cryptographic material")]
    Crypto,
    #[error("Invalid input: {0}")]
    InvalidInput(&'static str),
    #[error("Unsupported signing or hash algorithm")]
    UnsupportedAlgorithm,
    #[error("Bad signature")]
    BadSignature,
    #[error("Invalid Merkle leaf count")]
    MerkleLeafCount,
    #[error("Transmission does not match authoritative context")]
    TransmissionContextMismatch,
    #[error("Relationship predecessor or identity mismatch")]
    RelationshipMismatch,
    #[error("External checkpoint does not match restored state")]
    CheckpointMismatch,
    #[error("Signing key is not the expected authorized sender")]
    SignerMismatch,
    #[error("Unknown relationship participant")]
    UnknownParticipant,
    #[error("Unknown history record")]
    UnknownNode,
    #[error("Payload hash or length mismatch")]
    PayloadHashMismatch,
    #[error("Arithmetic overflow")]
    ArithmeticOverflow,
    #[error("Transmission exceeds the negotiated resource limit")]
    TransmissionLimit,
    #[error("Transmission expired; provisional data discarded")]
    TransmissionExpired,
    #[error("Unexpected relationship or session lifecycle state")]
    UnexpectedState,
    #[error("Storage error: {0}")]
    Storage(#[from] std::io::Error),
    #[error("Journal is incomplete or corrupt")]
    CorruptJournal,
    #[error("Journal write failed; reopen and inspect before further writes")]
    JournalPoisoned,
}
