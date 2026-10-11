# Vectors

Some files remain structured placeholders for TRAX v1.1.0 conformance and must not be treated as
cryptographic evidence merely because they are present. Segment-proof conformance is exercised
with deterministic keys and event data in `tests/conformance.rs`; a future checked-in segment
vector must encode the complete ordered `SegmentProof` and signed `SegmentCommitmentV1`.

- Files are named by requirement mapping (see Conformance Test Plan).
- Keep binary CBOR/COSE as raw bytes; do not JSON-wrap in production.
