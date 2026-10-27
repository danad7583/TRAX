# Vectors

Some files remain structured placeholders for TRAX v1.1.0 conformance and must not be treated as
cryptographic evidence merely because they are present. Segment-proof conformance is exercised
with deterministic keys and event data in `tests/conformance.rs`; a future checked-in segment
vector must encode the complete ordered `SegmentProof` and signed `SegmentCommitmentV1`.

- Files are named by requirement mapping (see Conformance Test Plan).
- Keep binary CBOR/COSE as raw bytes; do not JSON-wrap in production.

## Transmission profile V2

`transmission_v2.cbor` is a complete frozen canonical transcript: three signed
genesis records, a three-packet request, a two-packet response, and the original
initiator-signed terminal artifact and final checkpoint. It uses public test
seeds `[1;32]` and `[2;32]`, genesis nonce `[3;32]`, session nonce `[4;32]`, and
SHA-512/256. These are test keys, never deployment keys.

The 6,160-byte vector's SHA-512/256 is
`1c524040831fa1f2c43fa1f68e6520fdef0982b1e83fa3dec177e309774dfaff`.
Rust admission tests consume the fixed signatures; the independent
`node tests/verify_transmission_vector.cjs` implementation reconstructs CBOR,
hash chains, count-bound Merkle roots and the complete transcript, then verifies
all original signatures using Node/OpenSSL Ed25519. It imports no TRAX code.
`cargo run --example transmission_vectors` explicitly regenerates this file;
normal tests never rewrite it. Changes require deliberate protocol review.
