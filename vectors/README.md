# Canonical relationship transcript

`relationship.cbor` is a 33,040-byte deterministic CBOR transcript containing
the original three signed genesis nodes, two linked application sessions, six
signed request/response transmissions, both original initiator closures, the
complete traversable history and its final checkpoint. The second session is
initiated by the other peer. Session one contains two request/response rounds.

SHA-512/256 of the complete file:
`f9e1504e0aaa105315455f403500b3995a03e468620cc95df6726e25c7e9e957`.

Public fixed test seeds are `[1;32]` and `[2;32]`, genesis nonce `[3;32]`, and
session nonces `[4;32]` and `[5;32]`. These are conformance fixtures, never
deployment keys. Genesis uses unchanged schema 2 and its original signatures;
session schema 3 authenticates continuous predecessor state.

`tests/transcript.rs` verifies the fixed artifacts without recreating signatures.
`node tests/verify_transcript.cjs` independently implements CBOR, SHA-512/256,
Merkle construction, record IDs/digests and boundary checks, and uses
Node/OpenSSL Ed25519 to verify every original signature. It imports no TRAX code.

`cargo run --example generate_transcript` deliberately regenerates the file.
Normal tests never rewrite it. Review protocol and digest changes before
accepting a regenerated artifact, then rerun the independent verifier.

The separate `tests/fixtures/standalone_session.cbor` is rejected-format test
data only. It preserves earlier valid signed packet bytes for downgrade/domain
substitution regressions and proves unchanged genesis bytes. No historical
authentication implementation or positive compatibility path is retained.
