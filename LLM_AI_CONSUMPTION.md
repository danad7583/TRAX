# TRAX implementation guide

Use source, tests, [README.md](README.md), and [docs/DAG.md](docs/DAG.md) as evidence. Do not infer a complete protocol from module names, benchmark labels, or requirement IDs.

## Scope and layers

TRAX is a library for deterministic DAG records, insertion/verification, explicit-cadence signed checkpoints, key authority, and durable history. Applications supply networking, connections, request routing, models/tools, policy decisions, and reactions to verification failures. TRAX does not determine malicious intent or send alerts.

Keep these layers distinct:

1. `PairDag` represents common immutable relationship history mirrored by peers, with explicit forks, shared configuration, independent checkpoint attestations, and durable replay verification.
2. `dag::TrustedSessionContext` and `ReceiveAdmissionWindow` are same-author, same-receiver session-batch helpers. Directional admission windows do not imply unrelated logical DAGs.
3. `LocalAdmissionDag` is a process-local Packet0 helper, not persistent pair storage or distributed synchronization.
4. Python bindings expose Rust-backed crypto/Packet0/session-window operations, not an agent host.

## Breaking representation change

Version 0.2 uses strict length-first deterministic CBOR: recursive encoded-length/byte map-key ordering, duplicate rejection, and exactly one canonical item. This replaces declaration/insertion-order prototype encoding.

Old prototype V1 bytes, hashes, node IDs, proofs, and signatures must not be carried into the new profile. There is no automatic migration. Retaining a V1 type name does not preserve encoding compatibility. The durable journal is version 3 for the new exchange-proof format. New shared-graph records/proofs are portable between builds supporting their selected algorithms; the legacy hash32 feature cannot silently change them. Verify against the profile recorded in genesis or the applicable configuration action. Legacy helper outputs still belong to their selected compile-time hash profile.

## Explicit shared protocol configuration

The host's authenticated genesis agreement binds one shared `ProtocolConfig`; the library validates it rather than performing network negotiation. `with_default_k(signing_algorithm, hash_algorithm)` selects K=8, while `new(k, signing_algorithm, hash_algorithm)` accepts an explicit override. Shared K must be greater than 4 (minimum 5) and fit u32. Algorithms remain explicit: supported signing is Ed25519; runtime hash selection is Blake3 or Sha512256. SHA-512/256 is always available and BLAKE3 requires the compiled feature. Unsupported selections fail rather than falling back. Serialization requires K and both algorithm fields, rejects unknown fields/algorithms, and validates K/build availability during deserialization. Omitting K does not select the construction helper's default.

All DAG events across all branches count toward shared K, including forks, rotations, configuration actions, control records, and padding. All remain provisional until a full checkpoint commits. An ordinary mixed-author segment requires one authorized participant's checkpoint signature. This attests the signer's DAG view, not every named author's independent signature or a network address. Rotation, configuration and closure have the additional bilateral requirements below.

`rotate(author, parent, branch, &old_key, &new_key)` starts at node 1 of a fresh segment on a new branch and requires current old-key authorization plus replacement-key possession proof. The peer's `acknowledge_and_pad(peer, &peer_key)` fills positions through K−2 with padding, records `Acknowledge` at K−1 and signs the exact prefix. The initiator replays that prefix and uses `accept_ack(&proof)`, then `finish_close()` to place `CloseConfirm` at K or `append` a real request in the final slot to continue. The final checkpoint must be signed by the initiator's current key: its replacement key after rotation. The unchanged peer and retired old key cannot finalize that exchange.

The detached K−1 proof is not an ordinary checkpoint and admits no partial history. `GraphSegmentProof.acknowledgment` embeds it; its hash is bound into the final checkpoint and close confirmation. `acknowledgment_for(proposal)` retrieves the peer evidence after commit. Both acknowledgment and full checkpoint must validate before accepted state advances.

`configure` is a current-key-authorized fork proposal at the first event of a fresh segment. The proposal and its exchange immediately use the new K/hash profile, while the old configuration tip and current key authorize the change. For old K=8 to new K=5, the prefix has four events and the initiator's final event is five. The accepted current configuration changes globally only on verified full commit, including later live continuations of older branches. Rotation changes only that participant's accepted key authority on commit; historical profiles and keys remain recorded.

No request/roundtrip or full ordinary segment is padded automatically. `request_close(author, branch)` explicitly opens a close proposal only when at least three slots remain; its peer acknowledgment step supplies filler. The final slot may carry a real request instead of close confirmation. Mutual protocol evidence cannot force a physical peer to stay connected.

Independent detached full-checkpoint attestations are retained with history; `checkpoint_for(participant, node_hash)` may retrieve an earlier proof after later records exist. Keep full checkpoints distinct from the exchange's detached prefix acknowledgment. Do not impose two signatures on ordinary full checkpoints or per-participant K at genesis.

## Separate same-author helpers

`SegmentConfig::new(k)` remains for legacy same-author session batching. K must be positive and fit u32; K=1 and odd sizes work. These helpers do not define the common graph's checkpoint signer policy.

Same-author session APIs:

- `LocalAdmissionDag::new(config)`
- `TrustedSessionContext::from_verified_state(config, ...)`
- `ReceiveAdmissionWindow::new(context) -> Result<...>`
- `create_segment_seal(config, key, events)`
- `verify_segment_proof_intrinsic(config, proof, key)`
- `verify_segment_proof_for_context(proof, context)`
- `ordered_merkle_root(config, events)`

Receivers enforce configured K against signed K. Staging remains provisional until a complete valid segment commits atomically. There is no partial commit or automatic padding. Restored count and counter/segment increments are checked for overflow. Restored context must already have been independently verified.

Shared-graph `profile::merkle_root` takes explicit ProtocolConfig, selects the runtime hash, computes only a root, and does not clone leaf payloads or construct proofs. The internal prefix root uses exactly K−1 leaves under the same profile. Legacy generic Merkle APIs take explicit SegmentConfig and support K=1, unlike shared ProtocolConfig. Odd final nodes are promoted unchanged; no duplicate/artificial leaves are introduced. Legacy inclusion proofs omit promotion levels and must match the exact path implied by K/index. Bare-root signatures, including explicit K8 raw helpers, are not admission seals.

## Helpers versus scaffolding

- Ed25519, hashing, Merkle commitments/proofs, and HKDF derivation are implemented helpers.
- Session derivation consumes supplied context/nonces and optional supplied shared-secret bytes; it is not an on-wire handshake.
- `crypto-x25519` is a dependency feature, not an implemented exchange/encryption stack.
- `rate::TokenBucket` works when the caller invokes it; no host policy is supplied.
- `replay::LastSeen` does not implement complete in-window duplicate filtering.
- Legacy rotation/quarantine types do not implement quarantine. Paired-DAG recorded key authority is separate.
- `encoding::cose_sign1` returns an explicit unsupported-operation error.
- The `no_std` feature name is not a working no-std guarantee.
- Historical vectors include placeholders; presence/nonempty contents are not proof of conformance.

## Validation and performance

~~~sh
cargo test
cargo check --all-targets
cargo bench --bench dag_benches
~~~

Python needs an extension build and separate pytest run. Default Cargo tests do not execute Python tests.

Inspect assertions: the deterministic-CBOR conformance test checks fixed expected bytes and a roundtrip; broader canonical checks live in `tests/encoding.rs`. Legacy segment tests exercise K1/3/4/5/8/14, odd Merkle paths, cross-K rejection, incomplete windows, and checked arithmetic. Shared profile tests reject K≤4. Shared graph and handshake tests cover ordinary checkpoints, old/new rotation proofs, detached peer prefix acknowledgment, final initiator authority, tampering/replay, continuation instead of closure, and configuration changes using new K immediately.

Do not reuse historical latency/throughput/speedup figures from the prototype. Its XOR cumulative-hash check was not authenticated segment verification. Local crypto measurements do not establish end-to-end networking/model performance.

Before claiming paired-DAG/storage behavior or test status, inspect the current implementation and actual validation results. Do not fill in missing host behavior.
