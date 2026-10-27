# Canonical API cutover

This is a breaking library and session-wire change. The only supported flow is
three signed genesis records, relationship-owned sessions, variable-length
transmissions authenticated on their last data packet, and initiator-signed
closure. Historical implementations remain in Git, not as compatibility APIs.

## Ownership inventory and removals

| Removed owner / interface | Existing callers before cleanup | Canonical responsibility |
| --- | --- | --- |
| `admission.rs`, `admission_dag.rs`; Packet 0 envelopes and `LocalAdmissionDag` | Old Python wrappers, same-author windows, handshake demos and retired lab | `genesis` verifies the complete three-node transcript and explicit identity acceptance |
| `dag.rs`; `TrustedSessionContext`, `ReceiveAdmissionWindow`, fixed segment seals and proofs | Old Python, fixed-window tests, old benchmark, AAICP's existing adapter | Relationship-owned complete-transmission staging and admission |
| `graph.rs`, `exchange.rs`; `PairDag`, fixed-cadence checkpoints, peer prefix acknowledgments and configuration exchanges | Their dedicated tests, shared graph demo and old storage | One ordered relationship history, typed traversal and original transmission/closure artifacts |
| Old `storage.rs`; `DurableDag` and checkpoint journal | Paired-graph tests and demo | One durable relationship journal with locking, re-verification and sync-before-release |
| `profile.rs`; K-selected root helpers | Old graph/exchange/storage plus incidental vector checksum calls | `crypto::hash_domain` and K-free `merkle` |
| `rotation.rs` placeholder structures and old graph rotation workflow | Historical wire containers and graph tests | No in-session rotation is supported; established keys cannot change, and current trust policy must reject retired identities |
| `replay.rs`, `rate.rs` | Old standalone tests / public helpers; neither canonical admission path uses them | Strict authoritative counters, transmission IDs, predecessor state and bounded staging; deployment rate policy remains external |
| Old `session.rs` HKDF derivation | Old conformance tests, Python wrappers, handshake demos | Session IDs derive from authenticated relationship context, including predecessor and ordinal |
| `transmission_crypto.rs` | Canonical transmission/genesis code and Merkle tests | Required variable Merkle primitives move to `merkle.rs`; negotiated hashing moves to `crypto.rs`; unused inclusion proofs are removed |
| `transmission_storage.rs` | Standalone-session durability tests | `storage.rs` becomes the sole journal owner for complete relationships |
| `python_transmission.rs` | The old combined Python module and transmission binding tests | One `python.rs` exposes only the canonical relationship API |
| `types.rs`; old AAIP messages, DAG/window records and proof containers | Superseded modules / tests / examples | Explicit canonical transmission, genesis and typed history records |
| K-specific `SegmentConfig`, `ProtocolConfig`, `DEFAULT_K` | Removed window/graph subsystems | Explicit `TransmissionProfile` and `TransmissionLimits` |
| Old `crypto` roots, bare-root signing, HKDF and compile-time `hash32` | Removed windows, Python and demos; two canonical tests used them only to manufacture rejected proofs | Agreed-profile domain hashing, strict Ed25519 and variable Merkle roots; incompatible bytes remain negative test data only |
| COSE scaffolding and generic permissive decoder | Old containers, tests and two demos | Deterministic CBOR plus bounded exact typed decoding |
| Unused public inclusion-proof API | Only its own test suite | Complete-transmission root reconstruction and independent root regression tests |
| `src/bin/test_perf.rs`, tracked swap file, `benches/dag_benches.rs` | Historical performance workflow | One canonical Criterion suite and heap measurement example |
| Old graph/exchange/handshake/profile/window/storage/vector test groups | Their corresponding removed implementations | Canonical genesis, Merkle, encoding, session, transmission, storage, adversarial and independent-vector suites |
| Old Packet 0 Python/TCP tests and alternate binding module | Historical Python API / lab workflow | One thin Rust-backed binding module and canonical Python suite |
| `examples/{aaip_scenario,handshake_client,handshake_server,mint_vectors,shared_dag}.rs` | Old Docker/runbook/demo modes | A canonical bidirectional, cross-session example |
| Historical placeholder vectors and unused loader | No executable canonical consumer | One independently checked complete relationship transcript and explicit incompatible-wire rejection fixture |
| Duplicate Dockerfile, Compose and mode-dispatch entrypoint | Historical AAIP demo | One root build/demo image |

Generic security assertions are transferred, rather than preserving obsolete
implementations merely to keep their test counts. The canonical suites cover
strict signatures, weak/malformed keys, encoding ambiguity, actual payload
hashes, atomic rejection, resource limits, parser limits, replay, locks, stale
pins, corrupt/incomplete journals and failed writes.

Direct dependencies `coset`, `hkdf`, `lru`, `x25519-dalek`, `half` and
`rand_core` have no required canonical production consumer and are removed.
Transitive dependencies remain where required by CBOR, Ed25519 or RNG crates.
Mandatory Ed25519/Serde are no longer pretend optional features. Unsupported
`no_std`, `crypto-x25519` and redundant algorithm/serialization feature flags
are removed. Optional BLAKE3 and Python are the supported feature choices.

## Permanent names

Suffix-bearing public transmission, genesis, context, checkpoint, terminal,
profile, limit and accumulator types lose their iteration suffix. In particular
`VerifiedGenesisV2 -> VerifiedGenesis`, `PacketV2 -> Packet`,
`TransmissionCommitmentV2 -> TransmissionCommitment`,
`VerifiedTransmissionV2 -> VerifiedTransmission`, and
`MerkleAccumulatorV2 -> MerkleAccumulator`.

| Previous public component | Canonical public component |
| --- | --- |
| `GenesisStepV2`, `GenesisEventV2`, `GenesisNodeV2`, `VerifiedGenesisV2` | `genesis::{GenesisStep,GenesisEvent,GenesisNode,VerifiedGenesis}` |
| `genesis::{TransmissionProfileV2,TransmissionLimitsV2}` | `config::{TransmissionProfile,TransmissionLimits}` |
| `SessionV2` | `session::Relationship` owns authority; `session::Session` is read-only session state |
| `SessionContextV2` | `transmission::SessionContext`, now with authenticated predecessor fields |
| `PacketV2`, `PacketEventV2` | `transmission::{Packet,PacketEvent}` |
| `TransmissionKindV2`, `TransmissionCommitmentV2`, `TransmissionSealV2` | `transmission::{TransmissionKind,TransmissionCommitment,TransmissionSeal}` |
| `VerifiedTransmissionV2` | `transmission::VerifiedTransmission`, still no unchecked public constructor |
| `CommittedNodeV2` | `session::HistoryRecord` with typed packet/start/genesis/terminal variants |
| `SessionCloseCommitmentV2`, `SessionTerminalV2` | `transmission::{SessionCloseCommitment,SessionTerminal}` with both history boundaries |
| `SessionCheckpointV2` | `transmission::SessionCheckpoint` for inspection; `RelationshipCheckpoint` is the complete durable external pin |
| `MerkleAccumulatorV2` | `merkle::MerkleAccumulator` |
| `hash_v2` | `crypto::hash_domain` |
| `merkle_root_v2` | `merkle::merkle_root` |
| `event_tip_v2` | `transmission::event_tip` |
| `InclusionProofV2`, root-and-proof creation and inclusion verification | Removed; no current complete-transmission consumer |
| `DurableSessionV2` | `storage::DurableRelationship`, protecting the complete relationship across sessions |
| Python `TransmissionSessionV2` | Python `Relationship`, explicit `begin_session` and read-only session/history inspection |
| Python `tx_genesis_offer`, `tx_genesis_accept`, `tx_genesis_confirm` | `create_genesis_offer`, `accept_genesis_offer`, `confirm_genesis` |
| Python `generate_nonce` | Same permanent helper, now canonical 32-byte nonces instead of old 16-byte data |
| `genesis::TRANSMISSION_VERSION_V2` | `config::{GENESIS_SCHEMA_VERSION=2,SESSION_SCHEMA_VERSION=3}`, separating unchanged genesis from the new session schema |
| `genesis::{MAX_TRANSMISSION_PACKETS_V2,MAX_TRANSMISSION_PAYLOAD_BYTES_V2,MAX_WIRE_PACKET_BYTES_V2,MAX_TRANSMISSION_TIMEOUT_MS_V2}` | Same names without `_V2`, under `config` |
| `transmission_crypto::{Hash,MAX_MERKLE_LEAVES}` | `crypto::Hash`, `merkle::MAX_MERKLE_LEAVES` |
| `SessionV2` receive/build/fragment/close methods | Methods on the authoritative `Relationship` |
| `SessionV2::{nodes,node}` | `Relationship::{history,record}`, covering every accepted record kind |
| `DurableSessionV2::session()` | `DurableRelationship::relationship()`; opening and checkpoints require the whole `RelationshipCheckpoint` |

Shared genesis creation/acceptance/confirmation function names remain stable;
their parameter/result types use the canonical owners. Generic Ed25519 signing
and strict verification helpers remain crypto primitives, never admission tokens.
Specifically, `config::{SigningAlgorithm,HashAlgorithm}`, `errors::TraxError`
(with canonical error variants), `crypto::{ed25519_sign,ed25519_verify}` and
`genesis::{genesis_node_id,create_genesis_offer,accept_genesis_offer,confirm_genesis}`
retain their names. `encode_deterministic` and `decode_strict` also remain.
The old freely constructible `session::Session { pub session_id }` is removed;
it is not the new relationship-owned, read-only `Session` despite the same name.

Standalone `SessionV2::new(genesis, ...)` is replaced structurally by
`Relationship::new(verified_genesis)` and `Relationship::begin_session(...)`.
`Session` is relationship-owned read-only session state, not an unchecked new
authority. `DurableSessionV2` becomes `DurableRelationship`, since the journal
must protect continuity through multiple sessions. Python uses the same
relationship authority. No compatibility aliases survive.

Removed Python exports are `LocalDag`, `TrustedSessionContext`,
`ReceiveAdmissionWindow`, `create_post_genesis_event_v1`, `create_segment_seal`,
`verify_segment_seal_intrinsic`, `verify_segment_seal_for_context`, `receiver_id`,
`create_admission_envelope_v1`, `decode_admission_envelope_v1`,
`verify_admission_envelope_v1`, `verify_admission_envelope_v1_for_receiver`,
`derive_session_id` and `hash32`. These exports are removed without compatibility
aliases; use verified genesis plus `Relationship` staging/admission. Generic
signature/hash helpers are not admission tokens. `PrivateKey`,
`generate_keypair`, `sign_message` and `verify_message` remain cryptographic
helpers with their existing permanent names.

The following table names the remaining retired Rust exports explicitly.
All methods belonging solely to these removed owners are removed with them.
The replacement column describes responsibility, not wire compatibility or a
one-for-one alias.

| Removed public owner and components | Canonical replacement or disposition |
| --- | --- |
| `admission::{ADMISSION_ENVELOPE_VERSION,KEY_LEN,HASH_LEN,NONCE_LEN,SIGNATURE_LEN,AdmissionEnvelopeV1,AdmissionEnvelopeV1Unsigned,create_admission_envelope_v1,decode_admission_envelope_v1,verify_admission_envelope_v1,verify_admission_envelope_v1_for_receiver}` | Three-node verified genesis and explicit trust acceptance |
| `admission_dag::{PACKET0_ADMISSION_OP,AdmittedPacket0Event,AdmittedPacket0Node,LocalAdmissionDag}` | Complete accepted genesis transcript as the relationship root |
| `dag::{POST_GENESIS_EVENT_VERSION,SEGMENT_COMMITMENT_VERSION,lineage_key_id,receiver_id,TrustedSessionContext,event_bytes,event_tip,ordered_merkle_root,commitment_signing_bytes,create_segment_seal,verify_segment_proof_intrinsic,verify_segment_proof_for_context,ReceiveAdmissionWindow}` | Relationship-owned, expected-peer-pinned transmission admission; current event hashing is `transmission::event_tip` |
| `types::{ProtectedHeaders,AaipMessage,RotationBlock,DagNode,PostGenesisEventV1,SegmentCommitmentV1,SegmentSealV1,SegmentProof,AcceptanceWindow}` and their former crate-root glob exports | Canonical genesis, packet, commitment and typed history records; no AAIP/COSE or fixed-window replacement |
| `graph::{NodeId,BranchId,ParticipantId,participant_id,PairGenesis,GraphOperation,GraphEvent,GraphCommitment,AuthorityId,CheckpointAttestation,GraphSegmentProof,ParticipantAuthority,KeyIdentity,PairDag,PendingSegment}` | `Relationship`, complete typed history and traversal; arbitrary branching, merging and in-session authenticated rotation are unsupported |
| `exchange::{PrefixContext,PrefixCommitment,PrefixAcknowledgment}` | Ordinary authenticated transmissions and initiator-only original closure; no bilateral checkpoint exchange |
| `rate::TokenBucket`, `replay::LastSeen`, `rotation::{RotationProof,QuarantineState}` | Authoritative continuity/counters enforce protocol replay checks; rate/quarantine policy stays outside TRAX; rotation is unsupported |
| `config::{DEFAULT_K,SegmentConfig,ProtocolConfig}`, `session::derive_session_id`, `storage::DurableDag` | Explicit transmission profile/limits, predecessor-bound session IDs and `DurableRelationship` |
| `crypto::{K8_MERKLE_DEPTH,MerkleProof,MerkleProofs,hash32,hkdf_extract_expand,ed25519_sign_merkle_root_raw,ed25519_sign_merkle_root_k8_raw,merkle_root_k8,merkle_root_and_proofs_k8,merkle_root,root_and_proofs,verify_merkle_inclusion_k8,verify_merkle_inclusion}` | Agreed-profile `hash_domain`, strict Ed25519 and `merkle::merkle_root`; no HKDF, fixed tree or bare-root admission path |
| `profile::{Hash,hash_bytes,domain_hash,merkle_root}`, `transmission::Hash`, `transmission_crypto::Hash` | One `crypto::Hash` and `crypto::hash_domain`; variable tree under `merkle` |
| `transmission_crypto::{InclusionProofV2,merkle_root_and_proofs_v2,verify_merkle_inclusion_v2}` | Removed unused public proof API |
| `encoding::{decode,cose_sign1}` | Exact bounded `decode_strict`; no permissive/COSE compatibility path |

`TraxError` removes the obsolete variants `Cose`, `StaleCounter`, `TipMismatch`,
`ForkSuspected`, `RateLimited`, `InvalidSegmentSize`, `SegmentSignatureFailure`,
`SegmentRootMismatch`, `SegmentContextMismatch`, `CounterDiscontinuity`,
`ProvisionalTipMismatch`, `SessionMismatch`, `ReceiverMismatch`,
`SegmentAlreadySealed`, `IncompleteSegment`, `UnknownBranch`, `BranchExists`,
`BranchTipMismatch`, `RetiredKey`, `AuthorityMismatch`, `KeyReuse`,
`GraphContextMismatch` and `DuplicateNode`. New variants are `MerkleLeafCount`,
`TransmissionContextMismatch`, `RelationshipMismatch` and `CheckpointMismatch`.
`SignerMismatch` and `UnknownNode` retain their names with canonical signer and
history meanings. Match canonical errors directly; removed graph/window error
variants are not compatibility-mapped.

## Authenticated cutover

The established genesis schema and variable Merkle construction retain their
existing authenticated encodings and domains. Session/transmission/closure
schema 3 deliberately adds continuous relationship predecessor context and a
traversable session-start record authenticated by the first transmission's
existing signature. Old standalone-session signatures are incompatible and
are rejected. Exact bytes and domains are specified in PROTOCOL.md.

The new complete transcript is regenerated and verified independently using
Node/OpenSSL and independent CBOR/Merkle/history reconstruction. Package
versions advance to 0.3.0. No old journals are automatically reinterpreted.

## External consumers

TRAX-Transport-Lab is retired research. Its old adapter/import checks and
fixed-window scenarios will break intentionally; there is no migration,
compatibility wrapper, patch plan, or continued integration test for it.
Nothing in that repository is changed.

AAICP is the next Rust consumer. Its currently checked-in adapter still imports
removed Packet 0, window, hash and session-derivation APIs in `session.rs`,
`segment.rs`, `wire.rs` and `node.rs`. That code must integrate the canonical
relationship API in a separate AAICP change; it is not modified here. TRAX
owns cryptographic history and admission; AAICP owns transport, orchestration,
agent decisions, model/tool execution and application authorization.

## Documentation and tooling inventory

README, the AI implementation guide, DAG contract and runbook are rewritten
around one canonical path. The exact wire specification becomes PROTOCOL.md;
SECURITY.md collects trust/deployment limits; PERFORMANCE.md contains fresh
measurements of the cleaned implementation. The three iteration-named protocol,
delivery and performance documents are removed. This cutover guide retains the
deletion/naming inventory needed by the next consumer rather than presenting
historical protocols as supported choices.

The independent verifier, transcript fixture and generator become
`verify_transcript.cjs`, `relationship.cbor` and `generate_transcript.rs`.
The canonical Python suite becomes `test_python_bindings.py`; genesis, Merkle,
storage and transcript tests use permanent responsibility names. One root
Dockerfile runs the canonical `session` example. The duplicate Dockerfile,
Compose and mode dispatcher are removed, along with the tracked editor swap.
The supported Cargo matrix is default, all features and no-default SHA-only;
required Ed25519/serialization cannot be disabled. The API guard rejects retired
exports and temporary component/artifact names while allowing cryptographic
schema/domain literals and historical references.

| Previous artifact | Canonical artifact or disposition |
| --- | --- |
| `examples/transmission_v2.rs` | `examples/session.rs` |
| `examples/transmission_vectors.rs` | `examples/generate_transcript.rs` |
| `tests/transmission_genesis.rs` | `tests/genesis.rs` |
| `tests/transmission_merkle.rs` | `tests/merkle.rs` |
| `tests/transmission_storage.rs` | `tests/storage.rs`; the previous paired-graph contents of that destination are replaced |
| `tests/transmission_vectors.rs` | `tests/transcript.rs` |
| `tests/verify_transmission_vector.cjs` | `tests/verify_transcript.cjs` |
| `tests/test_transmission_v2.py` | Consolidated into `tests/test_python_bindings.py` |
| `vectors/transmission_v2.cbor` | New `vectors/relationship.cbor`; original standalone-session bytes retained only as negative `tests/fixtures/standalone_session.cbor` data |
| `tests/{exchange,graph,graph_encoding,handshake,profile,segment_admission,vectors}.rs`, `tests/test_tcp_packet0_local.py` | Removed obsolete implementation/loader suites; applicable adversarial checks transferred to canonical tests |
| `vectors/{bad_signature,compromise_quarantine_signal,cose_sign1_valid,deterministic_cbor_valid,fork_equivocation_pair,replayed_nonce,rotation_proof_valid,segment_proof_corrupt,segment_proof_valid,stale_counter,unsupported_alg}.cbor`, `vectors/oversize_frame.bin` | Removed placeholder data; executable regressions and the independently verified complete transcript replace them |
| `tests/{conformance,encoding,transmission}.rs`, `benches/transmission_benches.rs`, `examples/transmission_memory.rs`, root `Dockerfile` | Retained names, rewritten or updated for the sole canonical implementation |

| Document or metadata | Final disposition |
| --- | --- |
| `README.md` | Rewritten purpose, Rust/Python entry points, setup, cutover and limits |
| `LLM_AI_CONSUMPTION.md` | Rewritten technical implementation guide |
| `docs/DAG.md` | Rewritten relationship/session ownership, full traversal and persistence contract |
| `docs/RUNBOOK.md` | Rewritten supported builds, checks, Python, example and single Docker path |
| `docs/PROTOCOL.md` | New exact canonical wire, domains, state machine, history and journal specification |
| `docs/SECURITY.md` | New authentication, trust, replay, durability and deployment boundaries |
| `docs/PERFORMANCE.md` | New measurements of the final canonical implementation |
| `docs/MIGRATION.md` | New architecture, removal/naming inventory, compatibility and validation report |
| `vectors/README.md` | Rewritten original-signature, two-session transcript and independent-verifier guide |
| `docs/TRANSMISSION_V2.md`, `docs/TRANSMISSION_V2_DELIVERY.md`, `docs/TRANSMISSION_V2_PERFORMANCE.md` | Deleted; current specification, delivery guarantees and measurements are consolidated above |
| `Cargo.toml`, `pyproject.toml` descriptions | Updated canonical purpose and package version 0.3.0 |
| GitHub About description | External metadata update remains pending; see validation limits below |

## Validation evidence

The reviewed baseline's [CI run 40449295937](https://github.com/danad7583/TRAX/actions/runs/40449295937)
completed successfully, including `build` and `msrv-sha-profile`. This was
verified from GitHub's run and job records. Its success is baseline evidence,
not a claim that new unsubmitted code has run remotely.

Current local checks executed on 2026-10-27, using rustc 1.96.0 on Windows/MSVC
and the rebuilt CPython 3.11 release extension:

| Executed check | Result |
| --- | --- |
| `cargo fmt --check` | Passed |
| `cargo build --offline --locked` | Passed |
| `cargo test --offline --locked` | 77 passed |
| `cargo test --offline --locked --all-features` | 77 passed |
| `cargo test --offline --locked --no-default-features` | 76 passed; BLAKE3-only coverage intentionally excluded |
| `cargo clippy --offline --locked --all-targets --all-features -- -D warnings` | Passed |
| Release Python extension rebuild/install with Maturin | Passed |
| Canonical Python suite | 36 passed |
| Independent Node/OpenSSL transcript verifier | Passed |
| Canonical bidirectional, linked-session example | Passed |
| Criterion benchmark smoke run | All 31 cases passed |
| Fresh Criterion measurements and heap example | Passed; method and results in [PERFORMANCE.md](PERFORMANCE.md) |
| Cargo metadata, direct-dependency review and API/artifact guard | Passed |
| Living Markdown link review and `git diff --check` | Passed |

The regression suites include malformed encodings, key/signature/profile
substitution, non-power-of-two transmissions through 1,024 packets, payload
tampering, replay/reordering, provisional failure, cross-session continuity,
complete mirror traversal, stale pins, journal corruption, duplicate writers
and injected write/sync failures. No fuzz campaign or separate property-test
runner was executed; these results refer to the executable regression
and conformance tests in this working tree.

The new CI matrix is configured but has not run remotely. Rust 1.89 is the
declared MSRV and was tested by baseline CI; the current cleanup was tested
locally with 1.96, not with 1.89. Docker execution requires a CLI/daemon; neither
is available locally. The configured image job still needs to execute before
claiming Docker validation. No Docker test success is claimed.

GitHub's external About description still mentions K=8. The connected tools
provide no repository-settings edit operation, and no `gh` CLI is installed.
Local package metadata and all living documentation use the canonical
description; the remote description remains a separately reported metadata
follow-up.
