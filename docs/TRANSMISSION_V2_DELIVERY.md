# Logical transmission V2 implementation report

## Architecture and migration

The repository was fetched before implementation. The supplied baseline
`929016e` remains remote main; local `f86312a` is its one additional commit.
That newer commit's immutable paired graph, bilateral rotation/configuration
checks, retired-key enforcement and durable journals are preserved.

V2 adds a separate, K-free request/response protocol. It does not change legacy
window or shared-graph bytes, roots, signatures, admission rules or journal
formats. Both old fixed-cadence profiles remain explicitly legacy. Version
numbers alone are insufficient to identify a profile: distinct schemas and
domain strings separate the new transmission V2 from existing graph V2.

The three authentication layers are separate:

1. **Genesis:** three original signed nodes plus explicit identity acceptance
   produce a shared canonical anchor. Signature possession never automatically
   authorizes an unknown identity.
2. **Transmission:** every packet is a hash-linked event; only its final data
   packet contains a signed context-bound, ordered, count-bound Merkle
   commitment. Nothing is admitted or exposed as authenticated input until
   that signature verifies against the pinned expected sender.
3. **Closure:** after any completed request/response round, the session
   initiator may sign its exact agreed full-history digest and boundary.
   The peer verifies and mirrors that original terminal artifact. There is no
   receiver countersignature or delivery guarantee.

A sender can create packets without advancing state. Both sender and receiver
then mirror them using the same admission path. Requests and responses
alternate; sessions remain open across multiple rounds. A session may be
initiated by either peer, independently of which peer initiated genesis.

The variable Merkle construction uses a largest-power-of-two split tree,
indexed/length-bound leaves, separate internal-node domains and a count-bound
root. A streaming frontier retains O(log N) hashes. Provisional payload storage
is explicitly bounded; complete payloads are never concatenated merely to hash
or sign them. `payload_chunks()` avoids another contiguous payload copy.

## Exact commitment specification

[TRANSMISSION_V2.md](TRANSMISSION_V2.md) specifies every wire field, byte-string
length, enum value, domain string, signature preimage, Merkle rule, history
accumulator, session anchor and journal frame. It includes the worked
100-packet request / 17-packet response / closure flow.

The final event's canonical signature-free metadata binds its actual validated
payload hash and length. Its leaf excludes the entire seal, including both
root and signature. The final seal signs the reconstructed complete
transmission commitment. This avoids circular hashing without adding a
mandatory seal packet. The full-history accumulator separately includes the
original accepted seals and signatures.

## Public Rust APIs

| Module | New public entry points |
| --- | --- |
| `genesis` | `TransmissionLimitsV2`, `TransmissionProfileV2`, `GenesisStepV2`, `GenesisEventV2`, `GenesisNodeV2`, `genesis_node_id`, `create_genesis_offer`, `accept_genesis_offer`, `confirm_genesis`, `VerifiedGenesisV2::verify` and read-only token accessors |
| `transmission_crypto` | `hash_v2`, `MerkleAccumulatorV2::{new,push,root,len,is_empty}`, `merkle_root_v2`, `merkle_root_and_proofs_v2`, `InclusionProofV2`, `verify_merkle_inclusion_v2`, bounded leaf-count constant |
| `transmission` | Wire packet/event/commitment/seal/terminal/context/checkpoint types, `TransmissionKindV2`, `event_tip_v2`, `SessionV2`, read-only `CommittedNodeV2`, non-forgeable `VerifiedTransmissionV2` |
| `SessionV2` | `new`, `build_transmission`, `fragment_transmission`, `start_receive`, `stage_packet`, `stage_encoded_packet`, `abort_receive`, `expire_receive`, `create_close`, `verify_and_close`, `verify_encoded_close`, read-only genesis/context/state/node/terminal queries |
| `VerifiedTransmissionV2` | `packets`, `commitment`, `payload`, `payload_chunks`; no public constructor |
| `transmission_storage` | `DurableSessionV2::{create_new,open,session,checkpoint,is_poisoned,start_receive,stage_packet,stage_encoded_packet,abort_receive,expire_receive,verify_and_close,verify_encoded_close}` |
| `encoding` | `decode_strict<T>(bytes,max_bytes)` with 64-level parser limit, deterministic typed round trip and byte cap |
| `errors` | `TransmissionLimit`, `TransmissionExpired`, `UnexpectedState` |

Authoritative sessions are not cloneable and have no unchecked arbitrary-tip
restore. Public wire objects remain untrusted until passed through admission.
No caller-provided successful hash or bare-root signature substitutes for the
Rust verification state machine.

## Public Python APIs

Private keys reuse the existing opaque Rust-backed key objects.

- `tx_genesis_offer(private_key, nonce, *, hash_algorithm="sha512-256",
  max_packets=None, max_payload_bytes=None, max_packet_payload_bytes=None,
  max_wire_packet_bytes=None, timeout_ms=None)` returns canonical offer bytes.
- `tx_genesis_accept(offer, private_key, trusted_peer)` verifies and explicitly
  authorizes the offered identity before signing acceptance.
- `tx_genesis_confirm(offer, acceptance, private_key, trusted_peer)` verifies
  and explicitly authorizes the responder before signing confirmation.
- `TransmissionSessionV2(offer, acceptance, confirmation, initiator, nonce,
  trusted_keys)` verifies the complete transcript through Rust.
- Its `build_transmission` and `fragment_transmission` methods return packet
  byte lists. `start_receive` begins staging; `stage_packet(packet_bytes)`
  returns `None` until final verification, then returns the verified payload.
- `checkpoint` (including session ID), `has_pending`, `abort_receive`, `expire_receive`,
  `create_close`, and `verify_and_close` expose the lifecycle. No Python method
  sets an arbitrary trusted tip or restores unchecked state.

The Python class is memory-only. Production durable reception uses the Rust
durable wrapper or an equivalently atomic host integration; Python state does
not claim crash-safe exactly-once behavior.

## File-by-file changes

| File | Change |
| --- | --- |
| `src/genesis.rs` | Bounded K-free profile, strict three-node genesis, explicit trust callback, private verified token |
| `src/transmission_crypto.rs` | Incremental V2 hashing, streaming count-bound Merkle tree and bounded inclusion proofs |
| `src/transmission.rs` | Versioned wire records, sender framing/signing, provisional receiver, atomic admission, immutable history/indexes, request/response lifecycle and initiator closure |
| `src/transmission_storage.rs` | Independent locked journal, bounded frames, verify/write/sync/admit order, poison-on-I/O-failure, replay against exact external latest-state pin |
| `src/python_transmission.rs` | Thin Rust-backed Python genesis, packet builder, receiver and closure interfaces |
| `src/encoding.rs` | New bounded exact typed decoder; existing generic/legacy encoding unchanged |
| `src/errors.rs` | Explicit resource, expiry and lifecycle errors |
| `src/lib.rs` | Exports new protocol modules and optional Python registration module |
| `src/python.rs` | Registers V2 bindings and permits internal reuse of opaque private keys |
| `tests/transmission.rs` | Required sizes, all commitment fields, bidirectional rounds, packet failures, adversarial rehashing, replay, closure, resources, wire budget and legacy substitution |
| `tests/transmission_genesis.rs` | Trust, signatures, profiles, chain links, nonce/anchor, parser and legacy separation |
| `tests/transmission_merkle.rs` | Independent recursive roots, fixed primitive vector, every inclusion path, odd counts, bounds and domain separation |
| `tests/transmission_storage.rs` | Locks, pins, rollback, replay, incomplete transactions, malformed frames, forgery, rejection without disk mutation and closed-state persistence |
| `tests/transmission_vectors.rs` | Frozen complete transcript consumed without recreating its signatures |
| `tests/test_transmission_v2.py` | Python sizes, independent CBOR/hash reconstruction, MITM substitutions, lifecycle, trust, bounds and closure |
| `tests/verify_transmission_vector.cjs` | Separate Node/OpenSSL wire/hash/signature/full-history verifier; imports no TRAX code |
| `examples/transmission_v2.rs` | Complete 100-to-17 and second-round mirrored flow with original initiator terminal |
| `examples/transmission_vectors.rs` | Explicit deterministic public test-vector regeneration |
| `examples/transmission_memory.rs` | Allocated-heap measurement separating retained inputs, provisional data and metadata-only history |
| `benches/transmission_benches.rs` | Variable roots, build, typed/wire admission, staging, signature, payload hashing and legacy comparison |
| `Cargo.toml` | Registers the additional Criterion bench; no new runtime dependencies |
| `.github/workflows/ci.yml` | Adds V2 pytest, independent Node vector, benchmark smoke check and Rust 1.89 SHA-profile test job |
| `README.md` | V2 entry points and migration/trust/rotation boundaries; legacy sections retained |
| `docs/TRANSMISSION_V2.md` | Exact protocol specification and 100-packet worked example |
| `docs/TRANSMISSION_V2_PERFORMANCE.md` | Actual measurement tables, methodology, heap figures and caveats |
| `docs/TRANSMISSION_V2_DELIVERY.md` | This report |
| `vectors/transmission_v2.cbor` | Frozen complete canonical signed transcript |
| `vectors/README.md` | Frozen-vector provenance, hash and independent verification instructions |

No AAICP files changed. Existing Packet 0, K-window crypto/admission, graph
rotation and legacy storage implementations remain unchanged.

## Validation

Executed locally on 2026-10-26 after the implementation changes (Cargo commands
used `--offline` because dependencies were already available):

| Command/check | Result |
| --- | --- |
| `cargo fmt --check` | Passed |
| `cargo build --offline` | Passed |
| `cargo test --offline` | 160 Rust tests passed |
| `cargo test --offline --all-features` | 160 Rust tests passed |
| `cargo test --offline --no-default-features --features crypto-ed25519,hash-sha2,serde` | 159 passed; the BLAKE3-only profile test is not compiled |
| `cargo clippy --offline --all-targets --all-features -- -D warnings` | Passed |
| `python -m maturin develop --offline --release --features python` | Built and installed CPython 3.11 release extension |
| `python -m pytest tests/test_python_bindings.py tests/test_tcp_packet0_local.py tests/test_transmission_v2.py -q` | 47 passed |
| `node tests/verify_transmission_vector.cjs` | Independent complete transcript passed |
| `cargo run --offline --example transmission_v2` | Mirrored 100/17/3/2 flow and initiator closure passed |
| Criterion transmission benchmark | All 32 cases measured successfully; separate benchmark test mode also passed |
| `cargo run --offline --release --example transmission_memory` | Heap measurement example passed |
| `git diff --check` | Passed |

The Rust suite retains all 108 previous tests and adds 52 V2 tests. Parameterized
size/field tests additionally exercise the required `1,2,3,7,8,9,17,35,100,138`
packet counts and every authenticated commitment field. Deterministic mutation
tests exercise 128 corrupted wire inputs. Dedicated tests simulate an attacker
who modifies payloads and correctly recomputes every downstream DAG/Merkle
hash, but cannot produce the expected peer signature. Failed cases assert
unchanged trusted state and no verified payload release. Storage tests inject
write/position failures and test sticky poison without trusted-memory advance.

## Measured performance

The [performance report](TRANSMISSION_V2_PERFORMANCE.md) contains all actual
Criterion values, confidence intervals, hardware/runtime details, commands and
heap tables. These are local shared-machine measurements, not network or model
throughput, and exclude journal fsync.

For SHA-512/256 and 1 KiB payload packets, complete wire admission measured
73.100 microseconds for one packet, 2.369 milliseconds for 100, 3.275
milliseconds for 138, and 23.406 milliseconds for 1,024 packets (42.72 payload
MiB/s). One prepared-commitment Ed25519 signature measured 24.313 microseconds.

For the exposed eight-leaf BLAKE3 helpers, legacy root generation measured
7.839 microseconds and V2 7.407 microseconds. The legacy helper also builds
inclusion proofs; V2 binds indices, lengths and count. This is an implementation
comparison, not an identical-work or full-protocol speedup claim.

For 1,024 packets / 1 MiB payload, allocated-heap peak was 5,379,722 bytes while
retaining input chunks and sender packet buffers; after dropping payload/source
buffers, receiver history retained 782,795 bytes. Heap bytes are not RSS and
exclude stack/OS/allocator bookkeeping.

## Operational boundaries and deferred functionality

- **Live V2 key rotation is not defined.** Keys/epoch zero are pinned by accepted
  genesis. Legacy rotation proofs cannot enter V2 or update its keys. A new key
  requires a new explicitly authorized genesis/session; the host trust policy
  must reject retired identities. Legacy rotation remains fully available.
- **One authoritative order:** no simultaneous transmission reconciliation,
  branch merging or automatic cross-process/session-ID registry is introduced.
  Hosts route a session to one durable journal; its OS lock coordinates users
  of that same file, not independently copied journals or hostile file editors.
- **Crash safety:** memory-only state can be rolled back or duplicated by its
  owner. Durable opening requires an authenticated fresh exact state pin.
  Updating that external pin and atomically coupling application side effects
  to committed input are host responsibilities. TRAX does not claim global
  exactly-once effects. Partial tails fail closed; recovery tooling is absent.
- **Bounded buffering:** payload memory is bounded by negotiated transmission
  limits, not constant-space disk-spooled. Accepted metadata/indexes grow with
  total session history; there are no authenticated snapshots or lazy indexes.
- **Timeout scheduling:** live staging checks elapsed time; the host polls
  `expire_receive` if no packets arrive, or drops/aborts the session. TRAX adds
  no background scheduler. Historical replay ignores live receive deadlines.
- **Authentication scope:** signatures prevent unauthenticated content
  modification/injection/substitution from becoming trusted input. They do not
  provide encryption, transparent-relay detection, stolen-key protection,
  denial-of-service immunity, network delivery evidence or application policy.
- **Transport:** full encoded packet caps are enforced, but sockets, UDP/TCP
  framing, retry, ordering delivery and model/tool execution remain external.
- **Validation environment:** local commands use Windows/MSVC, Rust 1.96 and
  CPython 3.11. GitHub's Ubuntu/Python 3.13 and new Rust 1.89 jobs have not run
  remotely because this revision has not been pushed. Their configuration is
  included, not reported as executed CI.

All requested core V2 authentication, mirrored-session, final-packet framing,
atomic admission and closure behavior is implemented. The explicit boundaries
above do not silently reuse legacy authority or claim unsupported security.
