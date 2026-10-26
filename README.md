# TRAX

**Trust Resolution and Agent eXchange** is a Rust library for deterministic DAG records, insertion/verification, shared negotiated configuration, checkpoint attestations, key authority, and durable history. Applications own networking, peer connections, models, and decisions about verification results.

## Version 0.2 compatibility

This is a breaking change from the 0.1 prototype. Deterministic CBOR now recursively sorts map keys by encoded length and then encoded bytes, rejects duplicate keys, and accepts exactly one canonical item. It replaces the prototype's declaration/insertion-order encoding.

**Existing prototype V1 bytes, node IDs, hashes, signatures, and proofs must not be carried into this profile. There is no automatic migration.** Retaining a V1 type name does not preserve the old signing transcript.

Shared-DAG genesis explicitly binds K, signing algorithm, and runtime hash algorithm in `ProtocolConfig`. `with_default_k(signing_algorithm, hash_algorithm)` selects K=8; algorithms still require explicit selection, and all serialized configuration fields remain mandatory. New graph records and proofs are portable across builds that support their selected algorithms, regardless of the legacy `hash32` default feature. They must be verified under their recorded historical configuration. Legacy `hash32`/session helpers still use a compile-time hash profile, whose output is not interchangeable between BLAKE3 and SHA-512/256. The durable journal uses version 3 for the exchange-proof format; earlier journal formats are not automatically migrated.

## Library layers

- **Shared paired history:** `PairDag` represents a common mirrored relationship DAG with immutable records, explicit forks, recorded key authority, independent checkpoint attestations, and a durable replay-verified journal. See [DAG and storage contract](docs/DAG.md).
- **Same-author session windows:** `dag::TrustedSessionContext` and `ReceiveAdmissionWindow` verify ordered batches for one lineage key, one receiver, and one session. Directional windows are distinct from the shared paired-DAG model.
- **Packet0 admission:** signed receiver-bound initial envelopes and process-local `LocalAdmissionDag` records. This helper is not persistent storage, a peer registry, or distributed synchronization.
- **Encoding and crypto:** strict deterministic CBOR, Ed25519 signatures, hashing, HKDF session-ID derivation, and ordered Merkle roots/proofs.
- **Optional Python bindings:** Rust-backed crypto, Packet0, and same-author session-window APIs.

TRAX does not open HTTP/transport sockets, perform an on-wire key exchange, invoke models/tools, interpret agent decisions, determine malicious intent, or send alerts. It returns validated records or errors for the application to handle.

## Shared paired-DAG contract

The host agrees on and authenticates one shared configuration at genesis. `ProtocolConfig::with_default_k(signing_algorithm, hash_algorithm)` selects K=8; `ProtocolConfig::new(k, signing_algorithm, hash_algorithm)` overrides the cadence. These constructors validate the supplied agreement; they do not perform network negotiation. K, signing algorithm, and hash algorithm are always serialized and required during deserialization:

~~~rust
use trax::config::{HashAlgorithm, ProtocolConfig, SigningAlgorithm};

let config = ProtocolConfig::with_default_k(
    SigningAlgorithm::Ed25519,
    HashAlgorithm::Sha512256,
)?;
assert_eq!(config.k(), 8);

let smaller = ProtocolConfig::new(
    5,
    SigningAlgorithm::Ed25519,
    HashAlgorithm::Sha512256,
)?;
~~~

Shared `ProtocolConfig` requires K greater than 4 (minimum 5), fitting u32. Ed25519 is the only supported signing algorithm; other algorithm identifiers are rejected. Runtime hashing supports SHA-512/256 and, when compiled with `hash-blake3`, BLAKE3. Selecting an unavailable algorithm returns `UnsupportedAlgorithm`; there is no fallback. Enabling an algorithm makes it available, not automatically selected.

All DAG events across all branches count toward the shared K, including ordinary records, forks, rotations, configuration actions, control records, and padding. Events remain provisional until a complete K-event checkpoint verifies and commits. For an ordinary mixed-author segment, either participant may supply its single checkpoint signature. This attests that participant's DAG view, not separate signatures from every named author or authentication of a network address.

Rotation, configuration changes, and closure use a bilateral exchange. `rotate(author, parent, branch, &old_key, &new_key)` must be the first event of a fresh segment on a new fork branch. It requires both current old-key authorization and proof of possession of the replacement key. The peer calls `acknowledge_and_pad(peer, &peer_key)`, adding padding through position K−2 and an `Acknowledge` event at K−1, then signing a detached proof of that exact prefix. The initiator replays the prefix and calls `accept_ack(&proof)`, then either `finish_close()` for a final `CloseConfirm` at K or appends a real request in that slot to continue. The initiator supplies the full checkpoint using its current key; after rotation, only its replacement key may seal it. The unchanged peer and retired initiator key cannot supply that final checkpoint.

The K−1 prefix acknowledgment is a distinct proof, not an ordinary full-K checkpoint or partial admission. It is embedded in `GraphSegmentProof.acknowledgment` and bound into the final checkpoint and confirmation. `acknowledgment_for(proposal)` retrieves the peer's recorded prefix evidence. Nothing becomes committed until the acknowledgment and final checkpoint both verify.

`configure` is also a current-key-authorized fork action at the start of a fresh segment. Its new K and hash profile apply from the proposal itself: changing K=8 to K=5 produces a four-event prefix and final event at five. The accepted DAG configuration changes only after the full exchange verifies and commits, then applies globally to later live insertions, including continuations of older branches. A committed rotation changes only the affected participant's authority. Earlier records and attestations retain their historical authority/profile.

Ordinary requests and completed ordinary segments receive no automatic padding or close proposal. `request_close(author, branch)` explicitly starts a close exchange when at least three slots remain; only its peer acknowledgment step adds the necessary filler. A close exchange can instead end with a real request. The recorded mutual close proof cannot force a physical peer to remain connected.

Detached checkpoint lookup via `checkpoint_for(participant, node_hash)` can return a historical attestation after later nodes have been appended. Adding another participant's independent attestation does not rewrite the referenced history.

## Legacy same-author session helpers

These are separate lower-level APIs, not the shared graph's admission or exchange policy. They use explicit `SegmentConfig::new(k)` and the legacy compile-time hash profile. Their K must be positive and fit u32; the shared graph's minimum K=5 does not apply to these helpers:



| API | Purpose |
| --- | --- |
| `LocalAdmissionDag::new(config)` | Carry the selected K into a Packet0-derived context |
| `TrustedSessionContext::from_verified_state(config, ...)` | Restore state the caller has already independently verified |
| `ReceiveAdmissionWindow::new(context)` | Create a window, checking restored count arithmetic |
| `create_segment_seal(config, key, events)` | Sign exactly K ordered same-author events |
| `verify_segment_proof_intrinsic(config, proof, key)` | Check internal validity; this is not current-session admission |
| `verify_segment_proof_for_context(proof, context)` | Additionally verify the authoritative session context |
| `ordered_merkle_root(config, events)` | Commit to exactly K ordered event encodings |

Use a Packet0-derived context when available. `from_verified_state` is a restoration boundary, not a way to declare unverified fields trusted.

~~~rust
use trax::admission_dag::LocalAdmissionDag;
use trax::dag::ReceiveAdmissionWindow;
use trax::{PostGenesisEventV1, SegmentConfig, SegmentSealV1, TraxError};

fn receive_batch(
    config: SegmentConfig,
    packet0: &[u8],
    packet0_payload: &[u8],
    receiver_public_key: &[u8],
    batch: Vec<(PostGenesisEventV1, Vec<u8>)>,
    seal: &SegmentSealV1,
) -> Result<Vec<PostGenesisEventV1>, TraxError> {
    let mut dag = LocalAdmissionDag::new(config);
    dag.admit_packet0(packet0, packet0_payload, receiver_public_key)?;
    let context = dag.trusted_context_from_latest_packet0()?;
    let mut window = ReceiveAdmissionWindow::new(context)?;
    for (event, payload) in batch {
        window.stage_with_payload(event, &payload)?;
    }
    window.verify_and_commit(seal)
}
~~~

For example, a caller can select `SegmentConfig::new(3)?`. Every event in this session-window API remains provisional until all K events and a valid seal are present. There is no partial commit, implicit end-of-session flush, or automatic padding. Failed verification does not advance committed history. Counter/segment arithmetic is checked before mutation.

The window hashes actual payload bytes. Its `content_hash` is authenticated by the seal, but these low-level event types do not define the application's canonical content; callers must define and check that binding themselves.

## Merkle profile

The shared graph uses runtime-profile `profile::hash_bytes(algorithm, data)`, `domain_hash(config, domain, bytes)`, and `merkle_root(protocol_config, messages)`. Root computation hashes borrowed payloads and reduces one vector of hashes in place; it does not construct inclusion proofs or clone all payloads.

Legacy `crypto::merkle_root(segment_config, messages)`, `root_and_proofs(segment_config, messages)`, and `verify_merkle_inclusion(segment_config, ...)` provide roots and inclusion proofs under the compile-time hash profile. Both full-segment layers use exactly K ordered leaves. Leaf and parent hashes have separate domain prefixes. At each level an unpaired final node is promoted unchanged; no duplicate/artificial leaf is added. Legacy inclusion proofs omit promotion levels and must match the sibling sequence implied by K and the ordered index exactly. Legacy K=1 has a leaf root and an empty proof; shared `ProtocolConfig` still requires K≥5. Detached prefix commitments use K−1 leaves under the negotiated shared profile.

`ed25519_sign_merkle_root_raw(config, key, messages)` signs only a bare root. It does not bind session, receiver, lineage, or counters and **is not an admission seal**. Explicit K8 raw helpers remain conveniences for that tree size, not an implicit admission configuration.

## Build and validation

Rust 1.89 or newer and a native linker are required. On Windows, install Visual Studio Build Tools with **Desktop development with C++** and the Windows SDK, then restart the terminal. On Linux, install the distribution's C/C++ build toolchain and development headers.

~~~sh
cargo build --release
cargo test
cargo check --all-targets
cargo bench --bench dag_benches
~~~

Benchmarks measure local library operations. The shared-DAG group measures segment preparation, staging and sealing, and full admission at 0 and 1,024 prior events, using K=8 and SHA-512/256. Admission fixture cloning and teardown occur outside the measured operation. This README makes no fixed latency, throughput, or end-to-end networking claim. Historical XOR-based cumulative-hash timings were not authenticated segment verification.

Default features are `crypto-ed25519`, `hash-blake3`, and `serde`. Shared-DAG configuration still explicitly selects its runtime algorithms. Compile the legacy SHA-512/256 profile without BLAKE3 availability using:

~~~sh
cargo check --no-default-features --features crypto-ed25519,hash-sha2,serde
~~~

The `no_std` feature name does not establish a working no-std build; the library uses standard-library facilities.

## Python bindings

Build the extension in a virtual environment with maturin:

~~~sh
python -m venv .venv
python -m pip install maturin pytest
maturin develop --release --features python
python -m pytest tests/test_python_bindings.py tests/test_tcp_packet0_local.py
~~~

Activate the environment before pip/maturin: `.venv\Scripts\Activate.ps1` on PowerShell, or `source .venv/bin/activate` on Linux. Alternatively install a wheel built by `maturin build --release --features python`.

Private keys are opaque Rust-backed objects:

~~~python
import trax

sender = trax.generate_keypair()
receiver = trax.generate_keypair()
payload = b"initial application payload"
session_id = trax.derive_session_id(
    trax.hash32(b"application-supplied transcript"),
    trax.generate_nonce(),
    trax.generate_nonce(),
)
envelope = trax.create_admission_envelope_v1(
    sender["private_key"], receiver["public_key"], session_id,
    trax.generate_nonce(), payload, "packet0.admission",
)
dag = trax.LocalDag(k=3)
node_id = dag.admit_packet0(envelope, payload, receiver["public_key"])
context = dag.trusted_context_from_latest_packet0()
assert context.k() == 3
window = trax.ReceiveAdmissionWindow(context)
~~~

The application supplies the handshake transcript and transport; deriving a session ID does not perform a handshake. Python requires a 32-byte transcript hash and 16-byte nonces.

Explicit-K Python entrypoints include:

- `create_segment_seal(private_key, events, k)`
- `verify_segment_seal_intrinsic(public_key, events, seal, k)`
- `verify_segment_seal_for_context(context, events, seal)`
- `TrustedSessionContext.from_verified_state(..., k=k)`

`window.stage(event_bytes, payload)` stages only; `window.verify_and_commit(seal_bytes)` releases the complete admitted batch. Hashing, direct signing/verification, receiver identity, and Packet0 encode/decode/verification helpers remain available. These Python wrappers expose the session-window layer; see [docs/DAG.md](docs/DAG.md) for the paired-DAG/storage API.

## Auxiliary helpers and limits

`session::derive_session_id` uses HKDF-SHA512 on supplied context/nonces and optional caller-supplied shared-secret bytes. The `crypto-x25519` dependency feature does not implement an X25519 exchange or encryption stack.

`rate::TokenBucket` is a standalone caller-driven limiter, not an integrated admission policy. `replay::LastSeen` leaves in-window duplicate filtering incomplete. Session-window counter continuity and paired-DAG verification are separate checks.

Legacy `rotation.rs` types do not implement quarantine or a rotation workflow. Paired-DAG recorded rotation is a distinct authority transition described in [docs/DAG.md](docs/DAG.md).

`encoding::cose_sign1` explicitly returns an unsupported-operation error; it never returns unsigned bytes as successful signing. Use the explicit admission/checkpoint signing APIs. Examples under `examples/` demonstrate helpers, not a complete host or wire protocol.

## Repository guide

- `src/config.rs`: validated shared configuration and optional K=8 construction helper
- `src/exchange.rs`: detached peer acknowledgments of exact K−1 prefixes
- `src/dag.rs`: same-author session admission and segment seals
- `src/admission.rs`, `src/admission_dag.rs`: Packet0 helpers
- [docs/DAG.md](docs/DAG.md): common paired DAG, forks, key authority, and durable journal
- `src/encoding.rs`, `src/crypto.rs`: deterministic representation and crypto primitives
- `tests/`: inspect assertions rather than inferring coverage from requirement IDs
- `benches/`: local-operation benchmarks
- `vectors/`: some historical files remain placeholders; filenames are not conformance evidence

Licensed under the [MIT License](LICENSE).
