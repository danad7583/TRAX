# TRAX

**TRAX** stands for **Trust Resolution and Agent eXchange**.

TRAX is a Rust-based cryptographic trust layer for verifiable agent-to-agent communication. It provides a transport-independent mechanism for agents to authenticate messages, validate interaction history, and resolve trust through signed Directed Acyclic Graphs rather than centralized authority.

TRAX is designed around a simple principle:

```text
Identity is not trust.
Trust is resolved from verifiable history.
```

The protocol focuses on objective trust verification. It does not attempt to determine whether an agent is intelligent, truthful, ethical, or semantically correct. Instead, TRAX verifies whether the agent’s communication history, signatures, counters, key transitions, and DAG lineage are cryptographically valid.

## Project Status

Current validated local status:

```text
cargo build --release  ✅ passed
cargo test             ✅ passed
cargo bench            ✅ passed
```

Validated conformance tests:

```text
req_3_1_1_deterministic_cbor      ✅ passed
req_4_1_2_session_id_binding      ✅ passed
req_5_1_1_segment_proof_validates ✅ passed
```

## Features

* Canonical CBOR encoding
* COSE Sign1-oriented message structure
* Handshake/session binding
* DAG nodes and K-window segment proofs
* Key rotation and quarantine support
* Replay protection using monotonic counters with windowing
* Token-bucket rate limiting
* Ed25519 signing support
* K=8 Merkle batch signing
* Transport-independent trust validation
* Signed DAG-based trust history
* Challenge-response validation
* Trust resolution separated from inference behavior

## Architecture Summary

TRAX separates identity from trust.

An agent identity may be represented by a public/private key pair, but identity alone does not establish trust. Trust is resolved by validating signed message history, DAG continuity, replay protection, key continuity, and challenge-response behavior.

TRAX supports an AAIP lower layer for signed agent packet/message exchange. AAIP naming is intentionally retained where examples or modes refer specifically to the lower signed-message scenario rather than the full TRAX trust-resolution layer.

For example:

```text
aaip_scenario = lower signed-message / packet exchange demonstration
trax          = trust-resolution layer built around DAG history and cryptographic continuity
```

### Receive admission invariant

Receipt is not admission. Packet 0/genesis is individually authenticated and establishes the
initial trusted session, receiver, lineage key, and DAG root. Every normal post-genesis event
MUST enter a provisional K-window first; structural validation alone MUST NOT advance trusted
history or release the event as admitted communication.

K=8 is the normative signed-batch profile. Events 1 through 7 remain provisional. The eighth
event carries or is associated with `SegmentSealV1`, which signs a deterministic,
domain-separated `SegmentCommitmentV1`. That commitment binds the session, receiver, trusted
lineage key identity, segment index, contiguous counters, starting committed tip, final
provisional tip, and the order-sensitive Merkle root of all eight events. K=8 signing is one
segment signature, not eight per-packet signatures; the final Kth event seals the window rather
than introducing a ninth event.

A receiver SHALL verify the entire ordered window and its seal against the lineage public key
already trusted through genesis or validated rotation. Only then SHALL it atomically admit all
eight events and advance the committed tip. Reordering or changing an event, changing context,
breaking tip/counter continuity, or failing signature verification rejects the whole window.
Failure commits zero provisional events and leaves the committed DAG state unchanged. Partial
windows MUST remain provisional and MUST NOT be promoted implicitly at end of session.

`receiver_id` has one normative meaning in this profile:
`H("TRAX:RECEIVER-ID:V1\\0" || receiver_lineage_public_key)`. It identifies the stable receiving
trust identity and MUST NOT be derived from an ephemeral transport or future transmission key.

### K=8 Rust admission API

`PostGenesisEventV1` commits to session, lineage and receiver identities, segment/counter
position, previous tip, content hash, and payload hash. `SegmentCommitmentV1` binds the ordered
K=8 Merkle root to that context; `SegmentSealV1` authenticates the commitment; `SegmentProof`
packages the ordered events and seal.

`TrustedSessionContext` privately owns the authoritative session ID, receiver ID, lineage
verification key, committed tip, segment index, and next counter. A verified `LocalAdmissionDag`
produces it with `trusted_context_from_latest_packet0()`. Applications restoring independently
verified state may use the explicitly named `from_verified_state` constructor.

`verify_segment_proof_intrinsic()` checks internal order, continuity, Merkle commitment, and
signature. It does **not** establish that the segment belongs to the receiver's current session.
`verify_segment_proof_for_context()` additionally matches admission fields against
`TrustedSessionContext`. Intrinsic cryptographic validity is not session admission.

`ed25519_sign_merkle_root_k8_raw()` is deliberately named as a low-level bare-root primitive.
Its output is not a `SegmentSealV1` and MUST NOT be used as proof of TRAX admission. The former
`ed25519_sign_batch_k8()` name remains only as a deprecated compatibility alias.

`ReceiveAdmissionWindow::stage_with_payload()` hashes actual payload bytes before provisional
staging. `content_hash` is authenticated by the seal but is not recomputed because this protocol
version does not yet define which canonical content bytes it represents. After eight valid
event/payload pairs, `verify_and_commit()` performs context-bound verification and atomically
returns the admitted events.

The receive window owns active admission state, not permanent DAG history. It retains the trusted
context, provisional events/tip, and total committed count. Newly committed events are returned
for external persistence rather than retained indefinitely. The context leaves a clean future
transition point for authenticated lineage-key rotation; rotation is not implemented here.

## Dependencies

TRAX is a Rust project and requires the Rust toolchain, including `cargo` and `rustc`.

### Rust Toolchain

Install Rust using `rustup`, then verify:

```bash
cargo --version
rustc --version
```

### Windows Build Dependencies

On Windows, the default Rust MSVC target requires the Microsoft C/C++ build tools. VS Code alone is not enough.

Required:

* Rust toolchain through `rustup`
* Microsoft Visual Studio Build Tools
* Desktop development with C++ workload
* MSVC C++ build tools
* Windows SDK

If these are missing, builds may fail with:

```text
error: linker `link.exe` not found
```

After installing the Windows build tools, restart the terminal or VS Code before running Cargo commands.

### Linux Build Dependencies

On Linux, Rust projects generally require the standard native build toolchain in addition to Rust.

Required:

* Rust toolchain through `rustup`
* System C compiler/linker
* Standard build tools such as `gcc`, `make`, and development headers

Debian/Ubuntu-based systems commonly satisfy this with the system build essentials package. Other distributions provide equivalent compiler and linker packages through their package managers.

### Optional Tools

* Docker / Docker Compose for containerized scenarios
* Git for source control
* Gnuplot for Criterion benchmark graphs

Gnuplot is optional. If it is not installed, Criterion may report:

```text
Gnuplot not found, using plotters backend
```

This does not prevent benchmarks from running.

## Build

```bash
cargo build --release
```

## Python Bindings

TRAX provides a Python extension module named `trax`. The Python API is a thin
PyO3/maturin binding over the compiled Rust crate; cryptographic and trust logic
remain in Rust.

After the package is installed from a built wheel or package distribution,
applications can import it directly:

```python
import trax

digest = trax.hash32(b"hello")
```

Session and Ed25519 helpers are also exposed as bytes-based wrappers around the
Rust implementation:

```python
import trax

keys = trax.generate_keypair()
private_key = keys["private_key"]
public_key = keys["public_key"]

message = b"hello from python"
signature = trax.sign_message(private_key, message)

assert trax.verify_message(public_key, message, signature) is True
assert trax.verify_message(public_key, b"tampered", signature) is False

nonce_a = trax.generate_nonce()
nonce_b = trax.generate_nonce()
transcript_hash = trax.hash32(b"demo transcript")
session_id = trax.derive_session_id(transcript_hash, nonce_a, nonce_b)

assert len(session_id) == 32
```

Packet 0 admission envelopes can be created and verified as canonical CBOR bytes:

```python
sender = trax.generate_keypair()
receiver = trax.generate_keypair()

payload = b"packet zero payload"
session_id = trax.hash32(b"session transcript")
nonce = trax.generate_nonce()

envelope = trax.create_admission_envelope_v1(
    sender["private_key"],
    receiver["public_key"],
    session_id,
    nonce,
    payload,
    "packet0.admission",
)

assert trax.verify_admission_envelope_v1(envelope, payload) is True
assert (
    trax.verify_admission_envelope_v1_for_receiver(
        envelope,
        payload,
        receiver["public_key"],
    )
    is True
)

dag = trax.LocalDag()
node_id = dag.admit_packet0(envelope, payload, receiver["public_key"])
trusted = dag.trusted_context_from_latest_packet0()

assert len(node_id) == 32
assert len(dag) == 1
```

### Python API

`hash32(data: bytes) -> bytes`

Returns the 32-byte TRAX hash for `data`.

`generate_keypair() -> dict`

Generates an Ed25519 keypair in Rust and returns `{"private_key": PrivateKey,
"public_key": bytes}`. The private key is an opaque Rust-backed Python object;
the public key is 32 bytes.

`PrivateKey.public_key() -> bytes`

Returns the 32-byte public key corresponding to the opaque private key.

`generate_nonce() -> bytes`

Returns a 16-byte cryptographically random nonce generated in Rust.

`derive_session_id(transcript_hash: bytes, client_nonce: bytes, server_nonce: bytes) -> bytes`

Derives a 32-byte TRAX session ID in Rust. `transcript_hash` must be 32 bytes;
`client_nonce` and `server_nonce` must be 16 bytes each.

`sign_message(private_key: PrivateKey, message: bytes) -> bytes`

Signs `message` with an opaque Rust-backed Ed25519 private key and returns a
64-byte signature. Raw private key bytes are not accepted by this API.

`verify_message(public_key: bytes, message: bytes, signature: bytes) -> bool`

Verifies a 64-byte Ed25519 signature with a 32-byte public key. Returns `True`
for a valid signature and `False` for a validly shaped signature that does not
verify.

`create_admission_envelope_v1(private_key: PrivateKey, receiver_public_key: bytes, session_id: bytes, nonce: bytes, payload: bytes, message_type: str, dag_parent_refs: list[bytes] | None = None, proof_type: str = "none") -> bytes`

Creates a canonical CBOR TRAX Admission Envelope v1 for Packet 0. The Rust
implementation binds the session ID, nonce, sender public key, receiver public
key, payload hash, message type, DAG parent references, proof type, and
signature. `session_id` must be 32 bytes, `nonce` must be 16 bytes,
`receiver_public_key` must be 32 bytes, and each DAG parent reference must be 32
bytes.

`verify_admission_envelope_v1(envelope: bytes, payload: bytes) -> bool`

Verifies the Admission Envelope v1 signature and payload hash binding using the
sender public key embedded in the envelope.

`verify_admission_envelope_v1_for_receiver(envelope: bytes, payload: bytes, receiver_public_key: bytes) -> bool`

Verifies the envelope and additionally checks that it is bound to the expected
32-byte receiver public key.

`decode_admission_envelope_v1(envelope: bytes) -> dict`

Decodes canonical CBOR Admission Envelope v1 bytes into a Python dictionary for
inspection. Verification should still use `verify_admission_envelope_v1` or
`verify_admission_envelope_v1_for_receiver`.

`LocalDag()`

Creates a local in-memory DAG admission history. This is ephemeral process-local
state and is not persistent storage, distributed DAG sync, replay prevention, or
full parent trust validation.

`LocalDag.admit_packet0(envelope: bytes, payload: bytes, receiver_public_key: bytes) -> bytes`

Verifies a receiver-bound Packet 0 admission envelope and appends a local DAG
node representing the verified admission event. Returns a stable 32-byte
admission node ID. Verification failure raises an exception and does not append.

`LocalDag.len() -> int`

Returns the number of local admitted Packet 0 DAG nodes.

`LocalDag.is_empty() -> bool`

Returns whether the local in-memory DAG has no admitted Packet 0 nodes.

`receiver_id(receiver_lineage_public_key: bytes) -> bytes`

Derives the domain-separated stable receiver identity used by post-genesis commitments.

`LocalDag.trusted_context_from_latest_packet0() -> TrustedSessionContext`

Produces opaque authoritative post-genesis context from the latest admitted Packet 0.

`TrustedSessionContext.from_verified_state(...) -> TrustedSessionContext`

Restores opaque context from state the application has already verified and persisted. Its fields
are readable through accessors but cannot be mutated directly from Python.

`ReceiveAdmissionWindow(context: TrustedSessionContext)`

Creates Rust-owned K=8 receiver state. It retains active admission state, not permanent history.

`ReceiveAdmissionWindow.stage(event: bytes, payload: bytes) -> bytes`

Verifies actual payload bytes plus event context, counter, and provisional-tip continuity before
staging. Failure leaves the provisional count unchanged.

`create_segment_seal_k8(private_key: PrivateKey, events: list[bytes]) -> bytes`

Creates a signed, context-bound `SegmentSealV1` for exactly eight ordered events.

`verify_segment_seal_k8_intrinsic(public_key, events, seal) -> bool`

Checks internal cryptographic validity only. A true result is not session admission.

`verify_segment_seal_k8_for_context(context, events, seal) -> bool`

Performs admission-grade verification against opaque trusted session context.

`ReceiveAdmissionWindow.verify_and_commit(seal: bytes) -> list[bytes]`

Atomically admits and returns exactly eight event encodings. Failure advances no committed state
and releases no events.

## Test

```bash
cargo test
```

## Benchmarks

```bash
cargo bench --bench dag_benches
```

Benchmarks include:

* Ordered K=8 event commitment/Merkle-root computation
* Signed, context-bound K=8 segment-seal creation
* Full K=8 verification, including context, ordered root, and Ed25519 signature

Historical figures for the former XOR-based length/hash check are intentionally omitted: that
operation was not trusted segment verification. Use the benchmark command above to measure the
real security operations on the target platform.

These benchmarks measure local cryptographic and DAG operations. They do not represent end-to-end network latency, remote agent processing, or full distributed system throughput.

## Conformance

Conformance tests live in:

```text
tests/conformance.rs
```

Run:

```bash
cargo test
```

Current conformance coverage includes:

* Deterministic CBOR behavior
* Session ID binding
* Segment proof validation

## Examples

### Handshake Demo

```bash
cargo run --example handshake_client
cargo run --example handshake_server
```

### AAIP Scenario

```bash
cargo run --example aaip_scenario
```

The `aaip_scenario` example demonstrates the lower signed-message / packet exchange layer used by TRAX. The name is intentionally retained when referring to that lower layer.

### Vector Generation

```bash
cargo run --example mint_vectors
```

## Docker Quickstart

Build the image:

```bash
cd docker
docker build -t trax-core:dev -f Dockerfile ..
```

Run the AAIP scenario:

```bash
docker run --rm -e MODE=aaip_scenario trax-core:dev
```

Generate vectors:

```bash
docker run --rm -e MODE=mint_vectors -v ${PWD}/vectors/generated:/app/vectors/generated trax-core:dev
```

Run handshake demos:

```bash
docker run --rm -e MODE=handshake_client trax-core:dev
docker run --rm -e MODE=handshake_server trax-core:dev
```

Open a shell inside the container:

```bash
docker run --rm -it -e MODE=shell trax-core:dev
```

Compose:

```bash
docker compose -f docker/docker-compose.yml up --build
```

## Repository Hygiene

Recommended `.gitignore` coverage:

```gitignore
/target/
/criterion/
/vectors/generated/
.env
.env.*
!.env.example
*.log
.DS_Store
Thumbs.db
.vscode/
!.vscode/settings.json
!.vscode/extensions.json
*.pdb
*.ilk
*.exe
*.dll
*.lib
*.exp
*.tmp
*.bak
*.swp
```

Do not ignore:

```text
src/
tests/
benches/
examples/
docs/
```

## Security Notes

TRAX is experimental research and development software. It should not be treated as production-ready cryptographic infrastructure without independent review, formal testing, and security validation.

The project currently demonstrates protocol mechanics, trust-chain validation, batch-signing performance, and conformance scaffolding. Additional review is recommended before deployment in sensitive environments.

## License

Add license information before publishing or distributing this repository.
