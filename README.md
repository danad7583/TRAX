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

### Python API

`hash32(data: bytes) -> bytes`

Returns the 32-byte TRAX hash for `data`.

`generate_keypair() -> dict`

Generates an Ed25519 keypair in Rust and returns `{"private_key": bytes,
"public_key": bytes}`. Both keys are 32 bytes.

`generate_nonce() -> bytes`

Returns a 16-byte cryptographically random nonce generated in Rust.

`derive_session_id(transcript_hash: bytes, client_nonce: bytes, server_nonce: bytes) -> bytes`

Derives a 32-byte TRAX session ID in Rust. `transcript_hash` must be 32 bytes;
`client_nonce` and `server_nonce` must be 16 bytes each.

`sign_message(private_key: bytes, message: bytes) -> bytes`

Signs `message` with a 32-byte Ed25519 private key and returns a 64-byte
signature.

`verify_message(public_key: bytes, message: bytes, signature: bytes) -> bool`

Verifies a 64-byte Ed25519 signature with a 32-byte public key. Returns `True`
for a valid signature and `False` for a validly shaped signature that does not
verify.

## Test

```bash
cargo test
```

## Benchmarks

```bash
cargo bench --bench dag_benches
```

Benchmarks include:

* K-window DAG segment verification
* Individual Ed25519 signing
* K=8 Merkle batch signing

Current benchmark snapshot from a Windows MSVC build:

```text
verify_last_8_nodes                  ~1.55 µs
verify_last_16_nodes                 ~3.15 µs
verify_last_32_nodes                 ~6.15 µs
verify_last_64_nodes                 ~12.29 µs
verify_last_128_nodes                ~24.69 µs
verify_last_256_nodes                ~49.33 µs

sign_8_nodes_individual_ed25519      ~183.9 µs
sign_16_nodes_individual_ed25519     ~368.0 µs
sign_32_nodes_individual_ed25519     ~748.9 µs
sign_64_nodes_individual_ed25519     ~1.48 ms
sign_128_nodes_individual_ed25519    ~2.96 ms
sign_256_nodes_individual_ed25519    ~5.90 ms

sign_batch_k8_merkle_root_ed25519    ~26.8 µs
```

Interpretation:

```text
8-node segment verification:      ~1.55 µs
8 individual Ed25519 signatures:  ~183.9 µs
K=8 Merkle batch signing:         ~26.8 µs
```

K=8 Merkle batch signing is approximately **6.8x faster** than signing 8 nodes individually in the measured environment.

Approximate throughput:

```text
8-node segment verification:       ~644,000 segment verifications/sec
K=8 Merkle batch signing:          ~37,000 signed batches/sec
Node-equivalent batch throughput:  ~298,000 signed node-equivalents/sec
```

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
