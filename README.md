# TRAX

**TRAX** stands for **Trust Resolution and Agent eXchange**.

TRAX is a core Rust library for **TRAX RFC v1.1.0** — a trust-only cryptographic protocol layer for verifiable agent-to-agent communication.

TRAX provides a transport-independent mechanism for agents to authenticate messages, validate interaction history, and resolve trust through signed Directed Acyclic Graphs rather than centralized authority. Identity alone does not imply trust; trust is derived from verifiable communication history, nonce freshness, key rotation continuity, and challenge-response validation.

The protocol is designed for distributed multi-agent systems, autonomous AI communication, edge environments, and agentic infrastructure where secure interaction must remain portable across transports, runtimes, and deployment models.

## Features

- CBOR + COSE_Sign1 canonical encoding
- Handshake/session binding
- DAG nodes + K-window Segment Proofs
- Key rotation + quarantine
- Replay protection using monotonic counters with windowing
- Rate limiting using token bucket controls
- Transport-independent trust validation
- Signed DAG-based trust history
- Challenge-response validation
- Trust resolution separated from inference behavior

## Dependencies

TRAX is a Rust project and requires the Rust toolchain, including `cargo` and `rustc`.

### Rust toolchain

Install Rust using `rustup`, then verify:

```bash
cargo --version
rustc --version
```

### Windows build dependencies

On Windows, the default Rust MSVC target requires the Microsoft C/C++ build tools. VS Code alone is not enough.

Required:

- Rust toolchain through `rustup`
- Microsoft Visual Studio Build Tools
- Desktop development with C++ workload
- MSVC C++ build tools
- Windows SDK

If these are missing, builds may fail with an error similar to:

```text
error: linker `link.exe` not found
```

After installing the Windows build tools, restart the terminal or VS Code before running Cargo commands.

### Linux build dependencies

On Linux, Rust projects generally require the standard native build toolchain in addition to Rust.

Required:

- Rust toolchain through `rustup`
- System C compiler/linker
- Standard build tools such as `gcc`, `make`, and development headers

Debian/Ubuntu-based systems commonly satisfy this with the system build essentials package. Other distributions provide equivalent compiler and linker packages through their package managers.

### Optional tools

The following tools are optional but useful for development and validation:

- Docker / Docker Compose for containerized scenarios
- Criterion benchmark support through Cargo dependencies
- Git for source control and repository management

## Build

After dependencies are installed, build the release binary:

```bash
cargo build --release
```

## Test

Run the test suite:

```bash
cargo test
```

## Conformance

See `TRAX_v1.1.0_Conformance_Test_Plan.md` and map tests to `tests/conformance.rs`.

## Handshake demo

```bash
cargo run --example handshake_client
cargo run --example handshake_server
```

## Benches

Benchmarks require the same native build dependencies as release builds.

```bash
cargo bench --bench dag_benches
```

## Vectors

See `/vectors` for structured placeholders. Replace with real CBOR/COSE bytes as they become available.

## Docker quickstart

Build the image with Docker Desktop:

```bash
cd docker
docker build -t trax-core:dev -f Dockerfile ..
```

Run the **A↔B scenario**:

```bash
docker run --rm -e MODE=aaip_scenario trax-core:dev
```

Generate **real vectors** inside the container at `/app/vectors/generated`:

```bash
docker run --rm -e MODE=mint_vectors -v ${PWD}/vectors/generated:/app/vectors/generated trax-core:dev
```

Handshake demos:

```bash
docker run --rm -e MODE=handshake_client trax-core:dev
docker run --rm -e MODE=handshake_server trax-core:dev
```

Open a shell inside the container:

```bash
docker run --rm -it -e MODE=shell trax-core:dev
```

Compose optional:

```bash
docker compose -f docker/docker-compose.yml up --build
```

## Project focus

TRAX focuses on objective trust verification between autonomous agents. It does not attempt to determine whether an agent is intelligent, truthful, ethical, or semantically correct. Instead, it verifies whether the agent’s communication history, signatures, counters, key transitions, and DAG lineage are cryptographically valid.

In short:

```text
Identity is not trust.
Trust is resolved from verifiable history.
```
