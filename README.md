# aaicp-core

Core Rust library for **AAICP RFC v1.1.0** (trust-only).

## Features
- CBOR + COSE_Sign1 canonical encoding
- Handshake/session binding
- DAG nodes + K-window Segment Proofs
- Key rotation + quarantine
- Replay protection (monotonic counters w/ window)
- Rate limiting (token bucket)

## Build
```bash
cargo build --release
```

## Test
```bash
cargo test
```

## Conformance
See `AAICP_v1.1.0_Conformance_Test_Plan.md` and map tests to `tests/conformance.rs`.

## Handshake demo
```bash
cargo run --example handshake_client
cargo run --example handshake_server
```

## Benches
```bash
cargo bench --bench dag_benches
```

## Vectors
See `/vectors` for structured placeholders. Replace with real CBOR/COSE bytes as they become available.


## Docker quickstart

Build the image (Docker Desktop):

```bash
cd docker
docker build -t aaicp-core:dev -f Dockerfile ..
```

Run the **A↔B scenario**:

```bash
docker run --rm -e MODE=aaip_scenario aaicp-core:dev
```

Generate **real vectors** (they'll be inside the container at `/app/vectors/generated`):

```bash
docker run --rm -e MODE=mint_vectors -v ${PWD}/vectors/generated:/app/vectors/generated aaicp-core:dev
```

Handshake demos:

```bash
docker run --rm -e MODE=handshake_client aaicp-core:dev
docker run --rm -e MODE=handshake_server aaicp-core:dev
```

Open a shell inside the container:

```bash
docker run --rm -it -e MODE=shell aaicp-core:dev
```

Compose (optional):

```bash
docker compose -f docker/docker-compose.yml up --build
```
