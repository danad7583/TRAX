# Supported development and demonstration workflow

## Build matrix

Rust 1.89+ and a native linker are required. Serde and Ed25519 are mandatory.
SHA-512/256 is always supported; optional `hash-blake3` makes BLAKE3 available,
and optional `python` adds the thin binding module. Agreed profiles select an
algorithm explicitly; feature availability does not change a negotiated hash.

```sh
cargo fmt --check
cargo build --locked
cargo test --locked
cargo test --locked --all-features
cargo test --locked --no-default-features
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo bench --locked --bench transmission_benches -- --test
cargo run --locked --example session
python scripts/check_public_api.py
node tests/verify_transcript.cjs
```

On Windows install Visual Studio C++ Build Tools and the Windows SDK. With a
virtual environment, set `PYO3_PYTHON` to its interpreter for all-feature builds.
Cached-dependency builds may add `--offline` without changing the checks.
No supported `no_std`, alternate signing-stack or old fixed-window feature
configuration is advertised.

## Python

```sh
python -m venv .venv
# Activate .venv using the command for your shell.
python -m pip install maturin pytest
maturin develop --locked --release --features python
python -m pytest tests/test_python_bindings.py
```

PowerShell activation: `.venv\Scripts\Activate.ps1`. Linux activation:
`source .venv/bin/activate`. Alternatively build a wheel with
`maturin build --locked --release --features python` and install it in the target
environment. Private keys remain opaque Rust objects; the Python relationship
API is memory-only and has no unchecked checkpoint restore.

## One canonical example and image

`cargo run --locked --example session` demonstrates both mirrors, multiple
requests/responses, original initiator closure, complete traversal and a linked
next session initiated by the other participant. It opens no sockets.

```sh
docker build --tag trax-demo .
docker run --rm trax-demo
```

The one root multistage Dockerfile builds/runs that same example. There are no
alternate protocol modes, duplicate Dockerfiles, Compose scenarios or dispatcher
scripts. CI is configured to build and run the image; local execution requires a Docker CLI
and daemon. Library/example success alone is not Docker validation.

## Conformance and performance

The checked-in `vectors/relationship.cbor` contains original signed artifacts
for two continuous sessions with both initiators. Rust consumes its fixed
signatures; Node/OpenSSL independently reconstructs encoding, Merkle roots,
all record IDs/digests, signatures and closures. Normal tests never rewrite it.
Deliberate protocol changes may run `cargo run --example generate_transcript`,
then review the byte/hash changes and rerun the independent verifier.

The incompatible standalone-session fixture exists only for rejection tests.
It is not a supported protocol or positive conformance vector.

Run measurements with the commands in [PERFORMANCE.md](PERFORMANCE.md).
Do not reuse historical throughput figures after changing measured code.

## Durable operation

Create `DurableRelationship` from a fresh accepted genesis. Persist the exact
latest checkpoint in authenticated rollback-resistant host storage. At open,
provide that pin and freshly authorized genesis. Failure is fail-closed; do not
truncate a journal silently, rewrite trusted history or bypass the pin check.
Coordinate application side effects transactionally outside the library.

TRAX-Transport-Lab is retired and is not a supported integration target. AAICP
integration is separate; no transport, EC2, GPU/model or end-to-end network
compatibility is claimed by these library checks.
