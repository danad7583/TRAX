# TRAX development runbook

This runbook covers local builds, tests, benchmarks, and packaging. It does not define a host protocol or deploy a service. See [README](../README.md) for library boundaries and [DAG contract](DAG.md) for shared history and checkpoint behavior.

Genesis binds shared K/signing/hash algorithms, all DAG events count, and records stay provisional until a complete checkpoint. Either participant may seal an ordinary mixed-author segment. Rotation, configuration and closure additionally require a detached peer prefix acknowledgment followed by the initiator's final checkpoint. Durable journal replay re-verifies the recorded history.

## Toolchain

Use Rust 1.89 or newer:

~~~sh
rustc --version
cargo --version
~~~

On Windows, install Visual Studio Build Tools with Desktop development with C++ and the Windows SDK. Restart the terminal after installation. The MSVC linker must be available:

~~~powershell
where.exe link
~~~

On Linux, install the distribution's C/C++ compiler/linker and development headers. These commands should resolve:

~~~sh
cc --version
make --version
~~~

The checked-in Docker builders use Rust 1.89 with Debian Bookworm, matching the runtime distribution. Their containers run demonstration executables; they are not agent hosts.

## Build and Rust checks

From the TRAX repository root:

~~~sh
cargo build --locked --release
cargo test --locked
cargo check --locked --all-targets
cargo fmt --check
~~~

Default Cargo tests do not run Python tests. Record the actual current results; do not use an old three-test transcript as a release gate.

Shared-DAG applications authenticate a shared `ProtocolConfig` at genesis. `with_default_k(signing_algorithm, hash_algorithm)` constructs K=8; `new(k, signing_algorithm, hash_algorithm)` permits an override. Shared K must exceed 4 (minimum 5) and fit u32. Signing/hash algorithms remain explicit, and serialized genesis still requires K and both algorithm fields. SHA-512/256 is always available at runtime; BLAKE3 requires its build feature. Unsupported selections must fail rather than fall back. All DAG events, including forks, rotations, configuration actions, control records and padding, count toward shared K; only a full checkpoint commits.

For rotation, `rotate(author, parent, branch, &old_key, &new_key)` starts a fresh segment on a new fork, with old-key authorization and new-key possession proof. The peer uses `acknowledge_and_pad(peer, &peer_key)` to add filler through K−2 and sign an `Acknowledge` prefix ending at K−1. The initiator replays it, calls `accept_ack(&proof)`, and supplies `finish_close()` or a real request in the final slot. The initiator's current key signs the final full checkpoint; after rotation it must use the replacement key. A peer or retired old key cannot finalize that exchange. Prefix evidence is embedded in the full proof and retained by `acknowledgment_for(proposal)`; full checkpoint lookup uses `checkpoint_for(participant, node_hash)`. Prefix verification alone never commits partial history.

Configuration is a current-key-authorized fork proposal at the first event of a fresh segment. Its new K/hash apply to the proposal and exchange immediately, and the accepted current configuration changes only after both peer ACK and final checkpoint verify. Old K=8 to new K=5 therefore has a four-event prefix and final event five. Ordinary requests and full ordinary segments receive no automatic padding. `request_close(author, branch)` explicitly opens a close exchange only with at least three slots available; only its peer ACK step adds filler. A final real request can continue instead of closing. Recorded mutual closure cannot force a physical peer to remain connected.

Legacy same-author session helpers still use explicit `SegmentConfig::new(k)`. Positive values up to u32::MAX, including K=1 and odd values, are supported; shared ProtocolConfig's minimum K=5 does not apply to them. Their K1/3/4/5/8/14, incomplete-window, cross-K and arithmetic tests are distinct from shared-graph tests. Run `cargo test --test profile` for runtime configuration/hash checks and `cargo test --test handshake` for the bilateral exchange checks.

The alternative hash profile can be compiled explicitly:

~~~sh
cargo check --locked --no-default-features --features crypto-ed25519,hash-sha2,serde
~~~

The command above removes BLAKE3 availability and selects the legacy SHA-512/256 helper profile. Shared-DAG runtime selection remains explicit in ProtocolConfig. New graph records/proofs remain portable across builds supporting the selected runtime algorithms and are verified against their recorded configuration, not whichever legacy hash32 algorithm is locally enabled. Legacy compile-time hash outputs are not interchangeable. The feature name `no_std` is not a working no-std guarantee.

## Encoding compatibility

Version 0.2 replaces prototype map declaration/insertion order with strict length-first deterministic CBOR. Map keys sort recursively by encoded length and then bytes; duplicate keys, noncanonical representations, and trailing data are rejected.

Prototype V1 bytes, node IDs, hashes, proofs, and signatures must not be reused under the new profile. There is no automatic migration. Validate the fixed-byte CBOR conformance test and the broader `tests/encoding.rs` checks when changing encoding.

The durable journal uses version 3 for the exchange-proof format. Earlier journal formats are not automatically migrated; preserve their version boundary when reviewing storage changes.

## Python extension workflow

Use a Python virtual environment and activate it before installing build tools.

~~~sh
python -m venv .venv
~~~

PowerShell activation:

~~~powershell
.venv\Scripts\Activate.ps1
~~~

Linux activation:

~~~sh
source .venv/bin/activate
~~~

Then build and test:

~~~sh
python -m pip install maturin pytest
maturin develop --release --features python
python -m pytest tests/test_python_bindings.py tests/test_tcp_packet0_local.py
~~~

For wheel packaging instead of a development install:

~~~sh
maturin build --release --features python --out dist
~~~

Install the resulting wheel before running pytest against that build. The CI wheel job builds, installs, and tests both Python test files. Python bindings expose Rust-backed crypto, Packet0, and same-author window helpers; Python tests are not a Python transport implementation inside the Rust library.

## Benchmark interpretation

~~~sh
cargo bench --bench dag_benches
~~~

Benchmark fixtures explicitly select K=8. The legacy session-window group measures ordered event Merkle-root computation, complete segment-seal creation, and intrinsic signed-proof verification. The ordinary shared-DAG group uses runtime SHA-512/256 and measures segment preparation, staging and sealing, and full admission at 0 and 1,024 previously committed events. The admission benchmark clones the mutable fixture before timing and drops it after timing so history setup and teardown do not dominate the measured operation. These benchmarks do not measure a bilateral rotation/closure exchange, complete host exchange, remote model inference, or disk-journal replay.

Do not carry forward the old XOR cumulative-hash timings or the bare-root signing speedup as current authenticated admission performance. `src/bin/test_perf.rs` compares direct signatures with a bare Merkle-root signature; that raw signature is not a session-bound segment seal.

When reporting a measurement, include revision, selected K/hash profile, hardware, build mode, actual operation, and repeated-run results. No fixed latency or throughput is promised. Criterion plotting-tool warnings do not change which operation was measured.

## Demonstration programs and containers

~~~sh
cargo run --example handshake_client
cargo run --example handshake_server
cargo run --example aaip_scenario
cargo run --example mint_vectors
~~~

The handshake examples derive and print a session ID from demonstration inputs; they do not connect over TCP/UDP or implement an on-wire handshake. `tests/test_tcp_packet0_local.py` is a local loopback Packet0 test fixture, not a production TCP service. Scenario/vector examples do not establish complete wire or COSE conformance.

Optional local Docker demonstration, from the repository root:

~~~sh
docker build -t trax-demo -f Dockerfile .
docker run --rm trax-demo
~~~

The multi-mode demonstration image builds the example binaries:

~~~sh
docker build -t trax-core:dev -f docker/Dockerfile .
docker run --rm -e MODE=aaip_scenario trax-core:dev
docker run --rm -e MODE=handshake_client trax-core:dev
docker run --rm -e MODE=handshake_server trax-core:dev
~~~

These commands run local demonstrations; they do not deploy a TRAX endpoint. The normal image build does not include Criterion benchmark executables; run benchmarks with Cargo in the development environment.

## Review before publishing

~~~sh
git status --short
git diff --check
~~~

Review changed source and tests, current Python packaging metadata, [MIT license](../LICENSE), and documentation together. Generated build outputs and vector-generation outputs should remain outside source control. Historical vector filenames are not evidence that their contents conform.

The library does not provide a model API, HTTP server, automatic network key exchange, encryption stack, malicious-peer classification, or network alerts. Legacy replay/quarantine helpers have the limits described in the README. Keep a clear distinction between same-author admission helpers, shared paired-history semantics, and application behavior.

Publishing, remote changes, or deployment are separate actions; the commands above do not authorize them.
