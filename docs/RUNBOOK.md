
# TRAX v1.1.0 — Real Scenario Runbook

## 0) Prereqs
- Rust stable
- Linux/macOS/WSL

## 1) Build
```bash
cargo build --release --features crypto-ed25519,hash-blake3
```

## 2) Handshake sanity check
```bash
cargo run --example handshake_client --features crypto-ed25519,hash-blake3
cargo run --example handshake_server --features crypto-ed25519,hash-blake3
```

## 3) Mint real vectors
```bash
cargo run --example mint_vectors --features crypto-ed25519,hash-blake3
ls vectors/generated
```

## 4) Full A ↔ B scenario
```bash
cargo run --example aaip_scenario --features crypto-ed25519,hash-blake3
```

## 5) Benches
```bash
cargo bench --bench dag_benches
```
