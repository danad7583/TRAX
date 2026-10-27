# Logical transmission V2 measurements

Measured again against the final V2 core on 2026-10-26 on the shared Windows
development machine. These are local,
single-threaded library measurements, not network latency, durable-write latency,
or model processing throughput.

## Environment and reproduction

- Windows NT 10.0.26200.0, x86-64/MSVC.
- CPU identifier: Intel64 Family 6 Model 186 Stepping 2, GenuineIntel.
- 20 logical processors visible to the process. Exact marketing model and RAM
  capacity were unavailable through permitted system inventory.
- rustc 1.96.0 (`ac68faa20`, 2026-05-25), LLVM 22.1.2; optimized Cargo bench/release
  profiles, default crate features. No processor affinity or exclusive CPU use.
- Criterion 0.5, 10 samples, one-second warm-up and target measurement per case.
  Criterion extended the largest cases when necessary to collect ten samples.

```powershell
cargo bench --offline --bench transmission_benches -- --sample-size 10 --measurement-time 1 --warm-up-time 1 --noplot
cargo run --offline --release --example transmission_memory
cargo bench --offline --bench transmission_benches -- --test
```

Source: `benches/transmission_benches.rs` and `examples/transmission_memory.rs`.
Criterion writes its estimates and confidence intervals beneath `target/criterion`.
The measured run's console capture is `target/transmission_bench_2026-10-26.log`;
these generated artifacts are not versioned. All 32 benchmark cases also passed
Criterion's separate test mode. The benchmark and memory example pass Clippy.

## Variable transmission timing

Every packet contains 1,024 payload bytes. V2 uses SHA-512/256 and one Ed25519
signature on the final packet. Fixtures use fully verified three-node genesis;
genesis construction/verification is outside the timed operation. Each admission
starts with a fresh session and no previous data history.

- **Root:** indexed/count-bound Merkle hashing of payload-sized byte strings.
  This isolates the primitive; actual transmission leaves contain encoded events.
- **Build:** payload hashing, event construction/linkage, canonical encoding,
  Merkle accumulation, final commitment/signature, and encoded-budget checks.
- **Typed admission:** complete packet checks, payload hashing, event/Merkle/
  history reconstruction, final signature verification, and metadata insertion.
  Source-packet cloning and fresh-session setup use Criterion's untimed setup.
- **Wire admission:** strict typed CBOR decoding plus the same full admission.
  Canonical source-packet encoding and fresh-session setup are outside timing.

Times below are Criterion central estimates in **microseconds per transmission**.
Throughput counts application payload only; it excludes protocol bytes.

| Packets | Payload | Root µs | Build µs | Typed admission µs | Wire admission µs | Wire MiB/s |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 KiB | 1.695 | 47.261 | 63.333 | 73.100 | 13.36 |
| 8 | 8 KiB | 12.273 | 149.017 | 182.063 | 234.689 | 33.29 |
| 17 | 17 KiB | 26.180 | 241.260 | 321.432 | 454.410 | 36.53 |
| 100 | 100 KiB | 151.648 | 1,254.415 | 1,654.239 | 2,369.132 | 41.22 |
| 138 | 138 KiB | 208.945 | 1,784.518 | 2,442.796 | 3,275.104 | 41.15 |
| 1,024 | 1 MiB | 1,566.975 | 12,857.649 | 17,420.692 | 23,406.183 | 42.72 |

Selected 95% confidence intervals for wire admission: 1 packet 71.870–74.220 µs;
100 packets 2.354–2.385 ms; 138 packets 3.225–3.334 ms; 1,024 packets
23.187–23.612 ms. Several cases contained outliers. These short shared-machine
runs are indicative measurements rather than deployment performance guarantees.

## Isolated operations and legacy comparison

| Operation | Central estimate | 95% confidence interval |
|---|---:|---:|
| First nonfinal typed packet, 1 KiB | 13.898 µs | 13.598–14.143 µs |
| Eighth/final packet after seven staged packets | 88.150 µs | 87.400–88.913 µs |
| Ed25519 signature over prepared V2 signing bytes | 24.313 µs | 24.169–24.499 µs |
| SHA-512/256 payload hash, 1 KiB | 1.316 µs | 1.308–1.333 µs |
| SHA-512/256 payload hash, 64 KiB | 73.452 µs | 72.559–74.032 µs |
| SHA-512/256 payload hash, 1 MiB | 1.156 ms | 1.146–1.168 ms |
| Legacy K=8 raw root, BLAKE3, 8 × 1 KiB | 7.839 µs | 7.738–7.978 µs |
| V2 eight-leaf root, BLAKE3, 8 × 1 KiB | 7.407 µs | 7.375–7.441 µs |

The final-packet measurement includes signature verification and insertion of
all eight authenticated metadata nodes. Nonfinal staging does not verify a
public-key signature or release payload. The signature-only measurement excludes
encoding and all event construction.

Legacy and V2 roots have different security transcripts: V2 binds leaf indices,
byte lengths and leaf count. The legacy root helper also constructs inclusion
proofs internally. Their timings therefore compare the exposed implementations,
not identical algorithms or full protocol admission. Neither row is the former
XOR-based prototype verification check.

## Heap usage

The standalone example wraps the Rust global allocator. Values below are live
or peak **allocated Rust heap bytes**, not RSS, allocator overhead, stacks, or OS
buffers. They are deltas above two initialized memory sessions and verified
genesis. The program deliberately retains the input chunks and the sender's
constructed packets while staging receiver copies, exposing that source-memory
cost instead of attributing everything to the Merkle frontier.

| Packets | Input chunks | After sender build | Before final receiver packet | After admission with returned payload | History only | Peak |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1,048 | 2,858 | 2,858 | 10,070 | 3,338 | 12,658 |
| 8 | 8,384 | 22,227 | 34,948 | 42,241 | 6,171 | 45,322 |
| 17 | 17,816 | 47,130 | 74,634 | 110,710 | 23,946 | 110,710 |
| 100 | 104,800 | 276,791 | 466,924 | 563,949 | 95,903 | 567,030 |
| 138 | 144,624 | 381,937 | 699,312 | 889,075 | 188,641 | 892,156 |
| 1,024 | 1,073,152 | 2,833,499 | 4,592,724 | 5,376,641 | 782,795 | 5,379,722 |

“History only” drops the returned verified payload, sender packets and input
chunks, retaining receiver metadata, original final signature and node indexes.
Vec/BTreeMap capacity changes explain uneven per-node retained sizes. The
streaming Merkle frontier retains only O(log N) hashes, while provisional packet
payloads remain buffered until authentication. Full session metadata grows with
accepted history; this example measures one transmission, not long-running
session growth. No journal fsync, network I/O, or application payload processing
is included in these timing or heap figures.
