# Performance

Measured 2026-10-27 against the cleaned TRAX 0.3.0 implementation on the shared
Windows development machine. These are single-threaded local library
measurements. They do not measure network latency, durable-write latency, or
application/model processing.

## Environment and reproduction

- Windows NT 10.0.26200.0, x86-64/MSVC.
- CPU identifier: Intel64 Family 6 Model 186 Stepping 2, GenuineIntel.
- 20 logical processors visible to the process. Exact CPU marketing model and
  RAM capacity were unavailable through permitted system inventory.
- rustc 1.96.0 (`ac68faa20`, 2026-05-25), LLVM 22.1.2.
- Optimized Cargo bench/release profiles, default crate features. No processor
  affinity or exclusive machine/CPU ownership.
- Criterion 0.5: ten samples, one-second warm-up and target measurement per case.
  Criterion extends a case when necessary to collect ten samples.

```powershell
cargo bench --offline --bench transmission_benches -- --sample-size 10 --measurement-time 1 --warm-up-time 1 --noplot
cargo run --offline --release --example transmission_memory
cargo bench --offline --bench transmission_benches -- --test
```

Sources: [transmission_benches.rs](../benches/transmission_benches.rs) and
[transmission_memory.rs](../examples/transmission_memory.rs).
The measured run and the separate smoke run both passed all **31 cases**.
The memory example completed successfully. Criterion estimates and confidence
intervals are under `target/criterion`; the console capture is
`target/transmission_bench_2026-10-27.log`. Generated measurements are not tracked.

## Complete logical transmissions

Every packet contains 1,024 application payload bytes. The transmission fixtures
use SHA-512/256, a fully verified three-node genesis, and exactly one sender
Ed25519 signature on the final actual data packet.

Each admission starts from a fresh relationship with its verified genesis and no
application history. The incoming first packet carries the session-start
context. Genesis verification and relationship initialization are outside the
timed operation; authenticating and admitting that first session's context is
inside it. Sender-side local session preparation is also outside construction
timing. Two-session relationship continuity is covered by protocol tests, not
this timing fixture.

- **Root:** indexed, length-bound, count-bound Merkle hashing of payload-sized
  byte strings. This isolates the primitive; protocol leaves encode packet events.
- **Build:** payload hashing, packet/event construction and linkage, deterministic
  encoding, Merkle accumulation, final commitment/signature, and wire-budget checks.
- **Typed admission:** complete packet checks, payload hashing, session and
  relationship history reconstruction, Merkle/final-signature verification,
  and insertion of authenticated history records and indexes. Source packet
  cloning and fresh-relationship setup are outside timing.
- **Wire admission:** bounded strict typed CBOR decoding plus complete admission.
  Canonical source-packet encoding and fresh-relationship setup are outside timing.

Central estimates below are **microseconds per complete transmission**.
Throughput counts application payload only, excluding protocol bytes.

| Packets | Payload | Root µs | Build µs | Typed admission µs | Wire admission µs | Wire MiB/s |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1 KiB | 1.714 | 46.475 | 96.096 | 111.799 | 8.73 |
| 8 | 8 KiB | 12.519 | 134.365 | 254.348 | 315.989 | 24.72 |
| 17 | 17 KiB | 26.398 | 236.395 | 441.684 | 568.690 | 29.19 |
| 100 | 100 KiB | 152.837 | 1,189.944 | 2,312.100 | 3,001.557 | 32.54 |
| 138 | 138 KiB | 225.956 | 1,716.052 | 3,107.402 | 4,136.042 | 32.58 |
| 1,024 | 1 MiB | 1,579.683 | 12,966.796 | 22,358.889 | 29,974.098 | 33.36 |

Selected 95% confidence intervals for wire admission: one packet
111.069–112.478 µs; 100 packets 2.984–3.033 ms;
138 packets 4.095–4.184 ms; 1,024 packets
29.621–30.215 ms. Several cases contained outliers. These
short shared-machine runs are indicative measurements, not deployment guarantees.

## Isolated operations

| Operation | Central estimate | 95% confidence interval |
|---|---:|---:|
| First nonfinal typed packet, 1 KiB | 26.837 µs | 25.998–27.795 µs |
| Eighth/final packet after seven staged packets | 148.537 µs | 142.852–151.656 µs |
| Ed25519 signature over prepared signing bytes | 24.140 µs | 24.038–24.326 µs |
| SHA-512/256 payload hash, 1 KiB | 1.349 µs | 1.339–1.366 µs |
| SHA-512/256 payload hash, 64 KiB | 74.648 µs | 73.633–75.856 µs |
| SHA-512/256 payload hash, 1 MiB | 1.177 ms | 1.174–1.179 ms |
| Eight-leaf Merkle root, BLAKE3, 8 × 1 KiB | 7.316 µs | 7.232–7.467 µs |

The first nonfinal-packet case includes provisional adoption and validation of the
incoming session-start context. It does not verify a public-key signature or
release trusted payload. The final-packet case includes verification and atomic
insertion of the session-start record and all eight authenticated packet records.
The signature-only case excludes encoding and event construction.

The BLAKE3 row measures an explicitly selected hash primitive. The full
transmission cases above use the agreed SHA-512/256 profile; no algorithm is
substituted automatically. No retired implementation or arithmetic-only
verification result is used as a performance baseline.

## Heap usage

The standalone example wraps Rust's global allocator. Values are live or peak
**allocated Rust heap bytes**, excluding allocator overhead, RSS, stacks, and OS
buffers. They are deltas above two initialized relationships with verified genesis
and the sender's unadmitted local session draft.

The example deliberately retains input chunks and sender packets while the
receiver stages copies, so source-memory costs remain visible. The receiver
begins without a local session draft and authenticates the incoming session start.

| Packets | Input chunks | After sender build | Before final receiver packet | After admission with returned payload | History only | Peak |
|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1,048 | 3,114 | 3,114 | 11,230 | 3,218 | 17,368 |
| 8 | 8,384 | 24,275 | 39,044 | 53,257 | 13,091 | 59,953 |
| 17 | 17,816 | 51,482 | 83,082 | 127,886 | 28,578 | 141,278 |
| 100 | 104,800 | 302,391 | 525,292 | 647,413 | 120,999 | 722,557 |
| 138 | 144,624 | 417,265 | 800,176 | 1,031,747 | 230,449 | 1,135,163 |
| 1,024 | 1,073,152 | 3,095,643 | 5,117,012 | 6,933,601 | 1,815,467 | 7,696,201 |

“History only” drops the returned verified transmission, sender packets, and
input chunks. It retains the receiver's accepted session-start and packet records,
original final signature, relationship/session state, and traversal indexes.
Vector and tree-index capacity changes cause uneven retained bytes per node.

The Merkle frontier itself retains only O(log N) hashes. Provisional payloads are
buffered until complete authentication, and authenticated history metadata grows
with accepted history. This example measures one request in the first session,
not long-running history growth or session closure.

Journal fsync, crash recovery, transport I/O, application side effects, model
inference, and subsequent-session workloads are outside these timing and heap
measurements.
