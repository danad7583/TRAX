# TRAX

**Trust Resolution and Agent eXchange** is a Rust cryptographic library for two
agents to maintain one continuous, mirrored relationship history. It establishes
authorized keys through three signed genesis records, authenticates complete
logical transmissions with variable-length Merkle commitments, and verifies
initiator-controlled session closure.

Each packet contributes one hash-linked event. Only the last data packet of a
request or response contains its sender's Ed25519 signature. The receiver checks
every payload hash, link, counter, identity, context and Merkle commitment before
atomically admitting the transmission and releasing authenticated payloads.
Intermediate receipt is provisional. There is no fixed packet cadence or
automatic padding.

Either participant may initiate a session. Requests and responses can repeat
before the initiator closes it. The next session must continue from the accepted
closure and relationship digest; an unclosed session cannot silently reset or
fork. The full typed history includes genesis, session starts, packet events
with original seals, and original signed closures. The receiver verifies and
mirrors a closing artifact without countersigning it.

## Rust integration

Use these modules and types:

| Responsibility | API |
| --- | --- |
| Explicit algorithms and bounded resources | `config::{TransmissionProfile,TransmissionLimits,HashAlgorithm,SigningAlgorithm}` |
| Three-node genesis and caller trust | `genesis::{create_genesis_offer,accept_genesis_offer,confirm_genesis,VerifiedGenesis}` |
| Continuous authority and read-only session state | `session::{Relationship,Session}` |
| Full immutable history and traversal | `session::{HistoryRecord,HistoryKind}`, `Relationship::{history,record,ancestors,children}` |
| Packet/commitment/closure artifacts | `transmission` |
| Locked, sync-before-release persistence | `storage::DurableRelationship` |
| Hashing, Ed25519, variable Merkle roots | `crypto`, `merkle` |
| Deterministic encoding and bounded strict decoding | `encoding::{encode_deterministic,decode_strict}` |

After independently validating the three-node transcript and applying trust:

```rust,ignore
let mut history = Relationship::new(verified_genesis)?;
history.begin_session(local_public_key, fresh_nonce)?;
let packets = history.build_transmission(&private_key, "document.request", &chunks)?;
// Transport the original packets. Both mirrors admit through the same path.
receiver.start_receive()?;
for packet in packets {
    if let Some(verified) = receiver.stage_packet(packet)? {
        process_authenticated_payload(verified.payload_chunks());
    }
}
```

A receiver may start with no active session; packet zero carries a proposed
session context. Its predecessor must match the receiver's authoritative state.
The first complete valid request admits that session start atomically with its
packets. A `VerifiedTransmission` cannot be constructed unchecked.

`fragment_transmission` accounts for the complete encoded packet budget,
including first-context and final-signature overhead. Per-packet data size and
transport payload budget are distinct negotiated limits. The lab reference of
1,400 data bytes is not a universal UDP datagram size.

## Build and run

Rust 1.89 or newer and a native linker are required. On Windows use Visual
Studio C++ Build Tools and the Windows SDK. The supported feature choices are
default optional BLAKE3 availability, `--no-default-features` for SHA-512/256
only, and `python` for optional bindings. Serde and Ed25519 are required core
dependencies. The agreed genesis profile always selects the actual algorithm;
unavailable algorithms fail rather than falling back.

```sh
cargo build --locked
cargo test --locked
cargo run --locked --example session
```

The example runs a 100-packet request, signed responses, multiple exchanges,
closure, and a linked next session initiated by the other participant. It opens
no transport ports. For complete checks, Python setup and Docker see
[RUNBOOK](docs/RUNBOOK.md).

## Python

Bindings are thin and **memory-only**. Opaque Rust private keys, explicit trust,
relationship state and admission remain in Rust:

```python
import trax
a, b = trax.generate_keypair(), trax.generate_keypair()
offer = trax.create_genesis_offer(a["private_key"], trax.generate_nonce(),
                                 hash_algorithm="sha512-256")
accept = trax.accept_genesis_offer(offer, b["private_key"], a["public_key"])
confirm = trax.confirm_genesis(offer, accept, a["private_key"], b["public_key"])
history = trax.Relationship(offer, accept, confirm,
                            [a["public_key"], b["public_key"]])
history.begin_session(a["public_key"], trax.generate_nonce())
```

`start_receive` and `stage_packet` return no authenticated payload until the
final signature succeeds. `history`, `record`, `ancestors` and `children` expose
canonical bytes of accepted records, including closure. Checkpoint dictionaries
are inspection values, not unchecked restoration capabilities.

## Scope and trust boundaries

TRAX does not open sockets, run models/tools, route requests, encrypt payloads,
infer malicious intent or authorize application actions. AAICP will provide
transport and orchestration as a separate Rust consumer. The retired transport
lab has no compatibility layer or continuing test obligation.

In-session key rotation is unsupported. Keys are pinned by genesis; a new
relationship requires explicit acceptance under the host's current trust and
retirement policy. Never accept a replacement key merely because it self-signs.

Durable use requires an authenticated fresh external latest-state pin and host
coordination of application side effects. Memory state alone does not provide
crash-safe exactly-once effects. Signatures do not detect an unchanged transparent
relay or prevent authorized-key compromise, denial of service or plaintext
inspection.

The package 0.3.0 cutover intentionally removes old APIs and journals. Genesis
and Merkle encodings remain unchanged; session schema 3 adds predecessor-bound
continuity. See [MIGRATION](docs/MIGRATION.md) for deletions and naming maps,
[PROTOCOL](docs/PROTOCOL.md) for exact signed bytes,
[DAG](docs/DAG.md) for traversal, [SECURITY](docs/SECURITY.md) for guarantees,
and [PERFORMANCE](docs/PERFORMANCE.md) for measured costs.
