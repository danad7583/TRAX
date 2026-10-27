# TRAX logical transmission profile V2

Status: implemented protocol specification. V2 is a separate protocol, not a reinterpretation of legacy V1 windows or the shared fixed-cadence graph profile. Those APIs, signatures, rotation proofs, and journals remain unchanged. No session mixes proof formats.

## Repository baseline and compatibility

The requested baseline is `929016e` (Harden K-window session admission). A fetch on 2026-10-26 found no newer remote main commit. Local `f86312a` adds immutable shared graphs, explicit K and algorithm negotiation, bilateral rotation/configuration exchanges, retired-key enforcement, and locked durable journals. V2 preserves those interfaces; replacing literal 8s would discard their security semantics.

V2 does not negotiate a K. Its batch is one request or response. Existing `SegmentConfig`, `ProtocolConfig`, `ReceiveAdmissionWindow`, `PairDag`, and `DurableDag` remain legacy profiles. Their proofs cannot enter V2 admission. Live rotation of a V2 session is not defined in this revision: keys are pinned by verified genesis. A new key requires a new, explicitly trusted genesis and new session; existing legacy rotation interfaces continue to work in their own profile. Hosts must apply their current retirement/trust policy when accepting genesis.

## Encoding and cryptography

Wire records are length-first deterministic CBOR maps with named fields and no unknown fields. Hashes and public keys are CBOR byte strings of exactly 32 bytes; signatures are byte strings of exactly 64 bytes. Integers are unsigned and checked. Enum labels and all field names are specified by the Rust V2 structs. Strict typed decoding requires exact re-encoding equality, rejecting discarded tags, trailing bytes, duplicate keys, and alternative encodings. Each wire record is bounded before decoding; nesting is bounded.

The genesis profile explicitly chooses Ed25519 and either SHA-512/256 or available BLAKE3. Domain strings below include the final NUL byte. `H` is that selected 32-byte hash; `CBOR` is deterministic encoding. Signing input is the domain followed directly by CBOR of the signature-free commitment. No arbitrary root signature is an admission proof.

Variable Merkle trees use domain-separated indexed leaves, a deterministic unbalanced binary tree, and a count-bound root. The tree splits at the largest power of two strictly smaller than the leaf count. Thus odd leaves are neither duplicated nor padded. Leaves bind their zero-based index and byte length as unsigned 64-bit big-endian integers. Domains are `TRAX:MERKLE:LEAF:V2\0`, `TRAX:MERKLE:NODE:V2\0`, and `TRAX:MERKLE:ROOT:V2\0`; the outer root binds the positive leaf count. A streaming frontier uses O(log N) hashes. Legacy K=8 leaf/node domains and vectors are unchanged.

## Three-node shared genesis

An offer signed by A, an acceptance signed by B, and a confirmation signed by A form the complete transcript. Each event binds version, step, nonce, advertised participant keys, exact accepted profile, and the previous signed genesis-node hash. The offer has no responder key and a zero previous tip. Acceptance repeats the offer parameters and adds B's key. Confirmation repeats acceptance parameters. All three use signing domain `TRAX:GENESIS:V2\0`; node IDs use `TRAX:GENESIS:NODE:V2\0` over the original signed node. The shared anchor hashes the complete three-node transcript under `TRAX:GENESIS:ANCHOR:V2\0`.

Signature verification establishes key possession. Explicit caller trust callbacks separately authorize advertised identities; verification alone never grants peer authorization. Local records preceding the offer are outside the shared anchor. A verified-genesis token has private fields and cannot be deserialized or constructed unchecked. Existing Packet 0 APIs remain available and do not substitute for the three nodes.

## Session and transmission state machine

A session context binds V2, the shared genesis anchor, profile, both keys, session initiator, and a fresh application-supplied 32-byte nonce. The session ID is a domain-separated hash of that context. Either peer may be the initiator. One authoritative order is supported; concurrent or forked transmissions require host serialization, not reconciliation.

The state is `AwaitingRequest -> AwaitingResponse -> AwaitingRequest`, repeated until initiator closure. Each request is authored by the initiator and each response by the other peer. Transmission IDs are consecutive positive integers within the session; event counters are consecutive positive integers across its transmissions. Keys remain at pinned epoch zero. Neither unsigned metadata nor a peer-supplied replacement key can change authority.

Each `PacketEventV2` binds version, relationship anchor, session ID, transmission ID, initiator, sender, receiver, sender key epoch, request/response kind, bounded application message type, zero-based packet index, global event counter, previous tip, payload hash, payload length, and final-packet flag. Payload hash is `H("TRAX:PAYLOAD:V2\0" || payload)`. Event tip is `H("TRAX:EVENT:V2\0" || CBOR(event))`. Every packet, including the final one, contributes exactly one node.

`PacketV2` contains that event, its payload bytes, and an optional `TransmissionSealV2`. Only an event marked final has a seal. The Merkle leaf data is `CBOR(event)`, which already binds its validated payload bytes. The event excludes the seal, eliminating circular hashing. The last data packet carries the seal; no extra seal packet is required.

`TransmissionCommitmentV2` binds version, purpose, relationship anchor, session ID, transmission ID, initiator, actual sender, receiver, key epoch, kind, message type, starting committed tip, first and last counters, exact packet count, exact payload byte count, ordered Merkle root, and final event tip. Its Ed25519 signing domain is `TRAX:TRANSMISSION:V2\0`. Receivers independently reconstruct every field instead of trusting sender claims.

Only one provisional receiver exists per mutable session. Staging checks exact expected context, linkage, counters, payload, resource limits, and final framing, but exposes no payload. A final signature authenticates the entire reconstruction. Any failure clears provisional storage and commits zero events. Successful admission returns a non-forgeable verified transmission and atomically advances the tip, counters, transcript hash, and next expected direction. Dropping/aborting or expiry clears provisional data without modifying trusted state.

The configured positive limits bound packet count, per-packet data, total transmission payload, encoded packet bytes, and elapsed provisional lifetime. The host schedules timeout polling; ordinary staging also checks expiry. Bounded memory stores only the current transmission's payload; history retains authenticated metadata and signatures. Transport framing is external. The packet builder checks the complete encoded final packet against its selected budget and reduces final data capacity when fragmenting a byte stream.

## Mirroring and full-history closure

The session transcript hash starts with `H("TRAX:HISTORY:INIT:V2\0" || CBOR(context))`. Each admitted event updates it using `H("TRAX:HISTORY:EVENT:V2\0" || previous_hash || CBOR(event))`; the original final seal updates it with `H("TRAX:HISTORY:AUTH:V2\0" || previous_hash || CBOR(seal))`. Thus the full ordered metadata, payload commitments, and original signatures are included, with no payload concatenation. Both peers admit identical artifacts and obtain identical hashes.

Only the initiator may close, only while awaiting a request after at least one complete request/response pair, and never with pending data. `SessionCloseCommitmentV2` binds version, closure purpose, relationship/session, initiator and both participants, final data tip, exact history hash before closure, first/last included event positions, event count, completed transmission ID, and terminal counter. It is signed under `TRAX:SESSION:CLOSE:V2\0`. The original signed terminal node is hashed under `TRAX:SESSION:TERMINAL:V2\0`, mirrored without countersigning, and moves the session to Closed. Its own node is excluded from its signed history hash. Duplicate, stale-session, responder-authored, and mismatched-boundary closures fail without mutation.

## Persistence and replay boundary

Memory-only sessions reject replay relative to their current state but cannot prove freshness after a rollback or independently duplicated process. The V2 durable wrapper owns an exclusive journal lock, verifies before writing, synchronizes before admission or payload release, and poisons the writer after I/O failure. Reopening revalidates genesis and every transmission/closure against an externally trusted exact latest checkpoint. A stale external checkpoint is not rollback-resistant; checkpoint pin storage and atomic coupling to application side effects remain host responsibilities. Partial/corrupt journal tails fail closed; no silent recovery is performed.

There is no claim to prevent transparent relay, denial of service, stolen-key impersonation, or passive reading of plaintext payloads. The property is that unauthenticated modification, injection, or substitution cannot become trusted application input without the expected sender's signature. Network delivery acknowledgments and application policy remain outside TRAX. Closure does not prove durable delivery to the other peer.

Durable replay retains packet/parser/resource and signature checks but does not
apply live network elapsed-time deadlines to already-completed historical
transmissions. Replay never releases application payloads. Only the private
journal restoration path can omit that live deadline.

## Worked flow

A and B complete the three signed genesis records. A creates a fresh session. A's 100 transport-sized data chunks become events 1..100; only packet 100 has A's signature over the count-bound 100-leaf Merkle commitment. B stages all packets and exposes nothing until packet 100 verifies, then commits all 100. B sends a 17-packet response at counters 101..117, signed only on its last packet. A admits the complete response. Both may repeat request/response rounds. A finally signs the full agreed history through the last response; B verifies and appends A's identical signed terminal artifact. No K padding or receiver countersignature is used.

## Exact wire schema

All maps below deny unknown fields. Field declaration order does not affect
encoding: encoded keys sort by their encoded length, then encoded lexical bytes.
`hash32` and `key32` mean exactly 32-byte CBOR byte strings. `sig64` means a
64-byte CBOR byte string, checked before cryptographic acceptance. `uint` uses
the shortest unsigned CBOR integer encoding. There are no timestamps or floats.
Optional fields are present with either their value or CBOR null. Empty payload
bytes are permitted but still form a real signed transmission event.

| Record | Exact fields |
| --- | --- |
| `TransmissionLimitsV2` | `max_packets: u32`, `max_payload_bytes: u64`, `max_packet_payload_bytes: u32`, `max_wire_packet_bytes: u32`, `timeout_ms: u64` |
| `TransmissionProfileV2` | `version: 2`, `signing_algorithm: "ed25519"`, `hash_algorithm: "sha512-256" or "blake3"`, `limits: TransmissionLimitsV2` |
| `GenesisEventV2` | `version: 2`, `step: "offer" / "accept" / "confirm"`, `previous_tip: hash32`, `nonce: hash32`, `initiator_public_key: key32`, `responder_public_key: key32 or null`, `profile: TransmissionProfileV2` |
| `GenesisNodeV2` | `event: GenesisEventV2`, `signature: sig64` |
| `SessionContextV2` | `version: 2`, `relationship_id: hash32`, `profile: TransmissionProfileV2`, `initiator: key32`, `responder: key32`, `nonce: hash32` |
| `PacketEventV2` | `version: 2`, `relationship_id: hash32`, `session_id: hash32`, `transmission_id: u64`, `initiator: key32`, `sender: key32`, `receiver: key32`, `key_epoch: 0`, `kind: "request" or "response"`, `message_type: UTF-8 text`, `packet_index: u32`, `counter: u64`, `previous_tip: hash32`, `payload_hash: hash32`, `payload_len: u32`, `is_final: bool` |
| `TransmissionCommitmentV2` | `version: 2`, `purpose: "logical-transmission"`, `relationship_id: hash32`, `session_id: hash32`, `transmission_id: u64`, `initiator: key32`, `sender: key32`, `receiver: key32`, `key_epoch: 0`, `kind: "request" or "response"`, `message_type: UTF-8 text`, `starting_tip: hash32`, `first_counter: u64`, `last_counter: u64`, `packet_count: u32`, `payload_bytes: u64`, `merkle_root: hash32`, `final_event_tip: hash32` |
| `TransmissionSealV2` | `commitment: TransmissionCommitmentV2`, `signature: sig64` |
| `PacketV2` | `event: PacketEventV2`, `payload: CBOR byte string`, `authentication: TransmissionSealV2 or null` |
| `SessionCloseCommitmentV2` | `version: 2`, `purpose: "session-close"`, `relationship_id: hash32`, `session_id: hash32`, `initiator: key32`, `responder: key32`, `final_data_tip: hash32`, `history_hash: hash32`, `first_counter: u64`, `last_counter: u64`, `event_count: u64`, `transmission_id: u64`, `terminal_counter: u64` |
| `SessionTerminalV2` | `commitment: SessionCloseCommitmentV2`, `signature: sig64` |
| `SessionCheckpointV2` (external state pin) | `session_id: hash32`, `tip: hash32`, `history_hash: hash32`, `event_count: u64`, `transmission_id: u64`, `closed: bool` |
| `InclusionProofV2` | `leaf_index: u32`, `leaf_count: u32`, `siblings: array of hash32`, ordered bottom-up using the deterministic split tree |

The profile is transitively signature-bound through the shared genesis anchor
and the session ID. `session_id = H("TRAX:SESSION:ID:V2\0" || CBOR(context))`.
The initial application-session tip is
`H("TRAX:SESSION:ANCHOR:V2\0" || session_id || relationship_id)`.
Local genesis bookkeeping and legacy graph identities never enter this anchor.

The three signature preimages are exactly:

1. `"TRAX:GENESIS:V2\0" || CBOR(GenesisEventV2)`.
2. `"TRAX:TRANSMISSION:V2\0" || CBOR(TransmissionCommitmentV2)`.
3. `"TRAX:SESSION:CLOSE:V2\0" || CBOR(SessionCloseCommitmentV2)`.

Ed25519 signs these bounded commitment bytes directly, without prehashing the
signature input or concatenating the complete transmission payload. A receiver
reconstructs the expected commitment from trusted state and validated events;
it does not authorize the signer from a key advertised by an incoming packet.

`message_type` is nonempty UTF-8 with at most 64 encoded bytes and identical
across a transmission. Kind, direction and IDs are determined by session state.
The application supplies fresh genesis/session nonces; TRAX cannot establish
global nonce uniqueness without the host's persistent identity ledger.

Default bounds are 16,384 packets, 16 MiB payload per transmission, 1,400 data
bytes per packet, 4,096 full encoded bytes per packet, and 30 seconds elapsed
provisional lifetime. Negotiated hard maxima are 1,048,576 packets, 256 MiB
payload, 1 MiB encoded packet, and 24 hours. All limits must be positive;
per-packet payload must fit both total payload and full wire bounds. A selected
wire budget too small for even an empty authenticated final packet is rejected
by the builder. The decoder enforces a 64-level nesting limit before typed
admission, in addition to its input-byte cap.

After closure, the public checkpoint includes the terminal node: event count
is the terminal counter, tip is its signed-artifact hash, and history hash is
`H("TRAX:HISTORY:TERMINAL:V2\0" || preclose_history_hash || CBOR(terminal))`.
The signed closing commitment itself always excludes its terminal artifact.

## Durable framing

V2 journals have independent magic `TRAX:TRANSMISSION:JOURNAL:V2\0`. Each
frame is `u64BE(encoded_length) || canonical_record || checksum32`, where
`checksum32 = SHA-512/256("TRAX:JOURNAL:FRAME:V2\0" || canonical_record)`.
The initial header is `{genesis: [offer, accept, confirm], context: SessionContextV2}`.
Later records are Serde externally tagged enums `{Packet: PacketV2}` or
`{Terminal: SessionTerminalV2}`. These journal enum labels are case-sensitive.
Header decoding is capped at 65,536 bytes; record decoding is capped at the
negotiated encoded-packet limit plus 128 bytes of enum framing allowance.

No provisional packet is journaled. Once the final signature verifies, the
wrapper writes the transmission's packet frames and performs one `sync_all`
before trusted state advances or payload is returned. Replay admits only at
verified final packets; a trailing provisional transaction is an error, even
if each preceding frame checksum is valid. A checksum detects corruption and
never substitutes for a signature. External pin updates, filesystem directory
durability, backups, and transactional application effects remain host duties.
