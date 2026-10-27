# Canonical authenticated relationship protocol

This document defines the single supported authentication path. Public component
names are permanent. Numeric wire schemas and domain suffixes remain explicit
cryptographic identifiers: established genesis schema 2 and Merkle construction
2 are unchanged; session, event, transmission, history and journal schema 3
deliberately add continuous relationship authority. Incompatible standalone
session proofs and earlier journal formats are rejected, never reinterpreted.

## Encoding and algorithms

`CBOR(x)` is deterministic, shortest-form CBOR. Map keys sort recursively by
their encoded length and then encoded bytes. Duplicate keys are rejected. Typed
wire structs deny unknown fields. Decoding accepts one item, limits nesting to
64 levels, enforces an input-byte cap and requires exact typed re-encoding.
Discarded semantic tags, trailing bytes and alternate encodings cannot survive.

`H` is the profile's explicitly agreed 32-byte BLAKE3 or SHA-512/256 hash.
Unavailable algorithms fail without fallback. Signing is strict Ed25519 over
the domain bytes followed directly by `CBOR(commitment)`; do not prehash or sign
concatenated raw transmission payloads. All domain strings below include their
final NUL. `u64BE` is an unsigned eight-byte big-endian integer.

Hashes, keys and nonces use exactly 32-byte CBOR byte strings. Signatures are
64-byte byte strings. Payloads are byte strings. Integers are unsigned shortest
CBOR integers of the named width; arithmetic must not overflow. Optional fields
are encoded with their value or CBOR null, including optional hash byte strings.

## Exact wire records

| Record | Exact fields |
| --- | --- |
| `TransmissionLimits` | `max_packets:u32`, `max_payload_bytes:u64`, `max_packet_payload_bytes:u32`, `max_wire_packet_bytes:u32`, `timeout_ms:u64` |
| `TransmissionProfile` | `version:2`, `signing_algorithm:"ed25519"`, `hash_algorithm:"sha512-256" or "blake3"`, `limits:TransmissionLimits` |
| `GenesisEvent` | `version:2`, `step:"offer" / "accept" / "confirm"`, `previous_tip:hash32`, `nonce:hash32`, `initiator_public_key:key32`, `responder_public_key:key32 or null`, `profile:TransmissionProfile` |
| `GenesisNode` | `event:GenesisEvent`, `signature:sig64` |
| `SessionContext` | `version:3`, `relationship_id:hash32`, `profile:TransmissionProfile`, `initiator:key32`, `responder:key32`, `nonce:hash32`, `session_index:u64`, `previous_tip:hash32`, `previous_history_hash:hash32`, `previous_record_count:u64` |
| `PacketEvent` | `version:3`, `relationship_id:hash32`, `session_id:hash32`, `transmission_id:u64`, `initiator:key32`, `sender:key32`, `receiver:key32`, `key_epoch:0`, `kind:"request" or "response"`, `message_type:text`, `packet_index:u32`, `counter:u64`, `previous_tip:hash32`, `payload_hash:hash32`, `payload_len:u32`, `is_final:bool` |
| `TransmissionCommitment` | `version:3`, `purpose:"logical-transmission"`, `relationship_id:hash32`, `session_id:hash32`, `transmission_id:u64`, `initiator:key32`, `sender:key32`, `receiver:key32`, `key_epoch:0`, `kind:"request" or "response"`, `message_type:text`, `starting_tip:hash32`, `first_counter:u64`, `last_counter:u64`, `packet_count:u32`, `payload_bytes:u64`, `merkle_root:hash32`, `final_event_tip:hash32` |
| `TransmissionSeal` | `commitment:TransmissionCommitment`, `signature:sig64` |
| `Packet` | `event:PacketEvent`, `payload:bytes`, `authentication:TransmissionSeal or null`, `session_start:SessionContext or null` |
| `SessionCloseCommitment` | `version:3`, `purpose:"session-close"`, `relationship_id:hash32`, `session_id:hash32`, `session_index:u64`, `initiator:key32`, `responder:key32`, `final_data_tip:hash32`, `session_history_hash:hash32`, `relationship_history_hash:hash32`, `first_counter:u64`, `last_counter:u64`, `packet_count:u64`, `transmission_id:u64`, `terminal_counter:u64` |
| `SessionTerminal` | `commitment:SessionCloseCommitment`, `signature:sig64` |
| `SessionCheckpoint` | `session_id:hash32`, `session_index:u64`, `tip:hash32`, `history_hash:hash32`, `packet_count:u64`, `transmission_id:u64`, `closed:bool` |
| `RelationshipCheckpoint` | `relationship_id:hash32`, `tip:hash32`, `history_hash:hash32`, `record_count:u64`, `completed_sessions:u64`, `last_session_id:hash32 or null`, `active_session:SessionCheckpoint or null` |

`message_type` is nonempty UTF-8 text of at most 64 encoded bytes and is identical
throughout a transmission. Profile/version and all listed fields remain required
in canonical encodings. Checkpoints are inspection/pinning data; they do not
construct unchecked authoritative state.

## Three signed genesis records

1. A signs an offer with its key, nonce, exact profile, no responder key, and
   zero previous tip. B verifies possession and explicitly decides whether A's
   identity is acceptable.
2. B signs acceptance repeating the exact offer parameters, adding B's distinct
   key and referencing A's original signed node hash. A verifies and applies
   explicit trust acceptance to B.
3. A signs confirmation repeating the accepted parameters and referencing B's
   original signed node hash. B verifies A's original signature.

The signing preimage for every step is
`"TRAX:GENESIS:V2\0" || CBOR(GenesisEvent)`.
Each original signed node ID is
`H("TRAX:GENESIS:NODE:V2\0" || CBOR(GenesisNode))`.
The relationship ID is
`H("TRAX:GENESIS:ANCHOR:V2\0" || CBOR([offer,acceptance,confirmation]))`.
Local bookkeeping before this shared transcript is excluded. Full verification
checks all shapes, links, algorithms and signatures before invoking final trust
callbacks. Weak/malformed keys and implicit replacement identities fail.

## Relationship root and session proposal

The accepted root record is position zero, ID equal to the relationship ID,
parent null, and kind `{type:"genesis",transcript:[the three original nodes]}`.
Its initial digest is
`H("TRAX:HISTORY:ROOT:V3\0" || CBOR(root_record))`.

A new context must exactly match the current relationship ID/profile/tip/digest/
record position, an authorized initiator and the other responder. Its ordinal
is `completed_sessions+1`; the host supplies a fresh 32-byte nonce. No accepted
unclosed session may exist. Session ID and proposed start-record ID are:

```
session_id = H("TRAX:SESSION:ID:V3\0" || CBOR(context))
start_id   = H("TRAX:SESSION:START:V3\0" || CBOR(context))
```

The start record points to `context.previous_tip` at position
`context.previous_record_count+1`. This is provisional: beginning or receiving
it alone changes no authoritative checkpoint. Packet zero of transmission one
contains `session_start:context`; every other packet has null. The first event
links to `start_id`; its counter is `previous_record_count+2`.

The receiver reconstructs and validates the context against its own current
authority. The first complete signed request authenticates it transitively
through `session_id` and the first parent link. Start plus packet records commit
atomically, using that request's one final signature. No additional handshake
signature is added to ordinary transmissions.

## Ordered variable Merkle transmission

Requests are authored by the session initiator; responses by the other peer.
Requests/responses alternate for any number of rounds. Transmission IDs start at
one and increase within the session. Packet indices start at zero per
transmission. Event counters are global relationship positions, including start
and terminal records. Every next event links to the previous event tip.

```
payload_hash = H("TRAX:PAYLOAD:V3\0" || received_payload_bytes)
event_tip    = H("TRAX:EVENT:V3\0" || CBOR(PacketEvent))
leaf[i]      = H("TRAX:MERKLE:LEAF:V2\0" || u64BE(i)
                 || u64BE(len(CBOR(event[i]))) || CBOR(event[i]))
inner(L,R)   = H("TRAX:MERKLE:NODE:V2\0" || L || R)
root         = H("TRAX:MERKLE:ROOT:V2\0" || u64BE(N) || tree(leaves))
```

`N` must be positive and within the negotiated and primitive bounds. A singleton
tree is its leaf. Otherwise split at the largest power of two strictly less
than N and recursively hash left/right subtrees. Odd leaves are neither copied
nor padded. Indices, lengths, tree shape, ordering and exact count are bound.
An O(log N) frontier computes the same root without concatenating payloads.
The complete-transmission protocol needs no public inclusion-proof API.

All packets contribute one event, including the final one. The entire seal is
outside the signature-free event: no signature/root circular dependency exists.
Only the final actual data packet has `is_final:true` and non-null authentication.
Its preimage is exactly
`"TRAX:TRANSMISSION:V3\0" || CBOR(TransmissionCommitment)`.

The receiver checks actual payloads, linkage, expected identities/key epoch,
direction, counters, IDs, context, resource limits and final framing, then
independently reconstructs every commitment field and Merkle root. Signature
verification uses its pinned expected sender key, never a replacement provided
by the packet. Failure discards the whole provisional transmission. No verified
token, application callback or authoritative history advance precedes success.

## Typed history and two digests

`HistoryRecord` has `{id:hash32,parent:hash32 or null,position:u64,kind:HistoryKind}`.
`HistoryKind` is a map with a `type` discriminator and these exact fields:

| Type | Additional fields |
| --- | --- |
| `genesis` | `transcript:[GenesisNode;3]` |
| `session_start` | `context:SessionContext` |
| `packet` | `event:PacketEvent`, `authentication:TransmissionSeal or null` |
| `session_terminal` | `terminal:SessionTerminal` |

For each accepted non-root record, update the relationship digest with
`H("TRAX:HISTORY:RECORD:V3\0" || previous_relationship_hash || CBOR(record))`.
The packet record ID is its signature-free event tip, but the digest includes
the original final seal/signature as part of that record.

The session digest starts at
`H("TRAX:HISTORY:INIT:V3\0" || CBOR(context))`.
Each event updates it with
`H("TRAX:HISTORY:EVENT:V3\0" || previous_session_hash || CBOR(event))`.
After each complete transmission, additionally fold its original seal:
`H("TRAX:HISTORY:AUTH:V3\0" || previous_session_hash || CBOR(seal))`.
These separate digests distinguish the current session transcript from the
entire relationship while binding the predecessor through the session context.

## Initiator-only closure and the next session

After at least one complete request/response round, and with no provisional
transmission, only the initiator may sign
`"TRAX:SESSION:CLOSE:V3\0" || CBOR(SessionCloseCommitment)`.
The commitment contains both pre-terminal digests, the final data tip and exact
global/session boundaries. The receiver recomputes them and verifies the pinned
initiator's signature. It mirrors that original terminal without countersigning.

The terminal record ID is
`H("TRAX:SESSION:TERMINAL:V3\0" || CBOR(SessionTerminal))`.
Its parent is the last data tip; its position is `last_counter+1`. Folding it
into the relationship digest makes that original signed artifact the accepted
tip. The read-only closed-session digest additionally becomes
`H("TRAX:HISTORY:TERMINAL:V3\0" || preclose_session_hash || CBOR(terminal))`.
The signed preimages exclude their terminal to avoid self-reference.

The next session, initiated by either peer, must bind this terminal ID and
post-terminal relationship digest. Stale contexts, old signatures, wrong
direction, duplicate closures and unclosed-predecessor resets fail. An idle or
abandoned accepted session is not an authenticated closure; resumption/quarantine
remains host-controlled. No fork reconciliation is invented.

## Limits, framing and persistence

Defaults: 16,384 packets, 16 MiB transmission payload, 1,400 data bytes per packet,
4,096 complete encoded bytes per packet, and 30 seconds provisional lifetime.
Hard maxima: 1,048,576 packets, 256 MiB payload, 1 MiB encoded packet and 24 hours.
All limits are positive and per-packet payload must fit total and wire bounds.
The selected profile must be accepted exactly by both peers.

Packet builders measure the complete encoded record. Fragmentation sizes first,
middle and final packets separately; first-context and final-signature metadata
may require separate packets even for a small payload budget. For nonempty
payload, the final packet carries actual data. No arbitrary cadence padding or
mandatory extra seal packet is added. Logical packet limits are separate from
UDP/TCP framing and actual network headers, which belong to the host.

The durable journal magic is `TRAX:RELATIONSHIP:JOURNAL:V3\0`. Its initial
canonical header is `{genesis:[GenesisNode;3]}`. Later records are externally
tagged maps `{Packet:Packet}` or `{Terminal:SessionTerminal}`. Each frame is
`u64BE(length) || canonical_record || checksum32`, with
`checksum32 = SHA-512/256("TRAX:JOURNAL:FRAME:V3\0" || canonical_record)`.
The header cap is 65,536 bytes; record cap is negotiated wire bytes plus 128
bytes of enum framing allowance. Lengths are checked before allocation.

No provisional data is journaled. A verified complete transmission's packet
frames are written and synced once before admission/release. Replay reconstructs
the start from packet zero and rejects an unfinished transaction at EOF. Exact
external pin comparison precedes returning the restored handle. Live network
deadlines are omitted only during private historical replay; all cryptographic
and resource checks remain. Failure poisons the writer without memory admission.

See SECURITY.md for external freshness/effect atomicity, unsupported rotation,
network/encryption boundaries and threat limitations. `vectors/relationship.cbor`
and `tests/verify_transcript.cjs` independently fix this complete format, including
two linked sessions and the original signed closures.
