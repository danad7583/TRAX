# Shared DAG contract and API

TRAX parses, appends, traverses and cryptographically verifies immutable DAG
history. The application owns key exchange, transport, message ordering, session
lifetimes, models and responses. AAICP and TRAX-Transport-Lab are unchanged.

## Genesis and negotiated profile

`ProtocolConfig::new(k, signing_algorithm, hash_algorithm)` selects the shared
profile. K must be **greater than 4**, so the minimum is 5. Applications can use
`ProtocolConfig::with_default_k(signing_algorithm, hash_algorithm)` for K=8.
Signing/hash algorithms remain explicit, and serialized genesis always includes K;
a missing field does not silently default during verification.

Ed25519 is the supported signature algorithm. Runtime hashing supports
SHA-512/256 and, when compiled with `hash-blake3`, BLAKE3. Unsupported selections
are rejected rather than replaced. Both peers must support all historical
algorithms needed to verify their relationship.

`PairGenesis::new(config, nonce, first_public_key, second_public_key)` includes
the agreed profile and sorted initial keys. Both ends derive the same genesis
regardless of argument order. `PairDag::from_verified_genesis(config, genesis)`
requires the complete expected profile. The host must authenticate the keys and
their negotiation; this constructor does not implement network negotiation.

Each initial public key is a stable participant ID across later key/hash changes.
The relationship ID includes its nonce and profile, not an IP address.

## Ordinary shared cadence

`begin_segment()` creates a small provisional overlay. Ordinary `append` and
`fork` events from both participants and all branches count toward the shared K.
The `counter` is insertion order; `sequence` is structural depth. Different
branches can contribute to a checkpoint without structurally merging.

An ordinary K-event segment may be sealed by either authorized participant.
`seal(participant, key)` signs its ordered, context-bound Merkle commitment.
`verify_and_commit` reconstructs the candidates, checks current authority,
ordering, configuration and signature, and atomically admits the entire batch.
Unsigned events remain available through `PendingSegment::events()` while the
session continues, but are separate from trusted `PairDag::node()` records.

No normal request or response automatically adds padding. A rejected or partial
proof advances no trusted node, tip, authority or configuration. One checkpoint
attests its signer's history; ordinary author metadata is not an independent
per-message signature. Host transport authentication remains a separate concern.

## Rotation and bilateral acknowledgment

Rotations start a fresh segment and a new branch. For K=8:

| Position | Participant | Record and evidence |
| --- | --- | --- |
| 1 | A | Rotation proposal: new public key, old-key authorization, new-key possession proof |
| 2–6 | B | Explicit `Padding` filler, or peer records |
| 7 | B | `Acknowledge` plus a detached signature over the exact seven-event prefix |
| 8 | A | `CloseConfirm` or a real request, with a full checkpoint signed by A's new key |

`rotate(author, parent, new_branch, old_key, new_key)` constructs both proofs.
The old currently authorized key establishes continuity with A's existing
identity; the new-key signature proves possession of the replacement private
key. A self-signed new public key alone cannot authorize a takeover. Both proofs
bind the same relationship, branch, parent, profile, counters and prior authority,
using distinct signing domains. Ed25519 verifies signatures; it does not decrypt
the node. The private keys are never transmitted.

After receiving and staging the proposal, B calls
`acknowledge_and_pad(b_id, b_key)`. This reserves the final slot for A, fills
positions through K−2, adds B's acknowledgment at K−1 and returns a
`PrefixAcknowledgment`. The helper validates its multi-record operation before
replacing the original overlay. A stages B's returned events and calls
`accept_ack(&proof)`.

The prefix proof binds the exact proposal, branch, relationship, profile,
previous checkpoint, segment index, counter range, ordered root, ACK event and
expected final slot. It is a distinct control proof, **not a K-event checkpoint**,
and never admits partial history. Its signature stays outside its ACK node hash
to avoid a recursive signature definition.

A then chooses:

- `finish_close()` adds a `CloseConfirm` in the final slot.
- `append(a_id, branch, request)` adds a real request there instead and continues.

Both choices require A's final checkpoint signature. For rotation, only A's
new key can seal that exchange; neither B nor A's old key can substitute. The
checkpoint binds B's exact acknowledgment proof. The `session_closing` flag is
derived from `CloseConfirm`, not supplied as an unchecked caller declaration.

After verification, the full K-node segment is mirrored and A's new authority
becomes committed. B's key is unchanged. Later extensions cannot use retired
keys on any branch. `identify_key` recognizes historical keys rather than
treating them as fresh participants. Historical signatures remain verifiable.

This proves bilateral agreement to a protocol close. It cannot prevent a peer
from disconnecting or guarantee that a remote process has durably saved data.

## Ordinary session close

`request_close(initiator, branch)` opens the same acknowledgment flow without
rotating a key. It needs three available slots: proposal, peer ACK and initiator
decision. If insufficient slots remain, complete the ordinary segment first.
There is no implicit flush, extra full padding segment or one-sided close helper.

`Padding`, `Acknowledge` and `CloseConfirm` are distinct from ordinary requests.
Filler is permitted only in an open exchange and cannot itself force closure.
A may send the final real request even after B supplied filler. Network packet
counts need not equal DAG node counts; proof metadata is not another DAG node.

## K and algorithm changes

`configure(author, parent, new_branch, new_config, current_key)` proposes a new
shared profile on a fresh branch. The old current key authorizes the change, but
the **transition itself uses the proposed new K and algorithms**, starting with
the proposal node. The old configuration-history reference remains bound into
that proposal until the exchange is accepted.

For 8 → 5, the proposal is node 1 under the new profile, B acknowledges the
four-node prefix, and A signs node 5. The committed graph adopts the new profile
only when both proofs and the complete five-node segment verify. Rejecting the
proposal or either proof leaves the previous profile unchanged.

The profile governs subsequent live events, including continuations on older
branches. Historical records retain their original profile. The host negotiates
settings with its peer; TRAX does not choose preferences or send negotiation packets.

## Traversal and proof lookup

Nodes have exactly one known structural parent. Branch creation never rewrites
or merges existing records. `parent`, `children`, `ancestors`, `branch_origin`,
`branch_tip` and `branches` expose immutable history. Global authority/configuration
references are continuity checks, not structural merges.

`checkpoint_for(participant, event_id)` returns a known full checkpoint
attestation. `acknowledgment_for(proposal_id)` returns the peer's signed prefix
agreement. Both are retained for later proof requests. `record_attestation`
verifies another permitted signature over existing history without adding nodes
or restoring retired keys' authority. `verify_history` replays the full evidence.
Signatures alone do not establish a wall-clock time of signing.

## Durable history

`DurableDag::create_new(path, initial_config, genesis)` creates a new append-only
journal without overwriting. `open(path, initial_config, expected_genesis_id)`
requires the original external anchor and re-verifies all segments, embedded
prefix proofs and extra attestations. Replayed configuration/rotation events
restore current state through their authenticated transitions.

Journal v3 uses canonical CBOR, framed lengths, fixed SHA-512/256 checksums and
an exclusive OS writer lock. A commit validates first, synchronizes the frame,
then advances trusted memory. A write/sync error leaves memory unchanged and
poisons that writer. Partial/corrupt records are errors; no silent repair drops
history. Provisional unsigned data is not part of the trusted journal.

A valid older complete prefix is not recognizable as rollback from a genesis
anchor alone; that needs an externally pinned latest checkpoint. The host owns
backups and directory durability. Current history/indexes are memory resident;
normal staging and verification do not clone the complete historical graph.

## Example and legacy helpers

Run `cargo run --example shared_dag` for the two-mirror K=8 rotation/ACK/final
exchange. Both private-key holders are simulated locally in this example only.

The separate legacy same-author window APIs use positive `SegmentConfig`
values, including K=1. They do not define the shared graph's K≥5 or close policy.
Python exposes those older primitives; the shared graph/exchange API is Rust.

Version 0.2 is a breaking prototype API/encoding change with no automatic history
migration. The new exchange also changes proof encoding and uses journal v3.
