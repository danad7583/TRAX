# Continuous mirrored relationship history

`Relationship` is the sole in-memory authority. It is non-cloneable and cannot
be restored from an arbitrary caller-supplied tip. Construction requires a
`VerifiedGenesis`, which verifies all three original signatures and explicit
identity acceptance before producing its private token.

## Root and record model

The genesis record at position zero stores the complete agreed original
offer/accept/confirmation transcript. Its ID is the canonical shared genesis
anchor; local records preceding that transcript are outside this relationship.

Every accepted record has `id`, `parent`, `position` and typed `kind`:

| Kind | Original data retained | ID |
| --- | --- | --- |
| `Genesis` | All three signed genesis nodes | Shared transcript anchor |
| `SessionStart` | Predecessor-bound session context | Domain hash of context |
| `Packet` | Signature-free event and original optional final seal | Domain hash of event |
| `SessionTerminal` | Initiator's original signed closure | Domain hash of signed terminal |

Each non-root record points to the previous accepted record. `record_count`
is the highest accepted position, excluding the root; `history().len()` equals
`record_count + 1`. Packet counters are their global positions, not counters
reset at each session. Start and terminal records also occupy positions.

The final packet's ID excludes its seal to avoid a signature/root hash cycle.
The relationship history digest includes the entire record, including its
original seal/signature. Thus a closure attests both content and authenticating
artifacts. No second seal record or signature is added to mirror reception.

## Session ownership and continuity

The first proposed session binds the genesis anchor and genesis-record digest.
Its `SessionStart` is position one; its first data event is position two. A draft
does not advance trusted state. Its first completely verified request admits
the start and all transmission events in one atomic transaction.

When a session is closed, its original signed terminal becomes the relationship
tip and is retrievable by `record(checkpoint.tip)`. A subsequent session binds
that exact tip, the current full-history digest, record position and next session
ordinal. Either participant may initiate it. The first transmission's existing
final signature authenticates this context, without an extra session-start
signature. Replayed or stale predecessor contexts fail.

An accepted but unclosed session blocks a new one. Missing final data can be
aborted or timed out provisionally; this never discards accepted history. An
unadmitted local session intent may be removed with `abort_draft_session`.
Accepted sessions cannot be reset, automatically forked or replaced through it.
An abandoned accepted session requires resumption or host quarantine; TRAX does
not invent an authenticated closure or an alternative authoritative branch.

## Traversal and mirroring

`history()` returns the complete accepted sequence. `record(id)` resolves the
root, starts, ordinary packet events and all signed terminals uniformly.
`ancestors(id)` returns nearest-parent-first ancestors, excluding the chosen
record. `children(id)` retrieves accepted successors. Records are exposed by
shared reference; editing a local serialized or cloned copy cannot modify
authority.

Both mirrors retain the same original event/seal/terminal artifacts, so they
derive identical IDs, parent links, positions and relationship digests. There
is one authoritative insertion order. Parallel writes, out-of-sync recovery,
arbitrary branching and branch merging are not supported in this profile.

`Session` exposes read-only context, checkpoint, expected direction, provisional
status and original terminal. It has no public constructor granting a separate
authority. Full older-session inspection uses the relationship's complete
record sequence, not an independently reset session object.

## Persistence

`DurableRelationship` owns the same authority behind one exclusive journal lock.
It verifies a complete transmission, writes its bounded packet frames, syncs,
then atomically admits the corresponding records and releases payload. Starts
are reconstructed from the first packet, and committed only with its complete
authenticated request. Closure follows the same verify/write/sync/apply order.

Reopening requires trusted genesis and an exact current external checkpoint;
all transactions are reverified. Truncated/corrupt tails and unfinished
transactions fail closed. Authenticated snapshots, partial-tail repair and
disk-backed lazy indexes are not implemented. Accepted metadata remains
memory-resident and grows with relationship history.
