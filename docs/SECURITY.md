# Security contract

## Authentication and authorization

Three genesis signatures prove possession of two distinct Ed25519 keys and bind
the exact negotiated cryptographic/resource profile. Explicit caller trust
callbacks authorize those identities. A valid self-signed unknown key is not
implicitly trusted. Genesis construction and verification reject weak keys,
altered parameters, wrong signers and malformed links.

Keys remain pinned for the relationship. Packets cannot advertise replacement
authority. In-session rotation is unsupported. A newly presented relationship
must pass the deployment's current acceptance and retired-key policy; possession
alone cannot establish that an obsolete identity remains authorized.

An authenticated request is still subject to AAICP's application authorization.
TRAX does not decide whether to invoke a tool, accept a task or alert peers.

## Admission invariant

Receipt and structurally correct hash links are not authentication. Intermediate
packet payloads remain bounded provisional data. The receiver reconstructs the
complete ordered, count-bound Merkle root and every commitment field, verifies
the expected sender's final signature, then admits the complete transmission.
Failure releases no verified payload and commits zero events or session starts.

The final event excludes its entire authentication seal from its hash/Merkle
preimage. Actual payload hash and length are verified. Signed context binds
session, relationship, both participants, expected direction, key epoch, type,
ID, exact counters/counts/bytes, start and final tips. Another legitimate peer's
signature cannot substitute for the expected sender.

Strict CBOR decoding enforces byte caps, a 64-level nesting limit and exact
typed re-encoding. Unknown fields, discarded tags, duplicate keys, trailing data,
nonminimal integers and noncanonical ordering are rejected. Integer arithmetic
and bounded allocations are checked before authoritative mutation.

## Continuity, replay and closure

A non-cloneable `Relationship` owns strict counters, consecutive transmission
IDs and session ordinals. New sessions bind the exact latest accepted predecessor
and full relationship digest. An unclosed session cannot silently reset or fork.
First-context admission is atomic with the first authenticated request.

Only the session initiator can sign a normal terminal. Its commitment excludes
the terminal itself and includes both the independently reconstructed session
history and continuous relationship digest and exact boundaries. The peer
mirrors that original signed artifact without countersigning. Old-session,
duplicate, wrong-signer and inconsistent-history closures fail.

Memory-only state cannot establish freshness after owner rollback, process
duplication or repeated genesis/nonce reuse. The host must maintain identity,
nonce and authoritative-journal ownership. No standalone replay helper or
arbitrary-tip restoration substitutes for this state model.

## Persistence responsibilities

The durable wrapper holds one OS file lock, verifies before writing and calls
`sync_all` before state admission or payload release. I/O failure poisons the
writer; its trusted checkpoint remains unchanged. Complete, valid bytes might
have reached disk despite an error, so reopening/recovery must reconcile state
with an authenticated fresh external latest-state pin. Partial transactions
fail closed; no silent repair is performed.

Checksums detect corruption, not identity. An old valid prefix does not satisfy
a current external pin. A rolled-back pin or independently copied journal
cannot establish deployment-wide freshness. Locks coordinate the same file;
the host routes each relationship to one authority. External pin updates,
filesystem/directory durability, backups and atomic application side effects
remain host responsibilities. Do not claim global exactly-once effects.

## Resources and explicit limits

Negotiated bounds cap packet count, payload per packet, total transmission
payload, complete encoded packet bytes and provisional elapsed lifetime. The
host schedules `expire_receive` while idle; incoming staging also checks expiry.
Aborting/dropping staging discards provisional buffers. Historical replay keeps
all authentication/resource checks without applying live network deadlines.

Payload storage is bounded per transmission, not constant-space spooled to disk.
Accepted metadata/indexes grow with history. Selected wire budgets can require
different first/middle/final data capacities. No payload or signature may be
appended past the configured complete packet cap.

The protocol does not provide encryption, transparent-relay detection,
denial-of-service immunity, stolen-private-key protection, distributed fork
reconciliation, transport delivery evidence or model safety policy. An unchanged
relay remains cryptographically valid. Closure does not prove the other peer
durably received it.
