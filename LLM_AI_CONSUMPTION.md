# TRAX implementation guide

Use current code, executable assertions, README and the exact protocol document
as evidence. TRAX has one canonical authentication path, not interchangeable
window/graph protocols. Do not restore removed compatibility APIs for historical
examples or the retired transport lab.

## Responsibilities

- `config`: explicit signing/hash selection, schema constants and bounded limits.
- `crypto`: strict Ed25519 and agreed-profile domain hashing.
- `merkle`: variable-length count/index/length-bound root computation.
- `encoding`: deterministic CBOR and bounded exact typed decoding.
- `genesis`: three signed records, chain verification and explicit trust callbacks.
- `session`: non-cloneable relationship authority, read-only session state,
  atomic staging/admission, continuous typed history and initiator closure.
- `transmission`: untrusted wire records and private-constructor verified token.
- `storage`: one locked relationship journal, sync-before-release and exact-pin replay.
- `python`: thin memory-only access to the same Rust authority.

AAICP owns transport, orchestration, models/tools, application authorization and
responses to verification failures. Never add HTTP ports, sockets, agent policy,
or automatic alerting to TRAX's core.

## Invariants to preserve

Every request/response may contain any supported positive packet count. Its
final actual data packet alone carries its sender signature. The entire
authentication seal is excluded from event/Merkle preimages. Actual payload
bytes are checked; structural continuity alone never releases trusted data.
Failure commits neither provisional packet events nor their session start.

A relationship begins at the verified shared genesis anchor. Session contexts
bind the current tip, relationship digest, position and next ordinal. Starts
become accepted only with their first complete verified request. An accepted
unclosed session cannot be reset/forked. A signed closure is a fully indexed
history record; the next session continues from it, with either peer initiating.
The receiver mirrors original seals and terminal signatures, never countersigns
a normal closure.

Wire schema identifiers and domain strings are security data, not temporary
component names. Genesis schema 2 and Merkle domains remain unchanged; session
schema 3 deliberately introduces predecessor continuity. Public Rust/Python
symbols use permanent names. Run `scripts/check_public_api.py` after API edits.
See [PROTOCOL](docs/PROTOCOL.md) before changing authenticated bytes, and
regenerate/review/independently verify a complete transcript for any cutover.

## Validation and limits

Run the supported commands in [RUNBOOK](docs/RUNBOOK.md), including Python,
independent Node verification, all supported Cargo feature combinations and
benchmark smoke tests. Report actual commands/results; new CI configuration
does not prove its remote execution. The baseline `318a214` CI did succeed;
that is evidence for the baseline, not for later edits.

In-session key rotation, arbitrary branching/merge, encryption, out-of-sync
reconciliation, authenticated snapshots and automatic corrupt-tail recovery are
unsupported. Explicit host trust policy must reject retired identities. External
pin freshness, one authoritative journal, nonce handling and application-effect
atomicity remain deployment responsibilities. No unchanged transparent-relay,
stolen-key or denial-of-service detection is claimed.

Consult [SECURITY](docs/SECURITY.md), [DAG](docs/DAG.md),
[MIGRATION](docs/MIGRATION.md) and [PERFORMANCE](docs/PERFORMANCE.md) for the
precise implementation boundaries; historical test counts and benchmark labels
must not substitute for current evidence.
