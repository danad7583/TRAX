# LLM / AI Consumption Guide for TRAX

This document provides copy/paste prompts for developers, reviewers, researchers, and security engineers who want to use an LLM to understand the TRAX repository quickly.

TRAX stands for **Trust Resolution and Agent eXchange**.

TRAX is a Rust-based cryptographic trust layer for verifiable agent-to-agent communication. It resolves trust from signed history, DAG continuity, replay protection, key continuity, and challenge-response behavior rather than from identity alone.

Use these prompts with your preferred LLM by pasting the prompt and attaching or referencing the relevant repository files.

---

## 1. Fast Project Summary

```text
You are reviewing a Rust repository named TRAX.

TRAX stands for Trust Resolution and Agent eXchange. It is a cryptographic trust layer for verifiable agent-to-agent communication. It uses signed DAG-based history, canonical CBOR encoding, COSE-oriented message structure, replay protection, key rotation continuity, session binding, challenge-response validation, and K-window segment proofs.

Please summarize what this repository does in plain English for a developer who has not read the code. Explain what problem TRAX solves, what it does not solve, and how it differs from a normal message-signing library.
```

---

## 2. Architecture Explanation

```text
Review this TRAX repository as a protocol architecture.

Explain the major components and how they relate to each other:

- canonical encoding
- crypto operations
- session binding
- DAG nodes
- segment proofs
- replay protection
- key rotation / quarantine
- rate limiting
- AAIP signed-message scenario
- TRAX trust-resolution layer

Focus on the difference between identity, message authenticity, and trust resolution.
```

---

## 3. AAIP vs TRAX Boundary

```text
This repository contains references to both AAIP and TRAX.

Please explain the intended architectural boundary:

- AAIP refers to the lower signed-message or packet exchange layer.
- TRAX refers to the trust-resolution layer built around DAG history, cryptographic continuity, replay protection, key rotation, and segment proofs.

Identify whether any AAIP references appear intentional or whether they look like stale naming that should be renamed to TRAX.
```

---

## 4. Security Model Review

```text
Review the TRAX repository from a security engineering perspective.

Identify the security assumptions, trust boundaries, and likely threat model. Focus on:

- replay prevention
- nonce or counter handling
- DAG continuity
- signed history
- key rotation continuity
- challenge-response validation
- quarantine behavior
- rate limiting
- separation of identity from trust

Then identify what this repository does not currently prove or protect against.
```

---

## 5. Cryptography Review

```text
Review the cryptographic usage in this TRAX repository.

Focus on:

- Ed25519 signing
- K=8 Merkle batch signing
- hash usage
- HKDF usage
- SHA-2 / SHA-512 dependency usage
- BLAKE3 usage
- COSE Sign1-oriented message structure
- deterministic encoding assumptions

Call out any places where the implementation appears to be scaffolding, demo code, or not yet production-hardened cryptographic behavior.
```

---

## 6. Benchmark Interpretation

```text
TRAX currently has benchmark results approximately as follows:

- verify_last_8_nodes: ~1.55 microseconds
- verify_last_16_nodes: ~3.15 microseconds
- verify_last_32_nodes: ~6.15 microseconds
- verify_last_64_nodes: ~12.29 microseconds
- verify_last_128_nodes: ~24.69 microseconds
- verify_last_256_nodes: ~49.33 microseconds
- sign_8_nodes_individual_ed25519: ~183.9 microseconds
- sign_batch_k8_merkle_root_ed25519: ~26.8 microseconds

Explain what these benchmarks mean. Compare verification cost, individual signing cost, and K=8 Merkle batch signing cost. Explain why nanosecond-range performance is realistic for hashing and memory operations but not for public-key signing.
```

---

## 7. Firmware / Runtime Security Comparison

```text
Compare TRAX performance and architecture to common firmware security patterns.

TRAX performs K=8 Merkle batch signing in about 26.8 microseconds per 8-node batch and verifies an 8-node segment proof in about 1.55 microseconds.

Compare this approach to:

- secure boot
- measured boot
- TPM PCR extension chains
- firmware image verification
- runtime attestation
- per-message signing

Explain why TRAX is better understood as runtime trust validation rather than classic boot-time firmware verification.
```

---

## 8. Codebase Tour

```text
Give me a codebase tour of this TRAX repository.

Explain the purpose of each major folder and file:

- src/
- tests/
- benches/
- examples/
- docker/
- vectors/
- docs/
- Cargo.toml
- README.md
- RUNBOOK.md

Then suggest where a new developer should start reading first.
```

---

## 9. Conformance Test Review

```text
Review the TRAX conformance tests.

The known passing tests are:

- req_3_1_1_deterministic_cbor
- req_4_1_2_session_id_binding
- req_5_1_1_segment_proof_validates

Explain what each test likely validates and what additional conformance tests should be added next for a stronger protocol validation suite.
```

---

## 10. Signing Test Recommendation

```text
TRAX has verification and segment proof tests. Recommend additional signing tests.

Please propose Rust test cases for:

- Ed25519 sign/verify round trip
- tampered message rejection
- wrong public key rejection
- malformed signature rejection
- K=8 batch signing validation
- deterministic test vector generation

Keep the tests compatible with a Rust Cargo project using ed25519-dalek.
```

---

## 11. Public GitHub Readiness Review

```text
Review this TRAX repository for public GitHub readiness.

Check for:

- stale AAICP terminology
- intentional AAIP terminology
- build artifacts that should be ignored
- missing license
- README clarity
- RUNBOOK usefulness
- benchmark claim safety
- security disclaimer quality
- dependency documentation
- Windows and Linux build prerequisites

Provide a prioritized list of fixes before public release.
```

---

## 12. README Quality Review

```text
Review the README.md for TRAX.

Determine whether a new developer can quickly answer:

- What is TRAX?
- What problem does it solve?
- How do I build it?
- How do I test it?
- How do I benchmark it?
- What do the benchmarks mean?
- What dependencies are required on Windows and Linux?
- What parts are experimental?
- What does AAIP mean inside this repo?

Suggest concise edits only.
```

---

## 13. RUNBOOK Review

```text
Review RUNBOOK.md for TRAX.

Determine whether it gives a maintainer enough information to:

- validate local dependencies
- build the project
- run tests
- run benchmarks
- check terminology
- confirm .gitignore behavior
- prepare a commit
- push to a remote repository

Suggest missing operational checks or unnecessary sections.
```

---

## 14. Threat Modeling Prompt

```text
Perform a threat model for TRAX.

Assume TRAX is used for autonomous agent-to-agent communication where agents exchange signed messages and maintain DAG-based trust history.

Analyze threats including:

- replay attacks
- message forgery
- key compromise
- malicious key rotation
- DAG fork or injection
- stale node reuse
- denial of service
- rate-limit bypass
- malformed CBOR/COSE inputs
- compromised peer identity
- trusted history poisoning

For each threat, describe the mitigation present in TRAX if visible, and identify any missing controls.
```

---

## 15. Performance Claim Safety

```text
Review these proposed TRAX performance claims for accuracy and safety:

- TRAX verifies an 8-node segment proof in approximately 1.55 microseconds.
- TRAX performs K=8 Merkle batch signing in approximately 26.8 microseconds per 8-node batch.
- K=8 Merkle batch signing is approximately 6.8x faster than signing 8 nodes individually.
- TRAX reaches approximately 298,000 signed node-equivalents per second in the measured K=8 batch-signing path.

Explain which claims are safe, which need qualifiers, and what environment details should be included.
```

---

## 16. Contributor Onboarding

```text
I am a new contributor to TRAX.

Explain how to get productive quickly:

- what TRAX does
- what to read first
- how to build
- how to test
- how to benchmark
- how to avoid confusing AAIP and TRAX terminology
- what areas likely need more work
- what kind of pull requests would be useful
```

---

## 17. Documentation Consistency Check

```text
Scan the TRAX documentation for consistency.

Check whether the following terms are used correctly:

- TRAX
- Trust Resolution and Agent eXchange
- AAIP
- DAG
- segment proof
- K-window
- K=8 Merkle batch signing
- Ed25519
- canonical CBOR
- COSE Sign1
- replay protection
- session binding
- key rotation
- quarantine

Flag inconsistent, stale, or ambiguous terminology.
```

---

## 18. Minimal Executive Summary

```text
Write a short executive summary of TRAX for a technical decision-maker.

Keep it under 200 words.

Include:

- what TRAX is
- why signed history matters
- why identity alone is not trust
- what the K=8 batch-signing benchmark shows
- why this is relevant to autonomous agent communication
```

---

## 19. Deep Technical Summary

```text
Write a deep technical summary of TRAX for a security architect.

Cover:

- protocol objective
- identity vs trust
- signed message exchange
- DAG-based trust chain
- segment proof verification
- replay protection
- session binding
- key rotation continuity
- K=8 Merkle batch signing
- benchmark interpretation
- current limitations
- future hardening work
```

---

## 20. Pull Request Review Prompt

```text
You are reviewing a pull request for the TRAX repository.

Review the changes for:

- protocol correctness
- cryptographic safety
- deterministic encoding behavior
- replay protection impact
- DAG integrity impact
- test coverage
- benchmark impact
- terminology consistency
- README/RUNBOOK updates
- public API stability

Return a structured PR review with blockers, warnings, suggestions, and approved items.
```

---

## Recommended First Prompt

For most developers, start with this:

```text
You are reviewing a Rust repository named TRAX.

TRAX stands for Trust Resolution and Agent eXchange. It is a cryptographic trust layer for verifiable agent-to-agent communication. It resolves trust from signed DAG history, replay protection, key continuity, session binding, challenge-response behavior, and K-window segment proofs.

Please explain what this project does, how AAIP and TRAX differ, how the main source files likely fit together, and what I should read first as a developer.
```

---

## Notes for LLM Use

LLM output should be treated as review assistance, not as authoritative protocol validation.

For security-sensitive changes, use LLM output only as a supplement to:

* code review
* cryptographic review
* test validation
* benchmark validation
* threat modeling
* independent implementation review

TRAX is experimental research and development software. It should not be treated as production-ready cryptographic infrastructure without independent review and formal validation.
