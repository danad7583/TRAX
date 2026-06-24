# TRAX RUNBOOK

This runbook provides operational steps for building, testing, benchmarking, and preparing the TRAX repository for public GitHub publication.

TRAX stands for **Trust Resolution and Agent eXchange**.

## 1. Purpose

This runbook is intended for maintainers preparing or validating a TRAX local development environment.

It covers:

* Environment checks
* Windows and Linux dependency notes
* Build validation
* Test validation
* Benchmark validation
* Terminology checks
* Git hygiene before pushing to a remote repository

## 2. Environment Layout

Expected project root:

```text
TRAX/
├── Cargo.toml
├── README.md
├── RUNBOOK.md
├── src/
├── tests/
├── benches/
├── examples/
├── docker/
├── vectors/
└── docs/
```

The Rust package name should be:

```toml
name = "trax"
```

## 3. Dependency Checks

### Rust

Check Rust and Cargo:

```bash
cargo --version
rustc --version
```

### Windows

On Windows, confirm the MSVC linker is available:

```powershell
where.exe link
```

If `link.exe` is not found, install Visual Studio Build Tools with the C++ workload, then restart the terminal or VS Code.

To inspect Visual Studio Build Tools from PowerShell:

```powershell
& "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe" -products * -requires Microsoft.VisualStudio.Workload.VCTools -property installationPath
```

If this prints nothing, the C++ workload is not installed.

### Linux

On Linux, confirm native build tools are available:

```bash
cc --version
make --version
```

Install the equivalent of build essentials for the target distribution if these are missing.

## 4. Clean Build

From the project root:

```bash
cargo build --release
```

Expected result:

```text
Finished `release` profile [optimized]
```

If the build fails on Windows with:

```text
error: linker `link.exe` not found
```

the Windows C++ toolchain is missing or not loaded into the terminal environment.

## 5. Test Run

Run:

```bash
cargo test
```

Expected successful test output includes:

```text
running 3 tests
test req_4_1_2_session_id_binding ... ok
test req_5_1_1_segment_proof_validates ... ok
test req_3_1_1_deterministic_cbor ... ok

test result: ok. 3 passed; 0 failed
```

Some targets may show:

```text
running 0 tests
```

This is normal for compile-only targets or placeholder test modules.

## 6. Benchmark Run

Run:

```bash
cargo bench --bench dag_benches
```

The benchmark validates:

* K-window segment proof verification
* Individual Ed25519 signing
* K=8 Merkle batch signing

Current known-good benchmark snapshot from a Windows MSVC build:

```text
verify_last_8_nodes                  ~1.55 µs
verify_last_16_nodes                 ~3.15 µs
verify_last_32_nodes                 ~6.15 µs
verify_last_64_nodes                 ~12.29 µs
verify_last_128_nodes                ~24.69 µs
verify_last_256_nodes                ~49.33 µs

sign_8_nodes_individual_ed25519      ~183.9 µs
sign_16_nodes_individual_ed25519     ~368.0 µs
sign_32_nodes_individual_ed25519     ~748.9 µs
sign_64_nodes_individual_ed25519     ~1.48 ms
sign_128_nodes_individual_ed25519    ~2.96 ms
sign_256_nodes_individual_ed25519    ~5.90 ms

sign_batch_k8_merkle_root_ed25519    ~26.8 µs
```

Expected interpretation:

```text
K=8 verification path:       ~1.55 µs per 8-node segment
K=8 batch signing path:      ~26.8 µs per 8-node signed batch
8 individual signatures:     ~183.9 µs
```

K=8 Merkle batch signing reduces signing cost by approximately **6.8x** compared to signing all 8 nodes individually.

If this appears:

```text
Gnuplot not found, using plotters backend
```

it is not a failure. Criterion is using its fallback plotting backend.

## 7. Optional Clean Rebuild

Use only when a full rebuild is desired:

```bash
cargo clean
cargo build --release
cargo test
cargo bench --bench dag_benches
```

`cargo clean` removes local build output under `target/`. It does not alter source files.

## 8. Terminology Validation

The project was rebranded from AAICP Core to TRAX.

Before publishing, check for stale terminology:

### PowerShell

```powershell
Get-ChildItem -Recurse -File | Select-String -Pattern "AAICP|aaicp|Aaicp"
```

### Bash

```bash
grep -RInE "AAICP|aaicp|Aaicp" .
```

Expected result:

```text
No stale AAICP naming in public-facing TRAX files.
```

AAIP references may remain if they intentionally refer to the lower signed-message / packet exchange layer.

Known intentional AAIP naming:

```text
examples/aaip_scenario.rs
MODE=aaip_scenario
aaip_scenario documentation
```

Do not rename these unless the scenario is changed to demonstrate full TRAX trust-resolution behavior rather than the lower signed-message exchange.

## 9. Git Ignore Validation

TRAX should ignore generated build and benchmark artifacts.

Recommended `.gitignore` entries:

```gitignore
/target/
/criterion/
/vectors/generated/
.env
.env.*
!.env.example
*.log
.DS_Store
Thumbs.db
.vscode/
!.vscode/settings.json
!.vscode/extensions.json
*.pdb
*.ilk
*.exe
*.dll
*.lib
*.exp
*.tmp
*.bak
*.swp
```

Check ignored files:

```bash
git status --ignored
```

If `target/` was accidentally staged before `.gitignore` was added, remove it from Git tracking without deleting local files:

```bash
git rm -r --cached target
```

Then recheck:

```bash
git status --ignored
```

## 10. Pre-Push Validation

Before pushing to GitHub, run:

```bash
cargo build --release
cargo test
cargo bench --bench dag_benches
git status --ignored
```

Optional terminology scan:

```bash
grep -RInE "AAICP|aaicp|Aaicp" .
```

On Windows PowerShell:

```powershell
Get-ChildItem -Recurse -File | Select-String -Pattern "AAICP|aaicp|Aaicp"
```

## 11. Commit Preparation

Review staged files:

```bash
git status
```

Stage updates:

```bash
git add .
```

If build artifacts appear staged, remove them from Git tracking:

```bash
git rm -r --cached target
git rm -r --cached criterion
```

Commit:

```bash
git commit -m "Prepare TRAX public repository release"
```

## 12. Remote Setup

If the remote has not been added yet:

```bash
git remote add origin https://github.com/YOUR_USERNAME/trax.git
```

If the remote URL is wrong:

```bash
git remote set-url origin https://github.com/YOUR_USERNAME/trax.git
```

Verify:

```bash
git remote -v
```

Push:

```bash
git push -u origin main
```

If GitHub reports:

```text
Repository not found.
```

verify that:

* The GitHub repository exists
* The username is correct
* The repository name is correct
* The authenticated GitHub account has access
* The remote URL is correct

## 13. Known Good State

A known-good local state from the Windows MSVC environment produced:

```text
cargo build --release  ✅ passed
cargo test             ✅ passed
cargo bench            ✅ passed
```

Validated conformance tests:

```text
req_3_1_1_deterministic_cbor      ✅ passed
req_4_1_2_session_id_binding      ✅ passed
req_5_1_1_segment_proof_validates ✅ passed
```

Validated K=8 performance:

```text
8-node segment verification       ~1.55 µs
K=8 Merkle batch signing          ~26.8 µs
8 individual Ed25519 signatures   ~183.9 µs
```

## 14. Release Notes Reminder

Before publishing publicly, confirm:

* License has been selected
* README is accurate
* RUNBOOK is accurate
* No secrets or local environment files are committed
* `target/` is ignored
* Generated vectors are intentionally included or ignored
* AAIP references are intentional
* TRAX terminology is consistent
