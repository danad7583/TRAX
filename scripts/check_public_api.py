"""Check declarations/artifact names, excluding authenticated wire identifiers."""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
TEMPORARY = re.compile(r"V\d+(?=$|[A-Z_])|(?:^|_)(?:v\d+|k\d+|alpha|beta|prototype|legacy)(?:_|$)")
DECLARATION = re.compile(
    r"^\s*(?:pub(?:\([^)]*\))?\s+)?(?:struct|enum|trait|type|fn|mod)\s+(\w+)", re.MULTILINE
)
RETIRED = {
    "LocalDag", "LocalAdmissionDag", "TrustedSessionContext", "ReceiveAdmissionWindow",
    "SegmentConfig", "ProtocolConfig", "DEFAULT_K", "DEFAULT_SEGMENT_K",
    "PairDag", "PairGenesis", "GraphSegmentProof", "PrefixAcknowledgment",
    "create_segment_seal", "verify_segment_seal_intrinsic", "verify_segment_seal_for_context",
    "derive_session_id", "hash32", "tx_genesis_offer", "tx_genesis_accept", "tx_genesis_confirm",
}
RETIRED_MODULES = {
    "admission", "admission_dag", "dag", "exchange", "graph", "profile", "rate", "replay",
    "rotation", "types", "python_transmission", "transmission_crypto", "transmission_storage",
}


def main():
    # Only names are checked. Signature/hash domain strings, numeric schema
    # fields and historical Git references must keep their wire-level meaning.
    failures = []
    for folder in ("src", "tests", "examples", "benches", "vectors", "docs"):
        for path in (ROOT / folder).rglob("*"):
            if not path.is_file() or "__pycache__" in path.parts or "generated" in path.parts:
                continue
            relative = path.relative_to(ROOT)
            if TEMPORARY.search(path.stem):
                failures.append(f"{relative}: temporary artifact name")
            if path.suffix != ".rs" or folder != "src":
                continue
            source = path.read_text(encoding="utf-8")
            for match in DECLARATION.finditer(source):
                name = match.group(1)
                if TEMPORARY.search(name) or name in RETIRED:
                    line = source.count("\n", 0, match.start()) + 1
                    failures.append(f"{relative}:{line}: retired/temporary declaration {name}")
            for number, line in enumerate(source.splitlines(), 1):
                if re.match(r"\s*pub\s+(?:use|mod)\b", line):
                    for name in re.findall(r"\b[A-Za-z_]\w*\b", line):
                        if TEMPORARY.search(name) or name in RETIRED:
                            failures.append(f"{relative}:{number}: retired/temporary export {name}")
    for name in RETIRED_MODULES:
        if (ROOT / "src" / f"{name}.rs").exists():
            failures.append(f"src/{name}.rs: retired module remains")
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    print("Canonical public API and artifact names passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
