#!/usr/bin/env bash
set -euo pipefail

# MODE options:
# - handshake_client
# - handshake_server
# - mint_vectors
# - aaip_scenario
# - bench (criterion)
# - shell

echo "TRAX container starting with MODE=${MODE}"

case "${MODE}" in
  handshake_client)
    exec /usr/local/bin/handshake_client
    ;;
  handshake_server)
    exec /usr/local/bin/handshake_server
    ;;
  mint_vectors)
    mkdir -p /out
    exec /usr/local/bin/mint_vectors
    ;;
  aaip_scenario)
    exec /usr/local/bin/aaip_scenario
    ;;
  bench)
    # Run the bench binary if it exists; otherwise print hint.
    if [ -x /usr/local/bin/dag_benches ]; then
      exec /usr/local/bin/dag_benches
    else
      echo "Bench binary not present. Rebuild with benches enabled."
      exit 1
    fi
    ;;
  shell)
    exec bash
    ;;
  *)
    echo "Unknown MODE=${MODE}"
    exit 2
    ;;
esac
