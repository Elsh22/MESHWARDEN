#!/usr/bin/env bash
# ADR-007: only mw-crypto may declare primitive crypto crates as deps.
set -euo pipefail
prims='ed25519-dalek|x25519-dalek|sha2|ml-kem'
viol=0
for m in crates/*/Cargo.toml bin/*/Cargo.toml workloads/*/Cargo.toml; do
  case "$m" in
    crates/mw-crypto/Cargo.toml) continue ;;
    bin/mw-sim/Cargo.toml) grep -Eq '^[[:space:]]*ml-kem' "$m" && continue ;;
  esac
  if grep -Eq "^[[:space:]]*($prims)\b" "$m"; then
    echo "FAIL: $m declares a primitive crypto crate directly"; viol=1
  fi
done
[[ $viol -eq 0 ]] && echo "crypto-boundary: OK"
exit $viol
