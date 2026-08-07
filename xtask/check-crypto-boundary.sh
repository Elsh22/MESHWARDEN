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
# ADR-016: no C-backed crypto (aws-lc*, ring) reachable from mw-transport,
# in the full graph (dev deps included) and in the shipping graph.
if cargo tree --locked -p mw-transport | grep -Eqi 'aws-lc|ring'; then
  echo "FAIL: C-backed crypto reachable from mw-transport (ADR-016)"; viol=1
fi
if cargo tree --locked -p mw-transport -e normal | grep -Eqi 'aws-lc|ring'; then
  echo "FAIL: C-backed crypto in mw-transport shipping graph (ADR-016)"; viol=1
fi
# Slice-1 boundary: mw-transport must not declare mw-crypto or mw-identity
# in any dependency section. (mw-crypto is reachable transitively via
# mw-proto's AlgId — that edge is ADR-007-sanctioned and not checked here.)
if grep -Eq '^[[:space:]]*mw-(crypto|identity)\b' crates/mw-transport/Cargo.toml; then
  echo "FAIL: mw-transport declares mw-crypto/mw-identity"; viol=1
fi

[[ $viol -eq 0 ]] && echo "crypto-boundary: OK"
exit $viol
