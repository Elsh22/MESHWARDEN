#!/usr/bin/env bash
# The single build gate. Every commit must pass this. Crate-local test runs
# never count. Set MW_SKIP_MUSL=1 only if the musl target is unavailable locally.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

step() { printf '\n== %s ==\n' "$1"; }

step "fmt"
cargo fmt --all -- --check

step "build (all targets)"
cargo build --workspace --all-targets --locked

step "test (workspace)"
log=$(mktemp)
if ! cargo test --workspace --locked --no-fail-fast >"$log" 2>&1; then
  grep -E '^(error|---- |failures:|test result)' "$log" | tail -n 60
  echo "FAIL: workspace tests"
  exit 1
fi
grep -E '^test result' "$log" | awk '{p+=$4; f+=$6} END {printf "tests: %d passed, %d failed across %d binaries\n", p, f, NR}'

if [ "${MW_SKIP_MUSL:-0}" != 1 ]; then
  step "static musl build"
  cargo build --workspace --locked --target x86_64-unknown-linux-musl
fi

step "crypto boundary"
bash xtask/check-crypto-boundary.sh

if [ -f xtask/check-no-fixed-crypto-arrays.sh ]; then
  step "no fixed-size crypto arrays"
  bash xtask/check-no-fixed-crypto-arrays.sh
  bash xtask/check-no-fixed-crypto-arrays.sh --self-test
fi

if [ -d crates/mw-session ]; then
  step "mw-session structure (ADR-017)"
  if cargo tree --locked -p mw-session | grep -Eiw 'aws-lc-rs|aws-lc-sys|ring'; then
    echo "FAIL: C-backed crypto reachable from mw-session"; exit 1
  fi
  if cargo tree --locked -p mw-session --depth 1 | grep -w 'mw-trust'; then
    echo "FAIL: mw-session depends on mw-trust"; exit 1
  fi
  if [ -f xtask/check-machine-purity.sh ]; then
    bash xtask/check-machine-purity.sh
    bash xtask/check-machine-purity.sh --self-test
  fi
fi

if command -v cargo-deny >/dev/null 2>&1; then
  step "cargo deny"
  cargo deny check
fi

printf '\nGATE: PASS\n'
