#!/usr/bin/env bash
# ADR-017 Testing obligations (Structural): no clock read, socket, timer, or
# sleep anywhere in mw-session::machine, and no private key type reachable from
# AuthMachine (INV-4, INV-14; "Division of responsibility": no I/O, no clock
# reads, no timers, no entropy source).
# Fails if crates/mw-session/src/machine*.rs or any file under a
# crates/mw-session/src/machine*/ directory mentions a banned token, or if any
# mw-session source uses `#[path`. Every line is scanned, comments and strings
# included, so machine docs must describe the rules without naming the tokens.
# This is a text lint, checked line by line. It cannot see a banned type
# reached through an alias, macro, or include! defined outside machine, a
# grouped `use std::{...}` split across lines with a renamed module, or
# entropy hidden in HashMap's default hasher. The type-level proof of INV-14
# is separate.
# --self-test: plants one line per banned token plus word-boundary controls in
# machine sources, a `#[path` in lib.rs, and an impure out-of-scope driver.rs,
# and fails unless exactly the lines marked HIT are caught.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Banned tokens, POSIX ERE, matched as whole words.
banned=(
  # Clock and timers.
  'std::time' 'time::' 'SystemTime' 'Instant'
  'std::thread' 'thread::' 'sleep'
  # Async runtime, sockets, filesystem, other ambient I/O.
  'tokio' 'std::net' 'net::' 'std::fs' 'fs::'
  'std::io' 'io::' 'std::process' 'process::' 'std::env' 'env::'
  # Grouped import of any of the above, e.g. `use std::{fs, net};`.
  'std::\{[^}]*[^A-Za-z0-9_](time|thread|net|fs|io|process|env)'
  # Entropy.
  'rand(_[A-Za-z0-9_]+)?' 'OsRng' 'getrandom'
  # Private-key types. mw-crypto exports ed25519::Keypair (it wraps
  # ed25519_dalek::SigningKey) and the Signer trait, which only key holders
  # implement. mw-identity exports Keystore (it wraps Keypair). Glob imports
  # from either crate would bring these in unnamed, so they are banned too.
  'Keypair' 'SigningKey' 'Signer' 'Keystore'
  '(mw_crypto|mw_identity)(::[A-Za-z0-9_]+)*::\*'
)
# Word boundaries are spelled out so BSD, GNU, and ugrep agree. A token that
# ends in `::` needs no right boundary.
pattern=$(
  for t in "${banned[@]}"; do
    if [[ "$t" == *:: ]]; then
      printf '(^|[^A-Za-z0-9_])%s|' "$t"
    else
      printf '(^|[^A-Za-z0-9_])%s([^A-Za-z0-9_]|$)|' "$t"
    fi
  done
)
pattern=${pattern%|}

# Prints file:line:source for every banned mention in machine sources under
# $1 (machine*.rs, and every .rs file under a machine*/ directory), and for
# every `#[path` attribute anywhere under $1, since that could load machine
# code from an unscanned file.
# Exits 2 if $1 is missing or holds no machine sources, so a moved or renamed
# module can never pass as clean.
scan() {
  [[ -d "$1" ]] || { echo "FAIL: $1 is not a directory" >&2; return 2; }
  local files=() all=() f
  while IFS= read -r -d '' f; do files+=("$f"); done \
    < <(find "$1" -path "$1/machine*" -name '*.rs' -type f -print0)
  [[ ${#files[@]} -gt 0 ]] || { echo "FAIL: no machine sources under $1" >&2; return 2; }
  while IFS= read -r -d '' f; do all+=("$f"); done \
    < <(find "$1" -name '*.rs' -type f -print0)
  grep -nHE -- "$pattern" "${files[@]}" || [[ $? -eq 1 ]]
  grep -nHE -- '#[[:space:]]*!?[[:space:]]*\[[[:space:]]*path([^A-Za-z0-9_]|$)' "${all[@]}" \
    || [[ $? -eq 1 ]]
}

if [[ "${1:-}" == "--self-test" ]]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  mkdir -p "$tmp/src/machine"
  # One HIT line per banned token, each matched by that token alone.
  cat > "$tmp/src/machine.rs" <<'RS'
use std::time; // HIT
const Z: u8 = time::Duration::ZERO; // HIT
fn a(t: SystemTime) {} // HIT
fn b(i: Instant) {} // HIT
use std::thread; // HIT
fn c() { thread::yield_now() } // HIT
fn d() { sleep(x) } // HIT
/// Doc comments count: tokio. HIT
use std::net; // HIT
fn e() { net::TcpStream } // HIT
use std::fs; // HIT
fn f() { fs::read(p) } // HIT
use std::io; // HIT
fn g() { io::stdout() } // HIT
use std::process; // HIT
fn h() { process::abort() } // HIT
use std::env; // HIT
fn i() { env::args() } // HIT
use std::{net, fs}; // HIT
use rand; // HIT
use rand_core::RngCore; // HIT
const S: &str = "OsRng"; // HIT
fn j() { getrandom(b) } // HIT
fn k(k: &Keypair) {} // HIT
fn l(k: &dyn Signer) {} // HIT
fn m(ks: Keystore) {} // HIT
use mw_crypto::ed25519::*; // HIT
//! Controls: SignRequest, random_nonce, operand, grand, Timestamp, PublicKey.
fn ok(a: InstantX, b: KeypairSet, c: SignerId, d: KeystoreRef, e: SystemTimeish) {}
fn ok2(a: OsRngLike, b: SigningKeyId, c: mytokio, d: tokio_like, e: asleep, f: sleeper) {}
fn ok3() { runtime::x; subnet::x; cfs::x; bio::x; subprocess::x; myenv::x; mythread::x; }
use std::{iter, ops, collections::BTreeMap};
use mw_crypto::ed25519::PublicKey;
RS
  cat > "$tmp/src/machine/sub.rs" <<'RS'
pub struct Ok;
use ed25519_dalek::SigningKey; // HIT
RS
  cat > "$tmp/src/machine_util.rs" <<'RS'
use tokio::sync; // HIT
RS
  cat > "$tmp/src/lib.rs" <<'RS'
#[path = "other.rs"] // HIT
mod machine;
RS
  cat > "$tmp/src/driver.rs" <<'RS'
use tokio::net::TcpStream;
use std::time::Instant;
RS
  hits=$(scan "$tmp/src")
  got=$(printf '%s\n' "$hits" | cut -d: -f1,2 | sort -u)
  want=$(grep -rnH 'HIT' "$tmp/src" | cut -d: -f1,2 | sort -u)
  if [[ "$got" != "$want" ]]; then
    echo "FAIL: self-test hits differ from HIT lines"
    diff <(printf '%s\n' "$want") <(printf '%s\n' "$got") || true
    exit 1
  fi
  mkdir "$tmp/empty"
  for missing in "$tmp/absent" "$tmp/empty"; do
    if scan "$missing" 2>/dev/null; then
      echo "FAIL: self-test expected scan of $missing to fail"
      exit 1
    fi
  done
  echo "machine-purity self-test: OK ($(printf '%s\n' "$got" | grep -c .) planted lines caught; controls and driver.rs clean)"
  exit 0
fi

hits=$(scan crates/mw-session/src) || { echo "FAIL: nothing scanned in crates/mw-session/src"; exit 1; }
if [[ -n "$hits" ]]; then
  printf '%s\n' "$hits"
  echo "FAIL: impure mention in mw-session::machine (ADR-017 Division of responsibility)"
  exit 1
fi
echo "machine-purity: OK"
