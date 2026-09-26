#!/usr/bin/env bash
# ADR-017 Testing obligations (Structural): no fixed-size crypto array in any
# mw-proto wire or spec structure (.cursor/rules/crypto-boundary.mdc).
# Fails if a `[u8; N]` array type appears in crates/mw-proto/src.
# Comments, string literals, and char literals are blanked first, so
# wire-layout docs such as `payload: [u8; payload_len]` in frame.rs do not
# count. Raw strings (r"..", r#".."#) are not understood; none exist in
# mw-proto/src today.
# --self-test: plants a temp file with one array field among comment, string,
# and non-array `u8;` controls, and fails unless exactly that field is caught.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

# Prints file:line:source for every `[u8; N]` array type in code.
# Exits 2 if the directory is missing or holds no .rs files, so a moved or
# emptied target can never pass as clean.
scan() {
  [[ -d "$1" ]] || { echo "FAIL: $1 is not a directory" >&2; return 2; }
  local files=()
  while IFS= read -r -d '' f; do files+=("$f"); done \
    < <(find "$1" -name '*.rs' -type f -print0)
  [[ ${#files[@]} -gt 0 ]] || { echo "FAIL: no .rs files under $1" >&2; return 2; }
  awk '
    FNR == 1 { depth = 0; instr = 0 }
    {
      src = $0; code = ""; n = length(src); i = 1
      while (i <= n) {
        c = substr(src, i, 1); c2 = substr(src, i, 2)
        if (depth > 0) {
          if (c2 == "/*") { depth++; i += 2 }
          else if (c2 == "*/") { depth--; i += 2 }
          else i++
          code = code " "; continue
        }
        if (instr) {
          if (c == "\\") i += 2
          else { if (c == "\"") instr = 0; i++ }
          code = code " "; continue
        }
        if (c2 == "//") break
        if (c2 == "/*") { depth = 1; i += 2; code = code " "; continue }
        if (c == "\"") { instr = 1; i++; code = code " "; continue }
        if (c == "\047") {
          if (substr(src, i + 1, 1) == "\\") {
            j = index(substr(src, i + 2), "\047")
            if (j > 0) { i += j + 2; code = code " "; continue }
          } else if (substr(src, i + 2, 1) == "\047") {
            i += 3; code = code " "; continue
          }
        }
        code = code c; i++
      }
      if (code ~ /\[[[:space:]]*u8[[:space:]]*;/) print FILENAME ":" FNR ":" $0
    }' "${files[@]}"
}

if [[ "${1:-}" == "--self-test" ]]; then
  tmp=$(mktemp -d)
  trap 'rm -rf "$tmp"' EXIT
  cat > "$tmp/planted.rs" <<'RS'
/// doc: [u8; 4] is only a comment
// [u8; 4]
/* [u8; 4] /* nested */ [u8; 4] */
const S: &str = "/* [u8; 4]";
const Q: char = '"';
pub struct Planted {
    pub key: [u8 ; 32],
}
type T = u8;
fn f(x: u32) -> u8 { let b = x as u8; b }
RS
  hits=$(scan "$tmp")
  for missing in "$tmp/absent" "$tmp/empty"; do
    [[ "$missing" == */empty ]] && mkdir "$missing"
    if scan "$missing" 2>/dev/null; then
      echo "FAIL: self-test expected scan of $missing to fail"
      exit 1
    fi
  done
  if [[ "$(printf '%s\n' "$hits" | grep -c .)" -ne 1 ]] || ! grep -q ':7:' <<<"$hits"; then
    echo "FAIL: self-test expected exactly the planted field at line 7, got:"
    printf '%s\n' "$hits"
    exit 1
  fi
  echo "no-fixed-crypto-arrays self-test: OK (caught $hits)"
  exit 0
fi

hits=$(scan crates/mw-proto/src) || { echo "FAIL: nothing scanned in crates/mw-proto/src"; exit 1; }
if [[ -n "$hits" ]]; then
  printf '%s\n' "$hits"
  echo "FAIL: fixed-size [u8; N] array type in crates/mw-proto/src"
  exit 1
fi
echo "no-fixed-crypto-arrays: OK"
