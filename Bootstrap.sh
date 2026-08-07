#!/usr/bin/env bash
# MESHWARDEN workspace bootstrap. Run ONCE from the repo root.
# Creates the Rust workspace, pinned toolchain, cargo-deny policy,
# crypto-boundary check, and the docs/ + lab/ placeholder trees.
set -euo pipefail

# --- safety checks -----------------------------------------------------------
if [[ ! -d .git ]]; then
  echo "Run this from the MESHWARDEN repo root (no .git dir found here)." >&2
  exit 1
fi
if [[ -f Cargo.toml ]]; then
  echo "Cargo.toml already exists -- refusing to overwrite an existing workspace." >&2
  exit 1
fi

LIBS=(mw-crypto mw-proto mw-identity mw-policy mw-task mw-audit mw-transport \
      mw-discovery mw-trust mw-sandbox mw-store mw-telemetry mw-testkit)
BINS=(mw-agent mw-ca mw-control mw-cli mw-sim)
WORKLOADS=(wl-sensor-agg wl-maptile wl-montecarlo wl-telemetry wl-challenge)

# --- create crates (standalone; workspace root written afterwards) -----------
for c in "${LIBS[@]}";      do cargo new --quiet --lib --vcs none "crates/$c"; done
for c in "${BINS[@]}";      do cargo new --quiet       --vcs none "bin/$c";    done
for c in "${WORKLOADS[@]}"; do cargo new --quiet --lib --vcs none "workloads/$c"; done
cargo new --quiet --vcs none xtask

# --- workspace root ----------------------------------------------------------
{
  echo '[workspace]'
  echo 'resolver = "3"'
  echo 'members = ['
  for c in "${LIBS[@]}";      do echo "    \"crates/$c\","; done
  for c in "${BINS[@]}";      do echo "    \"bin/$c\","; done
  for c in "${WORKLOADS[@]}"; do echo "    \"workloads/$c\","; done
  echo '    "xtask",'
  echo ']'
  cat <<'EOF'

[workspace.package]
version = "0.1.0"
edition = "2024"
rust-version = "1.97"
license = "TODO"          # pick one before wiring deny.toml licenses to it

[workspace.dependencies]
# Near-term deps. Verify latest with `cargo add <crate>` in the owning crate.
tokio         = { version = "1", features = ["rt-multi-thread", "macros", "net", "time", "sync", "io-util"] }
rustls        = "0.23"
ed25519-dalek = "2"
x25519-dalek  = "2"
sha2          = "0.10"
axum          = "0.8"
thiserror     = "2"
anyhow        = "1"
EOF
} > Cargo.toml

# --- pinned toolchain + build config ----------------------------------------
cat > rust-toolchain.toml <<'EOF'
[toolchain]
channel = "1.97.1"
targets = ["x86_64-unknown-linux-musl"]
components = ["rustfmt", "clippy"]
EOF

mkdir -p .cargo
cat > .cargo/config.toml <<'EOF'
[target.x86_64-unknown-linux-musl]
rustflags = ["-C", "target-feature=+crt-static"]
EOF

# --- cargo-deny policy -------------------------------------------------------
cat > deny.toml <<'EOF'
[graph]
targets = [{ triple = "x86_64-unknown-linux-musl" }]
all-features = true

[bans]
multiple-versions = "warn"

# ADR-006: ml-kem confined to mw-sim, never on a security path.
# wrappers = allowed ONLY as a direct dependency of these crates.
[[bans.deny]]
name = "ml-kem"
wrappers = ["mw-sim"]

[licenses]
version = 2
allow = [
    "MIT",
    "Apache-2.0",
    "Apache-2.0 WITH LLVM-exception",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "ISC",
    "Unicode-3.0",
    "Zlib",
]

[advisories]
version = 2
ignore = []

[sources]
unknown-registry = "deny"
unknown-git = "deny"
EOF

# --- xtask crypto-boundary check (ADR-007) -----------------------------------
cat > xtask/check-crypto-boundary.sh <<'EOF'
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
EOF
chmod +x xtask/check-crypto-boundary.sh

# --- docs + lab placeholder trees -------------------------------------------
mkdir -p docs/adr docs/spec docs/runbooks
mkdir -p lab/provision lab/netem lab/deception lab/demos lab/bench lab/results
printf '# MESHWARDEN\n\nSee docs/README.md for reading order and the status board.\n' > README.md
printf '# MESHWARDEN docs\n' > docs/README.md
for f in 00-vision 01-prd 02-architecture 03-threat-model 04-crypto-decision \
         05-technology-evaluation 06-prototype-design 07-roadmap 08-proposal; do
  printf '# %s\n' "$f" > "docs/$f.md"
done
printf '# Traceability spine\n' > docs/traceability.md
printf '# Glossary\n' > docs/glossary.md
printf '# ADR index\n\n## Coupled decisions\n\n- ADR-009: Ed25519 hot path <-> hours-scale cert lifetime. Neither changes without re-deriving the other.\n' > docs/adr/README.md
touch lab/results/.gitkeep lab/bench/.gitkeep lab/netem/.gitkeep \
      lab/deception/.gitkeep lab/demos/.gitkeep lab/provision/.gitkeep \
      docs/spec/.gitkeep docs/runbooks/.gitkeep

echo
echo "Scaffold complete. Next:"
echo "  cargo build"
echo "  cargo deny check"
echo "  bash xtask/check-crypto-boundary.sh"