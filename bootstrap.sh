#!/usr/bin/env bash
# bootstrap.sh — velric-agent tool bootstrap (Linux / macOS)
#
# One command installs everything the skill needs:
#   1. Node >= 22.13 runtime (skipped when already present)
#   2. Runtime dependencies (npm install --omit=dev)
#   3. Self-verification: `velric-agent help` must list the command matrix
#
# Usage:
#   bash bootstrap.sh              # install + verify
#   bash bootstrap.sh --verify     # verify only (no install)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

log_ok()   { printf '[ok]   %s\n' "$1"; }
log_err()  { printf '[err]  %s\n' "$1" >&2; }

need_node() {
  if command -v node >/dev/null 2>&1; then
    # Node >= 22.13 required (native TS type stripping)
    local major minor
    major="$(node -e 'console.log(process.versions.node.split(".")[0])')"
    minor="$(node -e 'console.log(process.versions.node.split(".")[1])')"
    if [ "$major" -gt 22 ] || { [ "$major" -eq 22 ] && [ "$minor" -ge 13 ]; }; then
      log_ok "node $(node --version)"; return 0
    fi
  fi
  return 1
}

ensure_node() {
  if need_node; then return 0; fi
  log_err "Node >= 22.13 required (found $(node --version 2>/dev/null || echo 'none'))."
  case "$(uname -s)" in
    Darwin) echo "  brew install node@22" ;;
    *)      echo "  curl -fsSL https://deb.nodesource.com/setup_22.x | bash - && apt-get install -y nodejs" ;;
  esac
  return 1
}

install_deps() {
  if [ ! -d node_modules ] || [ ! -f node_modules/.package-lock.json ]; then
    npm install --omit=dev --no-fund --no-audit
    log_ok "runtime dependencies installed"
  else
    log_ok "runtime dependencies present"
  fi
}

verify() {
  local out
  out="$(node scripts/velric-agent.mjs help 2>&1)" || { log_err "verify failed: $out"; return 1; }
  printf '%s\n' "$out" | grep -q "velric-agent" || { log_err "help output malformed"; return 1; }
  local n
  n="$(printf '%s\n' "$out" | grep -cE '^\s*velric-agent [a-z]')"
  [ "$n" -ge 40 ] || { log_err "command matrix incomplete ($n commands)"; return 1; }
  log_ok "verified: $n commands available"
}

case "${1:-install}" in
  --verify)
    ensure_node
    verify
    ;;
  install)
    ensure_node
    install_deps
    verify
    log_ok "bootstrap complete — invoke via: node $SCRIPT_DIR/scripts/velric-agent.mjs <command>"
    ;;
  *)
    echo "usage: bash bootstrap.sh [--verify]" >&2
    exit 2
    ;;
esac
