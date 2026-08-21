#!/usr/bin/env bash
# ============================================================================
# Aegis PreFlight — ONE-TIME offline setup.
#
# Everything here is a documented FIRST-RUN step. After it completes, the app
# requires NO network access at runtime.
#   1. Semgrep (host tool)            — pip install if missing
#   2. Semgrep rules                  — already bundled in resources/semgrep-rules
#   3. Trivy binary                   — download into resources/bin if missing
#   4. Trivy vulnerability DB         — trivy fs --download-db-only (once)
#   5. Gitleaks                       — verify the bundled binary works
#   6. Ollama + llama3.2:3b           — verify model is present, pull once if not
#   7. Docker base image              — docker pull ubuntu:22.04 (once)
# ============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RES="$ROOT/aegis-preflight-app/resources"
BIN="$RES/bin"
mkdir -p "$BIN"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
ok()   { printf '    \033[1;32mOK\033[0m %s\n' "$*"; }
warn() { printf '    \033[1;33mWARN\033[0m %s\n' "$*"; }

# --- 1. semgrep host tool ---------------------------------------------------
say "1/7 Semgrep (host scanner binary)"
if command -v semgrep >/dev/null 2>&1 || [ -x "$HOME/.local/bin/semgrep" ]; then
  ok "semgrep found: $(command -v semgrep || echo "$HOME/.local/bin/semgrep")"
else
  warn "semgrep missing — installing via pip (--user)"
  python3 -m pip install --user --quiet semgrep
fi

# --- 2. semgrep rules (bundled) --------------------------------------------
say "2/7 Semgrep rule bundle"
if [ -d "$RES/semgrep-rules/python" ]; then
  ok "bundled rules present ($(find "$RES/semgrep-rules" -name '*.yaml' | wc -l) yaml files)"
else
  warn "bundle missing — cloning (shallow)"
  git clone --depth 1 https://github.com/semgrep/semgrep-rules.git "$RES/semgrep-rules"
  (cd "$RES/semgrep-rules" && git rev-parse HEAD > ../semgrep-rules.version && rm -rf .git)
fi

# --- 3. trivy binary --------------------------------------------------------
say "3/7 Trivy binary (bundled)"
TRIVY="$BIN/trivy"
if [ -x "$TRIVY" ]; then
  ok "$("$TRIVY" --version | head -1) at $TRIVY"
else
  VER="$(curl -sS https://api.github.com/repos/aquasecurity/trivy/releases/latest \
        | grep -oP '"tag_name":\s*"\K[^"]+')"
  warn "downloading trivy ${VER}"
  curl -sSL -o /tmp/trivy.tgz \
    "https://github.com/aquasecurity/trivy/releases/download/${VER}/trivy_${VER#v}_Linux-64bit.tar.gz"
  tar -xzf /tmp/trivy.tgz -C /tmp trivy && mv /tmp/trivy "$TRIVY" && chmod +x "$TRIVY"
  ok "installed $("$TRIVY" --version | head -1)"
fi

# --- 4. trivy vulnerability DB ----------------------------------------------
say "4/7 Trivy vulnerability DB (cached, downloaded once)"
if [ -n "$(ls -A "$HOME/.cache/trivy/db" 2>/dev/null)" ]; then
  ok "DB cache already populated at ~/.cache/trivy/db"
else
  "$TRIVY" fs --download-db-only
  ok "DB downloaded to ~/.cache/trivy/db"
fi

# --- 5. gitleaks ------------------------------------------------------------
say "5/7 Gitleaks (bundled)"
GITLEAKS="$BIN/gitleaks"
if [ -x "$GITLEAKS" ] && "$GITLEAKS" version >/dev/null 2>&1; then
  ok "gitleaks $($("$GITLEAKS" version)) at $GITLEAKS"
elif [ -x "$HOME/bin/gitleaks" ]; then
  cp "$HOME/bin/gitleaks" "$GITLEAKS" && chmod +x "$GITLEAKS"
  ok "copied from ~/bin — gitleaks $($("$GITLEAKS" version))"
else
  warn "gitleaks missing — download from https://github.com/gitleaks/gitleaks/releases"
  exit 1
fi

# --- 6. ollama model ----------------------------------------------------------
say "6/7 Ollama model llama3.2:3b"
OLLAMA_BIN="$(command -v ollama || echo "$HOME/.local/bin/ollama")"
if [ ! -x "$OLLAMA_BIN" ]; then
  warn "ollama not installed — install from https://ollama.com then re-run this script"
  exit 1
fi
(pgrep -f "[o]llama serve" >/dev/null || nohup "$OLLAMA_BIN" serve >/dev/null 2>&1 & sleep 2)
MODEL_PRESENT="$("$OLLAMA_BIN" list 2>/dev/null | grep -c '^llama3.2:3b' || true)"
if [ "${MODEL_PRESENT:-0}" -ge 1 ]; then
  ok "llama3.2:3b present locally"
else
  warn "pulling llama3.2:3b (one-time, ~2GB)"
  "$OLLAMA_BIN" pull llama3.2:3b
fi

# --- 7. docker base image -----------------------------------------------------
say "7/7 Docker base image ubuntu:22.04"
if docker image inspect ubuntu:22.04 >/dev/null 2>&1; then
  ok "ubuntu:22.04 image cached locally"
else
  docker pull ubuntu:22.04
fi

cat <<'EOF'

============================================================
 One-time setup COMPLETE. The app is now fully offline:
 runtime makes zero internet connections (loopback to the
 local Ollama server only).
============================================================
EOF
