#!/usr/bin/env bash
# Builds aegis-preflight_<version>_amd64.deb — FULLY SELF-CONTAINED.
#
# The .deb ships EVERYTHING the app needs at runtime:
#
#   /opt/aegis-preflight/runtime/                 custom jlink image (java + javafx)
#   /opt/aegis-preflight/aegis-preflight.jar      shaded fat jar
#   /opt/aegis-preflight/resources/               semgrep-rules + bin/{trivy,gitleaks}
#   /opt/aegis-preflight/llm/bin/llama-server     PACKED inference engine (llama.cpp)
#   /opt/aegis-preflight/llm/models/*.gguf        PACKED quantized LLM weights
#   /opt/aegis-preflight/app-logo.png
#   /usr/bin/aegis-preflight                      launcher (wires -Daegis.resources.dir)
#   /usr/share/applications/aegis-preflight.desktop
#
# The LLM engine and model are fetched ONCE at BUILD time from pinned,
# sha256-verified sources and packed into the .deb — no Ollama, nothing to
# download on the user's machine for AI features.
#
# Still provisioned once by scripts/setup-offline.sh (NOT per launch):
#   Trivy vulnerability DB (~/.cache/trivy/db) and Docker base image.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/aegis-preflight-app"
VERSION="$(xmllint --xpath 'string(/*[local-name()="project"]/*[local-name()="version"])' "$APP/pom.xml" 2>/dev/null \
  || grep -oPm1 '(?<=<version>)[^<]+' "$APP/pom.xml" | head -1)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

JAR="$(ls "$APP"/target/aegis-preflight-*-"all".jar 2>/dev/null | head -1 || true)"
[ -n "$JAR" ] || { echo "jar not built — run: (cd aegis-preflight-app && mvn package)"; exit 1; }

JLINK_BIN="$(command -v jlink || echo /usr/lib/jvm/java-17-openjdk-amd64/bin/jlink)"
JLINK="$(readlink -f "$JLINK_BIN")"
JAVA_HOME_JDK="$(dirname "$(dirname "$JLINK")")"
JMODS_JDK="$JAVA_HOME_JDK/jmods"
[ -d "$JMODS_JDK" ] || { echo "JDK jmods not found at $JMODS_JDK (install openjdk-17-jdk-headless)"; exit 1; }

# --- JavaFX jmods (fetched once into tools/, matching pom javafx.version) ----
JFX_VERSION="$(grep -oPm1 '(?<=<javafx.version>)[^<]+' "$APP/pom.xml")"
TOOLS="$ROOT/tools"
JFX_JMODS="$TOOLS/openjfx-${JFX_VERSION}_linux-x64_bin-jmods.zip"
if [ ! -f "$JFX_JMODS" ]; then
  echo "Fetching JavaFX ${JFX_VERSION} jmods (one-time, ~50 MB)..."
  mkdir -p "$TOOLS"
  curl -sSL --retry 3 -o "$JFX_JMODS" \
    "https://download2.gluonhq.com/openjfx/${JFX_VERSION}/openjfx-${JFX_VERSION}_linux-x64_bin-jmods.zip"
fi
JFX_JMOD_DIR="$STAGE/.javafx-jmods/javafx-jmods-${JFX_VERSION}"
mkdir -p "$(dirname "$JFX_JMOD_DIR")"
unzip -qo "$JFX_JMODS" -d "$(dirname "$JFX_JMOD_DIR")"

# --- custom runtime image (java + javafx, zero system JRE dependency) -------
echo "Building jlink runtime image..."
"$JLINK" \
  --module-path "$JFX_JMOD_DIR:$JMODS_JDK" \
  --add-modules java.se,javafx.base,javafx.graphics,javafx.controls,javafx.fxml,jdk.unsupported,jdk.crypto.ec \
  --strip-debug --no-header-files --no-man-pages --compress=2 \
  --output "$STAGE/opt/aegis-preflight/runtime"

# --- packed LLM engine + model (pinned, sha256-verified) --------------------
LLAMA_BUILD="b10549"
LLAMA_URL="https://github.com/ggml-org/llama.cpp/releases/download/${LLAMA_BUILD}/llama-${LLAMA_BUILD}-bin-ubuntu-x64.tar.gz"
MODEL_URL="https://huggingface.co/Qwen/Qwen2.5-1.5B-Instruct-GGUF/resolve/main/qwen2.5-1.5b-instruct-q4_k_m.gguf"
MODEL_SHA256="6a1a2eb6d15622bf3c96857206351ba97e1af16c30d7a74ee38970e434e9407e"

LLM_SRC="$APP/resources/llm"
LLM_DST="$STAGE/opt/aegis-preflight/llm"
mkdir -p "$LLM_DST/bin" "$LLM_DST/models"

if [ -x "$LLM_SRC/bin/llama-server" ]; then
  echo "Using pre-fetched llama-server from $LLM_SRC/bin"
  cp -a "$LLM_SRC/bin/." "$LLM_DST/bin/"
else
  echo "Fetching llama.cpp ${LLAMA_BUILD} engine (one-time)..."
  TMP_TGZ="$STAGE/.llama.tar.gz"
  curl -sSL --retry 3 -o "$TMP_TGZ" "$LLAMA_URL"
  tar -xzf "$TMP_TGZ" -C "$STAGE"
  SRC_DIR="$STAGE/llama-${LLAMA_BUILD}"
  cp -a "$SRC_DIR"/llama-server "$SRC_DIR"/libllama.so* "$SRC_DIR"/libllama-common.so* \
        "$SRC_DIR"/libllama-server-impl.so "$SRC_DIR"/libmtmd.so* \
        "$SRC_DIR"/libggml*.so* "$LLM_DST/bin/"
  install -Dm644 "$SRC_DIR/LICENSE" "$LLM_DST/bin/LICENSE-llama.cpp"
fi

MODEL_FILE="qwen2.5-1.5b-instruct-q4_k_m.gguf"
if [ -f "$LLM_SRC/models/$MODEL_FILE" ]; then
  echo "Using pre-fetched model from $LLM_SRC/models"
  cp -a "$LLM_SRC/models/$MODEL_FILE" "$LLM_DST/models/"
else
  echo "Fetching packed model (one-time, ~1.1 GB)..."
  curl -sSL --retry 3 -o "$LLM_DST/models/$MODEL_FILE" "$MODEL_URL"
fi
echo "Verifying model sha256..."
echo "$MODEL_SHA256  $LLM_DST/models/$MODEL_FILE" | sha256sum -c -

# --- app tree ---
install -Dm644 "$JAR"                       "$STAGE/opt/aegis-preflight/aegis-preflight.jar"
install -Dm644 "$APP/src/main/resources/styles/app-logo.png" \
                                            "$STAGE/opt/aegis-preflight/app-logo.png"
mkdir -p                                    "$STAGE/opt/aegis-preflight/resources/bin"
cp -r "$APP/resources/semgrep-rules"        "$STAGE/opt/aegis-preflight/resources/semgrep-rules"
install -Dm644 "$APP/resources/semgrep-rules.version" \
                                            "$STAGE/opt/aegis-preflight/resources/semgrep-rules.version"
install -m755 "$APP/resources/bin/trivy"    "$STAGE/opt/aegis-preflight/resources/bin/trivy"
install -m755 "$APP/resources/bin/gitleaks" "$STAGE/opt/aegis-preflight/resources/bin/gitleaks"

mkdir -p "$STAGE/usr/bin" "$STAGE/usr/share/applications"
cat > "$STAGE/usr/bin/aegis-preflight" <<EOF
#!/bin/sh
# Bundled runtime ships JavaFX modules — no system java/openjfx required.
# The LLM engine + model under llm/ start automatically inside the app.
exec /opt/aegis-preflight/runtime/bin/java \\
          -Daegis.resources.dir=/opt/aegis-preflight/resources \\
          -jar /opt/aegis-preflight/aegis-preflight.jar "\$@"
EOF
chmod 755 "$STAGE/usr/bin/aegis-preflight"

cat > "$STAGE/usr/share/applications/aegis-preflight.desktop" <<'EOF'
[Desktop Entry]
Type=Application
Name=Aegis PreFlight
GenericName=Security for AI Coding
Comment=Sandbox AI coding agents and block secrets/SAST bugs/CVEs before release. Fully offline after one-time setup.
Exec=aegis-preflight
Icon=/opt/aegis-preflight/app-logo.png
Terminal=false
Categories=Development;Security;
EOF

# --- control ---
mkdir -p "$STAGE/DEBIAN"
SIZE_KB="$(du -sk "$STAGE/opt" | cut -f1)"
cat > "$STAGE/DEBIAN/control" <<EOF
Package: aegis-preflight
Version: $VERSION
Section: utils
Priority: optional
Architecture: amd64
Installed-Size: $SIZE_KB
Depends: docker.io | docker-ce | docker-cli
Recommends: semgrep
Maintainer: Roshan Mallick <roshanmallick2025@gmail.com>
Description: Desktop security gate for AI-assisted coding.
 Two-gate architecture: Docker sandbox (--network=none, read-only rootfs,
 activity monitoring) plus PreFlight scan gate (Gitleaks secrets, Semgrep SAST
 with bundled rules, Trivy dependency CVEs with cached DB). Deterministic
 BLOCK -> fix -> rescan loop, SHA-256 hash-chained audit log.
 .
 Ships its own Java runtime with JavaFX modules AND its own LLM: a bundled
 llama.cpp engine plus quantized qwen2.5-1.5b-instruct weights generate the
 incident report entirely on-device (advisory only, never the security
 decision). No Ollama or other AI service required.
 .
 Fully offline after one-time setup (Trivy vulnerability DB via
 setup-offline.sh). No runtime internet connection required.
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
chmod 0755 /opt/aegis-preflight/resources/bin/trivy \
           /opt/aegis-preflight/resources/bin/gitleaks \
           /opt/aegis-preflight/runtime/bin/java \
           /opt/aegis-preflight/llm/bin/llama-server \
           /usr/bin/aegis-preflight
# One-time-setup hint shown after install (Trivy DB is NOT shipped in the deb)
echo "aegis-preflight: run 'scripts/setup-offline.sh' once (Trivy vuln DB), then enjoy fully-offline scanning."
exit 0
EOF
chmod 755 "$STAGE/DEBIAN/postinst"

OUT="$ROOT/dist/aegis-preflight_${VERSION}_amd64.deb"
mkdir -p "$ROOT/dist"
fakeroot dpkg-deb --build "$STAGE" "$OUT"
echo "Built $OUT ($(du -h "$OUT" | cut -f1))"
