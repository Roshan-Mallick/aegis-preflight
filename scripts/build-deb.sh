#!/usr/bin/env bash
# Builds aegis-preflight_<version>_amd64.deb — FULLY SELF-CONTAINED.
#
# The .deb ships its own jlink Java runtime with the JavaFX modules baked in,
# so the target machine needs NO java, NO openjfx, NO semgrep rules download:
#
#   /opt/aegis-preflight/runtime/                 custom jlink image (java + javafx)
#   /opt/aegis-preflight/aegis-preflight.jar      shaded fat jar
#   /opt/aegis-preflight/resources/               semgrep-rules + bin/{trivy,gitleaks}
#   /opt/aegis-preflight/applogo.png
#   /usr/bin/aegis-preflight                      launcher (wires -Daegis.resources.dir)
#   /usr/share/applications/aegis-preflight.desktop
#
# Still provisioned once by scripts/setup-offline.sh (NOT per launch):
#   Trivy vulnerability DB (~/.cache/trivy/db) and Ollama model (llama3.2:3b).
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

# --- app tree ---
install -Dm644 "$JAR"                       "$STAGE/opt/aegis-preflight/aegis-preflight.jar"
install -Dm644 "$ROOT/applogo.png"          "$STAGE/opt/aegis-preflight/applogo.png"
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
Icon=/opt/aegis-preflight/applogo.png
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
Recommends: ollama, semgrep
Maintainer: Roshan Mallick <roshanmallick2025@gmail.com>
Description: Desktop security gate for AI-assisted coding.
 Two-gate architecture: Docker sandbox (--network=none, read-only rootfs,
 activity monitoring) plus PreFlight scan gate (Gitleaks secrets, Semgrep SAST
 with bundled rules, Trivy dependency CVEs with cached DB). Deterministic
 BLOCK -> fix -> rescan loop, SHA-256 hash-chained audit log, on-device LLM
 (Ollama) incident reporting — advisory only, never the security decision.
 .
 Ships a bundled Java runtime with JavaFX modules (no system JDK/OpenJFX
 needed). Fully offline after one-time setup (Trivy vulnerability DB + Ollama
 model via setup-offline.sh). No runtime internet connection required.
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
chmod 0755 /opt/aegis-preflight/resources/bin/trivy \
           /opt/aegis-preflight/resources/bin/gitleaks \
           /opt/aegis-preflight/runtime/bin/java \
           /usr/bin/aegis-preflight
# One-time-setup hint shown after install (DB + model are NOT shipped in the deb)
echo "aegis-preflight: run 'scripts/setup-offline.sh' once (Trivy DB + Ollama model), then enjoy fully-offline scanning."
exit 0
EOF
chmod 755 "$STAGE/DEBIAN/postinst"

OUT="$ROOT/dist/aegis-preflight_${VERSION}_amd64.deb"
mkdir -p "$ROOT/dist"
fakeroot dpkg-deb --build "$STAGE" "$OUT"
echo "Built $OUT ($(du -h "$OUT" | cut -f1))"
