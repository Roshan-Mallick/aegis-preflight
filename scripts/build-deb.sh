#!/usr/bin/env bash
# Builds aegis-preflight_<version>_amd64.deb.
#
# Package layout:
#   /opt/aegis-preflight/aegis-preflight.jar      shaded fat jar
#   /opt/aegis-preflight/resources/               semgrep-rules + bin/{trivy,gitleaks}
#   /opt/aegis-preflight/applogo.png
#   /usr/bin/aegis-preflight                      launcher (wires -Daegis.resources.dir)
#   /usr/share/applications/aegis-preflight.desktop
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
APP="$ROOT/aegis-preflight-app"
VERSION="$(xmllint --xpath 'string(/*[local-name()="project"]/*[local-name()="version"])' "$APP/pom.xml" 2>/dev/null \
  || grep -oPm1 '(?<=<version>)[^<]+' "$APP/pom.xml" | head -1)"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

JAR="$(ls "$APP"/target/aegis-preflight-*-"all".jar 2>/dev/null | head -1 || true)"
[ -n "$JAR" ] || { echo "jar not built — run: (cd aegis-preflight-app && mvn package)"; exit 1; }

# --- tree ---
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
exec java -Daegis.resources.dir=/opt/aegis-preflight/resources \\
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
Depends: default-jre | openjdk-17-jre, docker.io | docker-ce | docker-cli
Recommends: ollama, semgrep
Suggests: pipx
Maintainer: Roshan Mallick <roshanmallick2025@gmail.com>
Description: Desktop security gate for AI-assisted coding.
 Two-gate architecture: Docker sandbox (--network=none, read-only rootfs,
 activity monitoring) plus PreFlight scan gate (Gitleaks secrets, Semgrep SAST
 with bundled rules, Trivy dependency CVEs with cached DB). Deterministic
 BLOCK -> fix -> rescan loop, SHA-256 hash-chained audit log, on-device LLM
 (Ollama) incident reporting — advisory only, never the security decision.
 .
 Fully offline after one-time setup (Semgrep rules, Trivy vulnerability DB,
 Ollama model — all pre-downloaded during installation). No runtime internet
 connection required.
EOF

cat > "$STAGE/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
chmod 0755 /opt/aegis-preflight/resources/bin/trivy \
           /opt/aegis-preflight/resources/bin/gitleaks \
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
