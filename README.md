# Aegis PreFlight

Desktop security tool for AI-assisted coding. Two-gate architecture:

- **Gate 1 — AEGIS (sandbox):** every AI-agent task runs inside a Docker
  container launched with `--network=none`, read-only rootfs, capped CPU/memory.
  A rule-based ActivityMonitor flags out-of-workspace file access, any network
  attempt and secret-looking strings in real time.
- **Gate 2 — PreFlight (scan gate):** before anything is released to your real
  filesystem, three deterministic scanners inspect the workspace:
  - **Gitleaks** — hardcoded secrets
  - **Semgrep** — SAST bugs using the *bundled* rule set (`resources/semgrep-rules`)
  - **Trivy** — dependency CVEs using the *cached* vulnerability DB

Findings feed a deterministic BLOCK → fix → rescan loop (max 3 retries):
the agent receives `findings.json`, self-fixes, and the scan repeats until PASS.
Every decision is persisted to a SHA-256 hash-chained SQLite audit log with a
one-click chain-integrity verification.

## The LLM is PACKED inside the app

The incident-report LLM ships **inside the package**: a bundled llama.cpp
engine (`llama-server`) plus quantized `qwen2.5-1.5b-instruct` GGUF weights,
started automatically when the app launches. **No Ollama, no model downloads,
no AI service accounts** — the engine binds to loopback only and never talks
to the internet. The model is Apache-2.0 licensed, safe to redistribute.

The LLM is **advisory only** — it never influences the BLOCK/PASS verdict,
which comes exclusively from scanner exit codes plus sandbox policy-violation
flags.

### Security Report card: cold-start behavior

The deterministic **structured report** (tool/rule ID, file:line, severity,
plain-language fix) is displayed the moment a scan finishes — it never waits
for the model and is a complete report on its own. The richer LLM narrative is
generated on a background thread (bounded budget: max 5 attempts × 25s timeout,
progressive backoff) and upgrades the card in place when ready. If the engine
is unavailable or slow, the structured report simply stays — no error, no
blocking, ever.

## Fully offline after one-time setup

> **Fully offline after one-time setup (Trivy vulnerability DB fetched once;
> Java runtime, JavaFX, scanners, rule packs, LLM engine AND LLM weights all
> ship inside the .deb). Zero non-loopback connections at scan time — verified
> at the syscall level.**

| Component | Where it comes from | Where it lives |
|---|---|---|
| Java runtime + JavaFX | shipped | `runtime/` inside the `.deb` (jlink image) |
| Semgrep rules | shipped | `resources/semgrep-rules` inside the `.deb` |
| Trivy binary | shipped | `resources/bin/trivy` inside the `.deb` |
| Trivy vulnerability DB | `trivy fs --download-db-only` once | `~/.cache/trivy/db` |
| Gitleaks binary | shipped | `resources/bin/gitleaks` inside the `.deb` |
| LLM engine + model | shipped (`llm/` in the `.deb`) | `/opt/aegis-preflight/llm` |
| Docker base image | `docker pull ubuntu:22.04` once | local Docker store |

Run `scripts/setup-offline.sh` once to perform/check every row above.
Afterwards the app performs **zero** network calls outside loopback:

- Semgrep runs with `--config=<bundled rules> --metrics=off --no-git-ignore`
  plus `SEMGREP_SEND_METRICS=off` / `SEMGREP_ENABLE_VERSION_CHECK=0` — never
  `--config=auto`, registry pulls or telemetry.
- Trivy runs with `--offline-scan --skip-db-update`.
- Gitleaks is inherently local.
- The sandbox itself has no network (`--network=none`), so the agent cannot
  phone home either.
- The packed LLM listens only on `127.0.0.1:11434` (auto-falls back to the
  next port if something else squats it).
- No hardcoded cloud endpoints exist anywhere in the codebase.

### Offline proof (v0.1.2 regression)

The full pipeline (sandbox isolation probe → planted secret/SAST bug/CVE →
BLOCK → findings.json self-fix → rescan PASS → hash-chain verify → on-device
LLM incident report from the PACKED engine) was executed under
`strace -f -e trace=connect,sendto`. Every socket operation of the whole
process tree (JVM, llama-server, Semgrep, Trivy, Gitleaks) was audited:

```
AF_INET6 : ::ffff:127.0.0.1:11434   (packed LLM server, loopback)
AF_INET  : 127.0.0.53:53            (loopback DNS only)
AF_UNIX  : docker.sock and pipes
→ zero non-loopback connections
```

## Install (deb)

```bash
sudo apt install ./aegis-preflight_0.1.2_amd64.deb   # jar + Java runtime + LLM + all resources
aegis-preflight                                       # GUI
```

Prerequisites on the machine: **Docker and Semgrep only**. No Java, no
OpenJFX, no Ollama. The one-time setup script verifies everything else.

## Run the headless demo path

```bash
cd aegis-preflight-app
java -cp target/aegis-preflight-*-all.jar aegis.cli.DemoRunner
```

This proves the whole chain unattended: sandbox isolation probe → planted
secret/SAST bug/vulnerable dependency → BLOCK → findings.json self-fix →
rescan PASS → hash-chain verification → on-device incident report generated
by the PACKED engine (auto-started, cold-start-aware).

## Build from source

```bash
cd aegis-preflight-app
mvn package               # produces target/aegis-preflight-0.1.2-all.jar
../scripts/build-deb.sh   # packages the .deb: jlink runtime + resources +
                          # pinned llama.cpp engine + sha256-verified GGUF
                          # (needs JDK 17 jmods; fetches JavaFX jmods once)
```

## Security model notes

- Verdicts are computed by `VerdictEngine` from scanner findings only;
  `LocalSecurityLLM` has no write path to severity or verdict values.
- Unavailable scanners do not silently pass the gate.
- The audit log is append-only and hash-chained; `Verify Chain Integrity`
  recomputes the full SHA-256 chain.
