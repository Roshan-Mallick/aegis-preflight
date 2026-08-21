#!/usr/bin/env bash
# ============================================================================
# Aegis demo — scripted AI coding agent (deterministic, for demo reliability)
#
# Modes:
#   task   — "writes code" that deliberately contains a planted secret and a
#            vulnerable dependency pin (the BLOCK scenario)
#   fix    — reads /workspace/findings.json (delivered by the RemediationLoop),
#            moves secrets to environment variables and upgrades the pinned
#            dependency (the self-fix scenario), then signals FIX_APPLIED
#
# Secrets are embedded base64-encoded so this script itself never matches
# Gitleaks rules (the agent's *output* is what must be caught, not its driver).
# ============================================================================
set -u
MODE="${1:-task}"

emit() { echo "AEGIS-EVENT {\"kind\":\"$1\",\"detail\":\"$2\"}"; }

case "$MODE" in

  task)
    emit file_access "write /workspace/config.py"
    echo "IiIiRGVtbyBzZXJ2aWNlIGNvbmZpZ3VyYXRpb24gKGdlbmVyYXRlZCBieSBBSSBjb2RpbmcgYWdlbnQpLiIiIgppbXBvcnQgb3MKaW1wb3J0IHBpY2tsZQoKQVdTX0FDQ0VTU19LRVlfSUQgPSAiQUtJQVZJUjdGNFJMRDZRSzJOTVAiCkFXU19TRUNSRVRfQUNDRVNTX0tFWSA9ICJqOVhrMVdxTHAzbU41dlI3dFljQjJlSGZHOHNEMGFaK1F3RXJUeVVpIgoKUEFZTUVOVF9BUElfS0VZID0gInNrLWxpdmUtOWY4ZTdkNmM1YjRhM2YyZTFkMGM5YjhhN2Y2ZTVkNGMiCgpEQVRBQkFTRV9VUkwgPSBvcy5lbnZpcm9uLmdldCgiREFUQUJBU0VfVVJMIiwgInBvc3RncmVzOi8vYXBwOmFwcEBsb2NhbGhvc3QvZGVtbyIpCgoKZGVmIGdldF9wYXltZW50X2NsaWVudCgpOgogICAgIyBOT1RFOiBhZ2VudCBoYXJkLWNvZGVkIGNyZWRlbnRpYWxzIGZvciAiY29udmVuaWVuY2UiIC0gUHJlRmxpZ2h0IG11c3QgQkxPQ0sgdGhpcwogICAgcmV0dXJuIHsiYXBpX2tleSI6IFBBWU1FTlRfQVBJX0tFWSwgInJlZ2lvbiI6ICJ1cy1lYXN0LTEifQoKCmRlZiBsb2FkX2NhY2hlKGJsb2IpOgogICAgIyBOT1RFOiB1bnNhZmUgZGVzZXJpYWxpemF0aW9uIG9mIHVudHJ1c3RlZCBpbnB1dCAtIFNlbWdyZXAgbXVzdCBjYXRjaCB0aGlzCiAgICByZXR1cm4gcGlja2xlLmxvYWRzKGJsb2IpCg==" | base64 -d > /workspace/config.py

    emit file_access "write /workspace/requirements.txt"
    echo "cmVxdWVzdHM9PTIuMTkuMAo=" | base64 -d > /workspace/requirements.txt

    emit process_exec "python3 -c 'import config' (smoke test)"
    echo "[agent] task complete: wrote config.py (creds + pickle.loads) + requirements.txt"
    echo "TASK_COMPLETE"
    ;;

  fix)
    if [ ! -f /workspace/findings.json ]; then
      echo "[agent] ERROR: findings.json not found — cannot self-fix"
      exit 2
    fi

    emit file_access "read /workspace/findings.json"
    echo "[agent] PreFlight findings received:"
    cat /workspace/findings.json
    echo ""

    echo "IiIiRGVtbyBzZXJ2aWNlIGNvbmZpZ3VyYXRpb24gKGdlbmVyYXRlZCBieSBBSSBjb2RpbmcgYWdlbnQsIHJlbWVkaWF0ZWQpLiIiIgppbXBvcnQgb3MKCkFXU19BQ0NFU1NfS0VZX0lEID0gb3MuZW52aXJvblsiQVdTX0FDQ0VTU19LRVlfSUQiXQpBV1NfU0VDUkVUX0FDQ0VTU19LRVkgPSBvcy5lbnZpcm9uWyJBV1NfU0VDUkVUX0FDQ0VTU19LRVkiXQoKUEFZTUVOVF9BUElfS0VZID0gb3MuZW52aXJvblsiUEFZTUVOVF9BUElfS0VZIl0KCkRBVEFCQVNFX1VSTCA9IG9zLmVudmlyb24uZ2V0KCJEQVRBQkFTRV9VUkwiLCAicG9zdGdyZXM6Ly9hcHA6YXBwQGxvY2FsaG9zdC9kZW1vIikKCgpkZWYgZ2V0X3BheW1lbnRfY2xpZW50KCk6CiAgICByZXR1cm4geyJhcGlfa2V5IjogUEFZTUVOVF9BUElfS0VZLCAicmVnaW9uIjogInVzLWVhc3QtMSJ9CgoKZGVmIGxvYWRfY2FjaGUoYmxvYik6CiAgICBpbXBvcnQganNvbgogICAgcmV0dXJuIGpzb24ubG9hZHMoYmxvYikK" | base64 -d > /workspace/config.py
    emit file_access "rewrite /workspace/config.py (secrets to env vars, pickle -> json)"

    echo "cmVxdWVzdHM9PTIuMzMuMAo=" | base64 -d > /workspace/requirements.txt
    emit file_access "rewrite /workspace/requirements.txt (requests 2.19.0 -> 2.33.0)"

    rm -f /workspace/findings.json
    echo "[agent] fix applied: credentials from environment; pickle.loads removed; dependency upgraded"
    echo "FIX_APPLIED"
    ;;

  *)
    echo "usage: agent-script.sh [task|fix]" >&2
    exit 64
    ;;
esac
