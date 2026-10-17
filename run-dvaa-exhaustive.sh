#!/usr/bin/env bash
set -uo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
TARGET="$ROOT/.targets/dvaa"
RESULTS="$ROOT/redteam-results"
SERVER_PID=""

mkdir -p "$RESULTS"

cleanup() {
  if [[ -n "$SERVER_PID" ]]; then
    kill "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

if [[ ! -f "$TARGET/node_modules/.package-lock.json" ]]; then
  echo "DVAA dependencies are missing under $TARGET; install them before running this workflow." >&2
  exit 2
fi
if [[ ! -x "$ROOT/.venv-garak/bin/garak" ]]; then
  echo "Garak is missing at $ROOT/.venv-garak/bin/garak." >&2
  exit 2
fi

if ! curl -fsS --max-time 2 http://127.0.0.1:7003/health >/dev/null 2>&1; then
  (
    cd "$TARGET"
    exec node src/index.js --offline --all
  ) >"$RESULTS/dvaa-server.log" 2>&1 &
  SERVER_PID=$!
fi

ready=0
for _ in $(seq 1 40); do
  if curl -fsS --max-time 2 http://127.0.0.1:7003/health >/dev/null 2>&1 \
    && curl -fsS --max-time 2 http://127.0.0.1:7001/health >/dev/null 2>&1 \
    && curl -fsS --max-time 2 http://127.0.0.1:7010/health >/dev/null 2>&1 \
    && curl -fsS --max-time 2 http://127.0.0.1:7020/health >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 1
done
if [[ "$ready" != 1 ]]; then
  echo "DVAA did not become ready. See $RESULTS/dvaa-server.log" >&2
  exit 3
fi

echo "Running DVAA built-in attack matrix..."
(cd "$TARGET" && node src/index.js --offline selftest --json) >"$RESULTS/dvaa-selftest.json" || true

echo "Running Promptfoo across the 15 API chat agents..."
npx --yes promptfoo@0.124.1 eval \
  -c "$RESULTS/promptfoo-dvaa-full.json" \
  -o "$RESULTS/promptfoo-dvaa-full-results.json" \
  --no-progress-bar >"$RESULTS/promptfoo-dvaa-full.log" 2>&1 || true

echo "Running Garak across the LegacyBot and SecureBot reference pair..."
for name in legacy secure; do
  "$ROOT/.venv-garak/bin/garak" \
    --target_type rest \
    --generator_option_file "$RESULTS/garak-dvaa-$name-rest.json" \
    --spec 'tag:owasp:llm01,probes.sysprompt_extraction,probes.encoding,probes.promptinject,probes.dan' \
    --parallel_attempts 1 \
    --generations 1 \
    --confidence_interval_method none \
    --seed 20261017 \
    --report_prefix "$RESULTS/garak-dvaa-$name-g1" \
    >"$RESULTS/garak-dvaa-$name-g1.log" 2>&1 || echo "Garak failed for $name; inspect its log." >&2
done

echo "Running MCP and A2A protocol checks..."
python3 "$ROOT/scan_dvaa_protocols.py"

echo "Building the summary..."
python3 "$ROOT/summarize_dvaa_scans.py"
echo "Complete. Open $RESULTS/dvaa-exhaustive-summary.md"
