#!/usr/bin/env bash
# Run one sandboxed assessment of a target repo, then destroy everything.
#
#   sandbox/controller.sh <repo-url> [harness-timeout-seconds]
#
# Output: reports/<RUN_ID>.json (harness report) and reports/<RUN_ID>.meta.json.
# Env: SANDBOX_RUNTIME (default runsc), VLLM_URL, MODELS_NETWORK, BUILD_TIMEOUT,
#      START_TIMEOUT, KEEP_RUN_DIR=1 to keep runs/<RUN_ID> for debugging.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

REPO_URL="${1:?usage: controller.sh <repo-url> [harness-timeout-seconds]}"
HARNESS_TIMEOUT="${2:-600}"

preflight
manifest="$(find_manifest "$REPO_URL")"
[[ -n "$manifest" ]] || die "no target manifest in sandbox/targets/ for $REPO_URL"

new_run
trap teardown EXIT
log "run $RUN_ID, manifest $(basename "$manifest")"
started="$(date -Is)"

build_target "$REPO_URL"
cp "$manifest" "$RUN_DIR/in/target.json"
start_target

log "running harness (timeout ${HARNESS_TIMEOUT}s)"
compose build --quiet harness
harness_exit=0
# `timeout` can't call the compose() function, so spell the command out.
timeout --kill-after=10 "$HARNESS_TIMEOUT" \
  docker compose -f "$SANDBOX_DIR/compose.yml" -p "$PROJECT" run --rm --no-deps harness \
  || harness_exit=$?
[[ $harness_exit -eq 124 ]] && log "harness hit the ${HARNESS_TIMEOUT}s timeout"

mkdir -p "$ROOT_DIR/reports"
report="$ROOT_DIR/reports/$RUN_ID.json"
if [[ -s "$RUN_DIR/out/report.json" ]]; then
  cp "$RUN_DIR/out/report.json" "$report"
  log "report: $report"
else
  log "harness wrote no report"
fi

python3 - "$ROOT_DIR/reports/$RUN_ID.meta.json" <<EOF
import json, sys
json.dump({
  "run_id": "$RUN_ID", "repo": "$REPO_URL", "commit": "$TARGET_COMMIT",
  "manifest_commit": json.load(open("$manifest")).get("commit"),
  "runtime": "$SANDBOX_RUNTIME", "harness_exit": $harness_exit,
  "started": "$started", "finished": "$(date -Is)",
}, open(sys.argv[1], "w"), indent=2)
EOF
exit "$harness_exit"
