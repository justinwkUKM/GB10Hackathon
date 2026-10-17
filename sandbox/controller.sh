#!/usr/bin/env bash
# Run one sandboxed assessment of a target repo, then destroy everything.
# Drives a curated subset of the target's agents with the scripted attacker and
# feeds a live dashboard (dashboard/status.json).
#
#   sandbox/controller.sh <repo-url> [harness-timeout-seconds]
#
# Env: SANDBOX_RUNTIME (default runsc), VLLM_URL, MODELS_NETWORK, AGENTS,
#      BUILD_TIMEOUT, START_TIMEOUT, KEEP_RUN_DIR=1.
set -euo pipefail
source "$(dirname "$0")/lib.sh"

REPO_URL="${1:?usage: controller.sh <repo-url> [harness-timeout-seconds]}"
HARNESS_TIMEOUT="${2:-600}"

preflight
export MANIFEST; MANIFEST="$(find_manifest "$REPO_URL")"
[[ -n "$MANIFEST" ]] || die "no target manifest in sandbox/targets/ for $REPO_URL"

new_run
trap teardown EXIT
mkdir -p "$ROOT_DIR/reports"
status init --run-id "$RUN_ID" --repo "$REPO_URL" --runtime "$SANDBOX_RUNTIME" \
  --stages "clone,build,sandbox,isolation,attack,report,teardown"
log "run $RUN_ID, manifest $(basename "$MANIFEST"), agents: $AGENTS"

# --- clone + build (the one networked step) ---
status stage clone active
sleep "${STAGE_DELAY:-5}"
git clone --quiet --depth 1 "$REPO_URL" "$RUN_DIR/src"
TARGET_COMMIT="$(git -C "$RUN_DIR/src" rev-parse HEAD)"
status stage clone done
[[ -f "$RUN_DIR/src/Dockerfile" ]] || die "repo has no Dockerfile at its root"
status stage build active
log "building target + harness images"
timeout "${BUILD_TIMEOUT:-900}" docker build --quiet -t "$TARGET_IMAGE" "$RUN_DIR/src" >/dev/null
compose build --quiet harness >/dev/null
# Canaries the harness should hunt for (the target's own hardcoded secrets).
python3 - "$MANIFEST" "$RUN_DIR/in/canaries.json" <<'EOF'
import json, sys
m = json.load(open(sys.argv[1]))
json.dump([{"label": f"{m['name']}-secret-{i}", "value": v, "kind": "secret"}
           for i, v in enumerate(m.get("canaries", []))], open(sys.argv[2], "w"))
EOF
status stage build done

# --- start target sandbox ---
status stage sandbox active
start_target
status stage sandbox done

# --- isolation checks (what the sandbox guarantees) ---
status stage isolation active
sleep "${STAGE_DELAY:-5}"
iso() { # iso <name> <expect ok|fail> <cmd...>
  local name="$1" expect="$2"; shift 2
  if "$@" >/dev/null 2>&1; then [[ "$expect" == ok ]] && status isolation "$name" true || status isolation "$name" false
  else [[ "$expect" == fail ]] && status isolation "$name" true || status isolation "$name" false; fi
}
iso "target: no internet" fail compose exec -T target wget -q -T 5 -O /dev/null https://example.com
iso "target: cannot reach vLLM" fail compose exec -T target wget -q -T 5 -O /dev/null "${VLLM_URL:-http://vllm:8000/v1}/models"
iso "target: fs read-only" fail compose exec -T target sh -c 'echo x > /app/pwned'
runtime="$(docker inspect -f '{{.HostConfig.Runtime}}' "$(compose ps -q target)")"
[[ "$runtime" == runsc ]] && status isolation "target: gVisor (runsc)" true || status isolation "target: runtime $runtime" false
status stage isolation done

# --- attack each curated agent ---
status stage attack active
for aid in $AGENTS; do
  port="$(agent_port "$aid")"
  [[ -n "$port" ]] || { log "skip $aid (not in manifest)"; continue; }
  level="$(python3 -c "import json;print(next(a['securityLevel'] for a in json.load(open('$MANIFEST'))['agents'] if a['id']=='$aid'))")"
  status agent "$aid" "$level" active
  log "attacking $aid ($level) on :$port"
  sleep "${STEP_DELAY:-5}"
  timeout --kill-after=10 "$HARNESS_TIMEOUT" \
    docker compose -f "$SANDBOX_DIR/compose.yml" -p "$PROJECT" run --rm --no-deps \
      -e TARGET_PROTOCOL=openai \
      -e TARGET_URL="http://target:$port/v1/chat/completions" \
      -e HEALTH_URL="http://target:9000/health" \
      -e SCOPE_ALLOWLIST="target,demo-target" \
      harness "$REPO_URL" --attacker scripted --scan-path /src >/dev/null 2>&1 || log "  $aid: harness exit $?"
  if [[ -s "$RUN_DIR/out/latest.json" ]]; then
    cp "$RUN_DIR/out/latest.json" "$ROOT_DIR/reports/$RUN_ID-$aid.json"
    status agent "$aid" "$level" done --report "$ROOT_DIR/reports/$RUN_ID-$aid.json"
    rm -f "$RUN_DIR/out/latest.json"
  else
    status agent "$aid" "$level" done --findings 0
  fi
done
status stage attack done

# --- aggregate + finalize ---
status stage report active
score="$(python3 - "$ROOT_DIR/reports" "$RUN_ID" <<'EOF'
import glob, json, os, sys
d, rid = sys.argv[1], sys.argv[2]
reps = [json.load(open(f)) for f in glob.glob(os.path.join(d, f"{rid}-*.json"))]
scores = [r.get("resiliencyScore") for r in reps if r.get("resiliencyScore") is not None]
agg = {"run_id": rid, "agents": len(reps),
       "total_findings": sum(len(r.get("findings", [])) for r in reps),
       "min_resiliency": min(scores) if scores else None,
       "avg_resiliency": round(sum(scores)/len(scores)) if scores else None,
       "reports": [os.path.basename(f) for f in glob.glob(os.path.join(d, f"{rid}-*.json"))]}
json.dump(agg, open(os.path.join(d, f"{rid}.json"), "w"), indent=2)
print(agg["min_resiliency"] if agg["min_resiliency"] is not None else "")
EOF
)"
[[ -n "$score" ]] && status finalize --score "$score" || status finalize
cp "$STATUS_FILE" "$ROOT_DIR/reports/$RUN_ID.status.json" 2>/dev/null || true
status stage report done
log "aggregate report: reports/$RUN_ID.json (min resiliency ${score:-n/a})"

# --- teardown (also runs on any earlier failure via the trap) ---
status stage teardown active
teardown
status stage teardown done
