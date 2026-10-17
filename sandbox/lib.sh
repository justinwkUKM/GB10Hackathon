# Shared helpers for controller.sh and smoke-test.sh. Source, don't execute.

SANDBOX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(dirname "$SANDBOX_DIR")"
DASHBOARD_DIR="$ROOT_DIR/dashboard"
STATUS_FILE="$DASHBOARD_DIR/status.json"

# Default curated agent subset for the demo (hardened + a few vulnerable).
AGENTS="${AGENTS:-securebot legacybot ragbot databot}"

# status <args...> -- update the live dashboard (no-op if python is missing).
status() {
  python3 "$DASHBOARD_DIR/status.py" --file "$STATUS_FILE" "$@" 2>/dev/null || true
}

# agent_port <id> -- print the agent's port from the active target manifest.
agent_port() {
  python3 - "$1" "$MANIFEST" <<'EOF'
import json, sys
aid, m = sys.argv[1], json.load(open(sys.argv[2]))
for a in m["agents"]:
    if a["id"] == aid:
        print(a["url"].rsplit(":", 1)[1]); break
EOF
}

export SANDBOX_RUNTIME="${SANDBOX_RUNTIME:-runsc}"
export MODELS_NETWORK="${MODELS_NETWORK:-dgx_models}"
# The harness writes /out as this uid so the report is owned by the host user.
# Rootless Docker maps container root to the host user; rootful maps uids 1:1.
if docker info --format '{{.SecurityOptions}}' 2>/dev/null | grep -q rootless; then
  export HOST_UID="${HOST_UID:-0}" HOST_GID="${HOST_GID:-0}"
else
  export HOST_UID="${HOST_UID:-$(id -u)}" HOST_GID="${HOST_GID:-$(id -g)}"
fi

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*" >&2; }
die() { log "ERROR: $*"; exit 1; }

# compose <args...> -- runs docker compose for the current run's project.
compose() {
  docker compose -f "$SANDBOX_DIR/compose.yml" -p "$PROJECT" "$@"
}

# new_run -- sets RUN_ID, PROJECT, RUN_DIR, TARGET_IMAGE and creates the run dir.
new_run() {
  RUN_ID="${RUN_ID:-$(date +%Y%m%d-%H%M%S)-$RANDOM}"
  export PROJECT="run_${RUN_ID//-/_}"
  export RUN_DIR="$ROOT_DIR/runs/$RUN_ID"
  export TARGET_IMAGE="dgxhack/target:$RUN_ID"
  mkdir -p "$RUN_DIR/in" "$RUN_DIR/out"
}

preflight() {
  docker info --format '{{json .Runtimes}}' | grep -q "\"$SANDBOX_RUNTIME\"" \
    || die "Docker runtime '$SANDBOX_RUNTIME' not registered; run sandbox/setup-host.sh"
  docker network inspect "$MODELS_NETWORK" >/dev/null 2>&1 \
    || die "network '$MODELS_NETWORK' missing; run sandbox/setup-host.sh"
  [[ "$SANDBOX_RUNTIME" == runsc ]] || log "WARNING: SANDBOX_RUNTIME=$SANDBOX_RUNTIME (no gVisor isolation)"
}

# find_manifest <repo-url> -- prints the path of the targets/*.json whose .repo matches.
find_manifest() {
  python3 - "$1" "$SANDBOX_DIR/targets" <<'EOF'
import json, pathlib, sys
url, d = sys.argv[1].rstrip("/").removesuffix(".git"), pathlib.Path(sys.argv[2])
for f in sorted(d.glob("*.json")):
    if json.loads(f.read_text()).get("repo", "").rstrip("/") == url:
        print(f); break
EOF
}

# build_target <repo-url> -- clones into $RUN_DIR/src and builds $TARGET_IMAGE.
# NOTE: this is the one step with network access, and it runs under runc, not gVisor.
build_target() {
  local url="$1"
  log "cloning $url"
  git clone --quiet --depth 1 "$url" "$RUN_DIR/src"
  TARGET_COMMIT="$(git -C "$RUN_DIR/src" rev-parse HEAD)"
  log "commit $TARGET_COMMIT"
  [[ -f "$RUN_DIR/src/Dockerfile" ]] || die "repo has no Dockerfile at its root"
  log "building $TARGET_IMAGE"
  timeout "${BUILD_TIMEOUT:-900}" docker build --quiet -t "$TARGET_IMAGE" "$RUN_DIR/src" >/dev/null
}

# start_target -- starts the target sandbox and waits for its image's HEALTHCHECK.
start_target() {
  log "starting target under $SANDBOX_RUNTIME"
  compose up -d --wait --wait-timeout "${START_TIMEOUT:-120}" target
}

# teardown -- removes everything the run created. Safe to call more than once.
teardown() {
  [[ -n "${PROJECT:-}" ]] || return 0
  log "tearing down $PROJECT"
  compose down -v --remove-orphans --timeout 5 >/dev/null 2>&1 || true
  docker image rm -f "$TARGET_IMAGE" >/dev/null 2>&1 || true
  [[ "${KEEP_RUN_DIR:-0}" == 1 ]] || rm -rf "$RUN_DIR"
}
