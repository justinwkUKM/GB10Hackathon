#!/usr/bin/env bash
# Verifies isolation and wiring with DVAA as the target, then tears everything down.
#
#   sandbox/smoke-test.sh [repo-url]
#
# Exit code is the number of failed checks.
set -uo pipefail
source "$(dirname "$0")/lib.sh"

REPO_URL="${1:-https://github.com/opena2a-org/damn-vulnerable-ai-agent}"
export VLLM_URL="${VLLM_URL:-http://vllm:8000/v1}"
failed=0

pass() { printf '  \e[32mPASS\e[0m %s\n' "$1"; }
fail() { printf '  \e[31mFAIL\e[0m %s\n' "$1"; failed=$((failed + 1)); }
# expect_ok <desc> <cmd...> / expect_fail <desc> <cmd...>
expect_ok()   { local d="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$d"; else fail "$d"; fi; }
expect_fail() { local d="$1"; shift; if "$@" >/dev/null 2>&1; then fail "$d"; else pass "$d"; fi; }

# probe <cmd...> -- runs a throwaway alpine container on the target network.
probe() {
  docker run --rm --runtime="$SANDBOX_RUNTIME" --network "${PROJECT}_net_target" alpine "$@"
}
# in_target <cmd...>
in_target() { compose exec -T target "$@"; }

set -e
preflight
new_run
trap teardown EXIT
build_target "$REPO_URL"
cp "$(find_manifest "$REPO_URL")" "$RUN_DIR/in/target.json"
start_target
compose build --quiet harness
set +e

echo "== isolation"
runtime="$(docker inspect -f '{{.HostConfig.Runtime}}' "$(compose ps -q target)")"
[[ "$runtime" == runsc ]] && pass "target runs under runsc" || fail "target runs under runsc (got '$runtime')"
expect_ok   "gVisor kernel inside the sandbox" \
  sh -c "docker run --rm --runtime=$SANDBOX_RUNTIME alpine dmesg | grep -qi gvisor"
expect_fail "target cannot reach the internet by name (example.com)" \
  in_target wget -q -T 5 -O /dev/null https://example.com
expect_fail "target cannot reach the internet by IP (1.1.1.1)" \
  in_target wget -q -T 5 -O /dev/null http://1.1.1.1
expect_fail "target cannot reach vLLM by name" \
  in_target wget -q -T 5 -O /dev/null "$VLLM_URL/models"
vllm_ips="$(docker network inspect "$MODELS_NETWORK" \
  -f '{{range .Containers}}{{.IPv4Address}} {{end}}' | sed 's#/[0-9]*##g')"
for ip in $vllm_ips; do
  expect_fail "target cannot reach models-network host $ip:8000" \
    in_target wget -q -T 5 -O /dev/null "http://$ip:8000/v1/models"
done
expect_fail "target cannot write outside its tmpfs mounts" \
  in_target sh -c 'echo x > /app/pwned'

echo "== wiring"
expect_ok "dashboard reachable from a sibling on net_target" \
  probe wget -q -T 5 -O /dev/null http://target:9000/health
expect_ok "agent chat endpoint answers (securebot :7001)" \
  probe wget -q -T 10 -O /dev/null --header 'Content-Type: application/json' \
    --post-data '{"messages":[{"role":"user","content":"hello"}]}' \
    http://target:7001/v1/chat/completions
expect_ok "harness can reach the target" \
  compose run --rm --no-deps harness python -c \
    "import urllib.request; urllib.request.urlopen('http://target:9000/health', timeout=5)"
expect_ok "harness can reach vLLM ($VLLM_URL)" \
  compose run --rm --no-deps harness python -c \
    "import urllib.request; urllib.request.urlopen('$VLLM_URL/models', timeout=5)"
expect_fail "harness cannot reach the internet" \
  compose run --rm --no-deps harness python -c \
    "import urllib.request; urllib.request.urlopen('https://example.com', timeout=5)"

echo "== $failed check(s) failed"
exit "$failed"
