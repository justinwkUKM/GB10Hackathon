# Harness Docker / gVisor sandbox

Runs an untrusted target repo and the red-team harness in separate gVisor (`runsc`)
containers with no internet access, collects a report, and destroys everything.

```
host: sandbox/controller.sh   (clone → build → run → collect → teardown, hard timeout)

 [vLLM, runc+GPU] --dgx_models (internal)-- [harness, runsc] --net_target (internal)-- [target, runsc]
                                                │ /in/target.json (ro)
                                                └ /out/ (rw) → reports/<run>.json
```

- The target is attached only to `net_target`. It can't reach vLLM, the host's LAN or the internet.
- The harness can reach the target and vLLM, nothing else.
- The host controller owns the timeout, report collection and teardown.

## Layout
| Path | What |
|---|---|
| `sandbox/setup-host.sh` | One-time setup: install `runsc` (arm64 or x86_64), register it with Docker, create the `dgx_models` network, attach vLLM (`VLLM_CONTAINER=<name>`) |
| `sandbox/compose.yml` | `target` and `harness` services, hardening, networks |
| `sandbox/controller.sh` | `controller.sh <repo-url> [timeout-s]` runs one full assessment |
| `sandbox/smoke-test.sh` | Isolation and wiring checks against DVAA |
| `sandbox/targets/dvaa.json` | Target manifest: agent endpoints and known canaries |
| `harness/Dockerfile` | Builds the real harness (Node 22, runs the scan CLI via tsx) |
| `harness/redteam` | Submodule: the real harness, branch `harness-dvaa-fixes` |
| `dashboard/` | Live visual dashboard (`index.html`), status writer (`status.py`), `serve.sh` |
| `docs/harness-integration-notes.md` | Gaps between the upstream harness and DVAA |

## Run (on the DGX Spark)
```bash
git submodule update --init
VLLM_CONTAINER=<vllm-container-name> sandbox/setup-host.sh
dashboard/serve.sh &                 # open http://localhost:8800 for the live view
sandbox/smoke-test.sh
sandbox/controller.sh https://github.com/opena2a-org/damn-vulnerable-ai-agent 600
```
Env: `VLLM_URL` (default `http://vllm:8000/v1`), `SANDBOX_RUNTIME` (default `runsc`;
`runc` only for local testing without gVisor), `AGENTS` (curated subset, default
`securebot legacybot ragbot databot`), `KEEP_RUN_DIR=1` to keep `runs/<id>`.

## How a run works
1. Clone + build the target image (the one networked step) and the harness image.
2. Start the target sandbox under `runsc`; run isolation checks.
3. For each curated agent, run the harness (scripted attacker, `TARGET_PROTOCOL=openai`)
   and collect `reports/<run>-<agent>.json`.
4. Aggregate to `reports/<run>.json`, snapshot the dashboard, tear everything down.

## Harness contract (per agent invocation)
- In: env `TARGET_URL`, `HEALTH_URL`, `TARGET_PROTOCOL=openai`, `CANARY_FILE=/in/canaries.json`;
  DVAA source mounted read-only at `/src` (`--scan-path /src`).
- Out: the scan CLI writes `reports/latest.json` (bind-mounted to `runs/<id>/out`).
- Only the reports mount, `/tmp` and `/app/redteam/.pi-agent` are writable.

## Status
- Full pipeline tested locally with `SANDBOX_RUNTIME=runc` (Fedora, rootless Docker):
  clone → build → attack 4 DVAA agents → aggregate report → teardown, with the live
  dashboard populated and nothing left behind. legacybot & ragbot produced hard-verified
  canary-token findings; securebot & databot withstood.
- Not yet run under gVisor on the Spark (the one red isolation chip in the demo is just
  `runc` locally; it reads `gVisor (runsc)` there).

## Known limitations
- The target image build runs under `runc` with network access, outside gVisor. Fine for a
  known repo like DVAA; arbitrary repos need the build inside gVisor too.
- Scripted attacker only; `/__signals__`-based verifiers and garak don't fire on DVAA
  (see `docs/harness-integration-notes.md`). Canaries are DVAA's built-in secrets.
