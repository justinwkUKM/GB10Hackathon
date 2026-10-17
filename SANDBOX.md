# Harness gVisor Sandbox

Runs an untrusted target repository and the red-team harness in separate
gVisor (`runsc`) containers with no internet access, drives a live visual
dashboard, collects a resiliency report, and destroys the sandbox when it's done.

```
host: sandbox/controller.sh   (clone → build → run → collect → teardown, hard timeout)

 [vLLM, GPU] ──dgx_models (internal)── [harness, runsc] ──net_target (internal)── [target, runsc]
                                             │ /in (ro) · reports (rw)
                                             └→ reports/<run>.json  +  live dashboard
```

- The target is attached only to `net_target`. It cannot reach vLLM, the host LAN, or the internet.
- The harness reaches the target and vLLM, nothing else.
- The host controller owns the timeout, report collection, and teardown.

## Layout
| Path | What |
|---|---|
| `sandbox/setup-host.sh` | Installs `runsc`, registers it with Docker, creates the `dgx_models` network, attaches vLLM |
| `sandbox/compose.yml` | `target` and `harness` services, hardening, internal networks |
| `sandbox/controller.sh` | `controller.sh <repo-url> [timeout-s]` runs one full assessment |
| `sandbox/smoke-test.sh` | Isolation and wiring checks |
| `sandbox/targets/dvaa.json` | Target manifest: agent endpoints and canaries |
| `harness/Dockerfile` | Builds the red-team harness (runs the scan CLI via tsx) |
| `harness/redteam` | The harness (submodule) |
| `dashboard/` | Live dashboard (`index.html`), status writer (`status.py`), `serve.sh` |

## Run
```bash
git submodule update --init
VLLM_CONTAINER=<vllm-container-name> sandbox/setup-host.sh
dashboard/serve.sh &                 # live view at http://localhost:8800
sandbox/smoke-test.sh
sandbox/controller.sh https://github.com/opena2a-org/damn-vulnerable-ai-agent 600
```

Environment:
- `VLLM_URL` — model endpoint (default `http://vllm:8000/v1`)
- `AGENTS` — agents to assess (default `securebot legacybot ragbot databot`)
- `KEEP_RUN_DIR=1` — keep `runs/<id>` for inspection

## How a run works
1. Clone the target and build its image plus the harness image.
2. Start the target sandbox under `runsc` and run the isolation checks.
3. For each agent, the harness attacks over the OpenAI-compatible API, verifies every
   finding with hard checks (canary tokens, cross-tenant access, outbound traps), and
   writes `reports/<run>-<agent>.json`.
4. Aggregate to `reports/<run>.json`, snapshot the dashboard, and tear the sandbox down.

## Dashboard
`dashboard/serve.sh` serves the live view: the pipeline, the sandbox isolation
guarantees, per-agent verdicts, and every hard-verified finding mapped to
OWASP LLM Top 10 / MITRE ATLAS / NIST AI RMF. It updates in real time as a run proceeds.

## Reports
- `reports/<run>-<agent>.json` — the harness report per agent (findings, score, mapping).
- `reports/<run>.json` — the aggregate (agents assessed, total findings, resiliency).
