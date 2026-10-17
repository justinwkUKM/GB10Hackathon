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
| `harness/` | Placeholder stub harness (`stub.py`) used for wiring tests |
| `harness/redteam` | Submodule: the real harness (`faris/harness_stuff`), not wired in yet |
| `docs/harness-integration-notes.md` | Gaps between the real harness and DVAA |

## Run (on the DGX Spark)
```bash
git submodule update --init
VLLM_CONTAINER=<vllm-container-name> sandbox/setup-host.sh
sandbox/smoke-test.sh
sandbox/controller.sh https://github.com/opena2a-org/damn-vulnerable-ai-agent 600
```
Env: `VLLM_URL` (default `http://vllm:8000/v1`), `SANDBOX_RUNTIME` (default `runsc`;
`runc` only for local testing without gVisor), `KEEP_RUN_DIR=1` to keep `runs/<id>`.

## Harness contract
- In: `/in/target.json` (manifest), env `VLLM_URL`.
- Out: `/out/report.json`.
- Only `/out` and `/tmp` are writable.

## Status
- Tested locally with `SANDBOX_RUNTIME=runc` (Fedora, rootless Docker): the smoke test passes
  every check except the two gVisor ones, and a full controller run collects the stub's report
  and leaves nothing behind.
- Not yet run under gVisor on the Spark.

## Known limitations
- The target image build runs under `runc` with network access, outside gVisor. Fine for a
  known repo like DVAA; arbitrary repos need the build inside gVisor too.
- Canaries are DVAA's built-in secrets; planting our own comes later.
