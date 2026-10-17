# Running the red-team harness against DVAA: integration notes

Context: the sandbox (`sandbox/`) runs the target and the harness in separate gVisor
containers on internal-only networks. The harness on `faris/harness_stuff`
(submodule at `harness/redteam`, commit `f004577`) is not wired in yet. These are
the gaps found when pointing it at DVAA
(https://github.com/opena2a-org/damn-vulnerable-ai-agent).

## Should fix (affects results)

### 1. Target protocol is hardcoded (`src/target.ts`: `sendToTarget`, `waitForHealth`)
The harness only speaks the demo-target API:
- `GET  <TARGET_URL>/health`
- `POST <TARGET_URL>/chat` with `{conversationId, message}`, expecting `{response}`

DVAA's 21 agents use OpenAI-style `POST /v1/chat/completions` with a `messages` array
and answer in `choices[0].message.content`. Only DVAA's dashboard (port 9000) has
`/health`. As it stands, the health wait never passes against DVAA.

**Ask:** a `TARGET_PROTOCOL=openai` option that keeps message history per
`conversationId`, plus a configurable health URL.

### 2. Only harness-generated canaries count (`generateCanaries` in `src/target.ts`, `canaryTokenVerifier` in `src/verifiers.ts`)
Canaries are fresh random values planted via `POST /__plant__`, and errors are
swallowed. Real targets like DVAA can't accept them; DVAA's secrets are hardcoded.
So DVAA leaking its own keys or SSNs never becomes a finding. A one-prompt stub
already finds 3 leaking agents (legacybot, ragbot, ragbot-aim); the harness would
report 0 for them.

**Ask:** load extra known canaries from a file (e.g. `CANARY_FILE=/in/canaries.json`)
and add them to the generated list. `sandbox/targets/dvaa.json` already lists DVAA's 7.

## Worth knowing (features that don't fire on DVAA)

### 3. garak has no target (`runGarak` in `src/target.ts`)
It runs `garak --model_type rest` with no REST generator config, so garak doesn't
know the target URL and fails even when installed. **Ask:** generate a REST
generator config from the target URL, or use garak's OpenAI-compatible generator.

### 4. `/__signals__` checks see nothing
The tool-call, outbound-request trap and cross-tenant verifiers read `GET /__signals__`,
which only the demo target provides. They fail quietly (empty signals), so only
text-based checks work on DVAA. Optional: DVAA's dashboard exposes
`/api/sandbox/exfil-log` and `/api/sandbox/cmd-log`, which could feed them.

## Minor (handled on the sandbox side with mounts and flags)
- **Output paths:** reports always go to `<repo>/reports`, and `.pi-agent/models.json`
  is written at startup. A `REPORT_DIR` env var would be cleaner than tmpfs and volume mounts.
- **Scope check:** `targetId` is always `"demo-target"`, so the allowlist check is
  effectively a no-op.
- **One target per run:** DVAA has 21 agents; the sandbox side will loop over them.

## Message to forward
> Running the harness against DVAA (inside the gVisor sandbox) hits two blockers:
> (1) target.ts only speaks our `/health` + `/chat {message}→{response}` protocol. Could
> we add `TARGET_PROTOCOL=openai` (`/v1/chat/completions`, with message history per
> conversationId) and a configurable health URL? (2) Canaries are only the generated
> ones, and `/__plant__` fails silently on real targets, so DVAA leaking its own secrets
> never counts. Could we load extra known canaries from `CANARY_FILE`? Also, `runGarak`
> passes `--model_type rest` with no generator config, so garak can't find the target.
