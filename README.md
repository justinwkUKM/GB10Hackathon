# Red-Team Harness (Pi + local model)

A local-first AI red-teaming harness. It takes a target application reachable
inside the sandbox it runs in, attacks it with a model as the brain (via the
[Pi](https://github.com/earendil-works/pi) agent harness) and a deterministic
scripted fallback, **verifies every finding with hard checks**, and emits a
resiliency report mapped to OWASP / MITRE ATLAS / NIST AI RMF.

> **Scope:** only run this against systems you own or have written permission to
> test. The harness is designed to run inside a no-egress sandbox; it connects to
> a target but never provisions, isolates, or reaches the internet itself.

## How it works

```
target reachable at TARGET_URL (inside the sandbox)
  → static scan of the target source  → capability profile
  → plant canaries (fake key, other-tenant record, unique UUID)
  → attacker loop:
       model brain (Pi + local model) — picks & adapts attacks
       or scripted attacker — deterministic, model-free fallback
       every message + observed side-effect is captured
  → verify (hard checks first; judge model only for fuzzy goals)
  → score + map to OWASP / MITRE / NIST
  → report (reports/latest.md + .json)
```

The orchestrator is plain TypeScript. Pi is embedded only for choosing and
adapting attacks; everything deterministic (target client, verifiers, scoring,
mapping, report) stays as code so it never drifts.

### Key design points
- **The model proposes; the harness decides.** `record_finding` proposals are
  re-verified independently against captured target behavior. A proposal without
  hard evidence is dropped.
- **Hard verifiers beat the judge** (`src/verifiers.ts`): canary token, tool-call
  assertion, outbound-request trap, cross-tenant id, policy/commitment regex,
  differential injection, refusal-bypass marker. A local safety judge is used
  only for genuinely fuzzy goals, and only if configured.
- **Typed tools, not shell.** The brain gets `send_to_target`, `run_garak`, and
  `record_finding` with strict TypeBox schemas. Built-in `bash`/`read`/`write`/
  `edit` are dropped (`noTools: "builtin"`).
- **Fail-closed gate.** Every tool call passes a `tool_call` handler enforcing
  scope + attack budget before it runs.

## Quick start

```bash
npm install
npm run build          # tsc --noEmit (green = buildable offline)
npm run scan           # run against the bundled vulnerable demo target (scripted)
cat reports/latest.md
```

Point it at a real target by setting `TARGET_URL` (and `SCOPE_ALLOWLIST`) in
`.env` — see `.env.example`. With a local OpenAI-compatible model endpoint up
(e.g. Ollama/vLLM serving the brain named in `models.json`), the harness
auto-selects the Pi brain; otherwise it falls back to the scripted attacker.

```bash
TARGET_URL=https://my-app.internal SCOPE_ALLOWLIST=my-app.internal npm run scan -- https://github.com/me/my-app
```

## Verification ladder

Each stage ships a headless `verify:<stage>` script that assumes no network
egress and exits non-zero on failure. Run them all:

```bash
npm run verify:all
```

| Stage | Asserts |
|---|---|
| `verify:0`   | build is green; reports whether model server + garak are present |
| `verify:0.5` | demo target builds, answers `/health`, documents its known vulns |
| `verify:2`   | canaries plant + detect verbatim; observed-egress log captures an attempt |
| `verify:3`   | Pi session offers exactly our 3 tools, none of the built-ins (headless) |
| `verify:4`   | each hard verifier true-positives; a clean response trips nothing |
| `verify:5`   | garak wrapper returns a well-formed summary (installed or not) |
| `verify:6`   | **≥1 finding on the vulnerable target AND 0 on the hardened copy** |
| `verify:7`   | verified-success counts per category; brain-vs-scripted if a model is up |

Stages needing the optional model server / garak **skip with a clear banner**
when those are absent (they are baked into the sandbox image); the deterministic
stages (0.5, 2, 4, 6) always run for real.

## Layout

```
src/
  orchestrator.ts      runScan(): embeds Pi, or the scripted attacker
  redteam-extension.ts typed tools + fail-closed tool_call gate + verification
  scripted-attacker.ts deterministic, model-free attacker (shares the same path)
  target.ts            target HTTP client, canaries, egress log, garak wrapper
  scan.ts              static scan → capability profile
  verifiers.ts         the hard checks
  judge.ts             local safety judge, fuzzy cases only
  report.ts            scoring + OWASP/MITRE/NIST mapping + Markdown render
  prompts.ts           attacker persona + kickoff prompt + profile rendering
  config.ts / types.ts config + shared types
  cli.ts               entry point (npm run scan)
demo-target/           deliberately vulnerable app + known-vulns.json (+ hardened mode)
verify/                the verification ladder (headless, egress-free)
```

Clean result framing: a clean run means *these attacks, at this coverage and
this judge, did not succeed* — not that the system is safe. The report never
claims a pass/fail or "NIST certified".
