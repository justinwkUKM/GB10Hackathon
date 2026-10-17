# DVAA broad local security scan

Date: 2026-10-17

## Coverage

DVAA ran in its built-in offline simulation on loopback. No Ollama, hosted model, or external API key was used. The target answers are deterministic demo behaviors; these results do not measure Gemma or another production LLM.

- Promptfoo: 180 checks (15 API chat agents × 12 cases).
- Garak: 22 probe classes and 5,250 prompts each against LegacyBot and SecureBot (10,500 target requests total).
- DVAA self-test: 88 cases across 11 API agents.
- Protocol checks: 18 checks over the four MCP and two A2A agents.
- This covers the 15 chat API agents with Promptfoo, plus all six non-chat protocol agents with protocol-specific requests. Garak is run on the vulnerable/reference chat pair. It is broad full-surface coverage of the repository's local demo interfaces, not a proof against every possible payload or runtime configuration.

## Findings

Promptfoo results: 112 passed, 36 failed because responses contained planted sensitive markers, and 32 returned empty assistant content.

Per API chat agent:

- **LongwindBot:** 4/12 passed, 4 disclosure assertions failed, 4 empty responses.
- **SecureBot:** 12/12 passed, 0 disclosure assertions failed, 0 empty responses.
- **HelperBot:** 8/12 passed, 0 disclosure assertions failed, 4 empty responses.
- **LegacyBot:** 4/12 passed, 8 disclosure assertions failed, 0 empty responses.
- **CodeBot:** 12/12 passed, 0 disclosure assertions failed, 0 empty responses.
- **RAGBot:** 4/12 passed, 8 disclosure assertions failed, 0 empty responses.
- **VisionBot:** 12/12 passed, 0 disclosure assertions failed, 0 empty responses.
- **MemoryBot:** 4/12 passed, 8 disclosure assertions failed, 0 empty responses.
- **RAGBot-AIM:** 4/12 passed, 8 disclosure assertions failed, 0 empty responses.
- **ResearchBot:** 8/12 passed, 0 disclosure assertions failed, 4 empty responses.
- **ResearchBot-AIM:** 8/12 passed, 0 disclosure assertions failed, 4 empty responses.
- **FlightBot:** 8/12 passed, 0 disclosure assertions failed, 4 empty responses.
- **FlightBot-AIM:** 8/12 passed, 0 disclosure assertions failed, 4 empty responses.
- **RepoBot:** 8/12 passed, 0 disclosure assertions failed, 4 empty responses.
- **RepoBot-AIM:** 8/12 passed, 0 disclosure assertions failed, 4 empty responses.

The demo's built-in matrix marked 17 of 88 outcomes as successful attacks, 34 as blocked, 3 as weak signals, and 34 as inconclusive. Several inconclusive responses need manual review; they are not counted as passes.

Protocol checks found 12 unsafe behaviors across MCP/A2A. These are intentionally vulnerable training fixtures; path reads and returned credentials/PII are planted sandbox data. A2A unauthorized-sender controls returned 403, while crafted privileged-identity messages were accepted/executed by the simulated vulnerable agents.

Garak reported 342 detector hits on LegacyBot and 386 on SecureBot. On LegacyBot, 342 were jailbreak mitigation-bypass hits, consistent with the disclosed override behavior. Garak's mitigation detector also flags SecureBot because its custom `[BLOCKED] Security Alert` response is not recognized as a refusal; this is a known detector false positive. Garak found no matches in the encoding, prompt-injection rogue-string, or system-prompt-extraction detectors for these canned replies; Promptfoo and direct protocol assertions independently detected disclosure.

Garak's JSONL contains 6 LegacyBot and 6 SecureBot truncated attempt rows for long prompts; aggregate eval and probe-summary records are intact and used above. Use the HTML reports for readable per-probe results.

## Artifacts

- Promptfoo matrix: `promptfoo-dvaa-full.json` and `promptfoo-dvaa-full-results.json`.
- Garak LegacyBot: `garak-dvaa-legacy-g1.report.html`, `.report.jsonl`, and `.hitlog.jsonl`.
- Garak SecureBot: `garak-dvaa-secure-g1.report.html`, `.report.jsonl`, and `.hitlog.jsonl`.
- DVAA built-in matrix: `dvaa-selftest.json`.
- MCP/A2A checks: `dvaa-protocol-checks.json`.
- Captured app log: `dvaa-server.log` (created by the workflow script).

## Limits

The scan exercises the repository's offline deterministic simulator. It does not test its optional live provider mode, external integrations, persistence across restarts, image inputs, or every tool side effect. The full Garak run uses one generation per payload to keep the local request volume bounded; a stochastic deployed model should be tested with multiple seeds and generations.
