# DVAA broad local scan workflow

This workspace targets only the DVAA repository at `.targets/dvaa`. The workflow runs its offline simulator on loopback, so no Ollama service, hosted AI provider, or API key is involved. The target responses are deterministic demo fixtures, not a live model evaluation.

## Run

Prerequisites are the checked-out DVAA dependencies, `.venv-garak`, Python 3, Node.js, and npx. Start the whole DVAA fleet in offline mode and run the workflow with:

```bash
./run-dvaa-exhaustive.sh
```

The script runs the repository self-test, a 12-case Promptfoo suite against all 15 OpenAI-compatible chat agents, 21 Garak probe classes against LegacyBot and SecureBot, and 18 bounded MCP/A2A protocol checks against the remaining six agents. It writes the summary and raw results under `redteam-results/`.

The self-test's local clone has one small compatibility adjustment: its probe URL uses `127.0.0.1` so macOS does not resolve `localhost` to IPv6 while DVAA listens on IPv4 loopback. The scan stays local. Garak uses one generation per payload to control socket use; the scan covers 5,250 prompts per reference agent. To increase stochastic-model coverage later, use multiple generations and seeds against a live model-backed deployment.

## Scope and interpretation

The combined workflow exercises all 21 DVAA demo agent endpoints: Promptfoo checks the 15 chat agents, protocol-specific requests cover the four MCP and two A2A agents, and DVAA's own matrix covers 11 chat agents. Garak is used for a deep comparison of the vulnerable LegacyBot and hardened SecureBot. This is broad full-surface coverage of the documented local demo interfaces, not a mathematical guarantee against every possible payload or external integration.

Garak detector hits and Promptfoo assertions are signals that need contextual reading. In particular, Garak's refusal detector does not recognize SecureBot's custom `[BLOCKED] Security Alert` message. The protocol and Promptfoo checks also return planted training data; those values are synthetic fixtures in the DVAA sandbox.

Reports can contain the demo's planted credentials and PII. Keep the `redteam-results/` directory private and use the output only for this local training target.
