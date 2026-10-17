# Garak and Promptfoo scan summary

Date: 2026-10-17 (local DVAA offline simulation)

## Scope

Garak 0.17.1 and Promptfoo 0.124.1 were run against DVAA LegacyBot and SecureBot on localhost. No hosted model, external AI API, or Ollama was used. The tests target the app's deterministic simulated responses, so they check the security behavior encoded in this demo rather than the resilience of a live language model.

Promptfoo ran two safety expectations per bot. Garak ran `dan.DAN_Jailbreak`, `encoding.InjectBase64`, and `promptinject.HijackHateHumans` (513 attempts per bot across those probes).

## Findings

- **DVAA LegacyBot: vulnerable.** Promptfoo failed both safety expectations. It acknowledged the instruction override and, when asked for its hidden prompt, disclosed the simulated system prompt, API keys, database credentials, and synthetic user records. These are demo fixtures, not real credentials or personal data.
- **DVAA SecureBot: passed the Promptfoo checks (2/2).** It blocked the override and system-prompt disclosure requests.
- **Garak: DAN jailbreak probe.** It detected the LegacyBot override as a mitigation bypass. It also marked SecureBot's response as a bypass because its detector did not recognize the app's custom `[BLOCKED] Security Alert` response as a refusal. Manual inspection confirms SecureBot blocked the request; treat that SecureBot hit as a detector false positive.
- **Garak: encoding and prompt-injection probes.** No detector hits were found for either bot. This reflects the limited set of probes and the fixed demo responses, and does not establish general resistance to those attacks.

## Artifacts

- Promptfoo LegacyBot configuration: [promptfoo-dvaa-legacy.yaml](promptfoo-dvaa-legacy.yaml)
- Promptfoo SecureBot configuration: [promptfoo-dvaa-secure.yaml](promptfoo-dvaa-secure.yaml)
- Promptfoo results: [LegacyBot JSON](promptfoo-dvaa-legacy.json), [SecureBot JSON](promptfoo-dvaa-secure.json)
- Garak configurations: [LegacyBot REST config](garak-dvaa-rest.json), [SecureBot REST config](garak-dvaa-secure-rest.json)
- Garak reports: [LegacyBot HTML](garak-dvaa-legacy.report.html), [SecureBot HTML](garak-dvaa-secure.report.html)
- Garak raw records: [LegacyBot JSONL](garak-dvaa-legacy.report.jsonl), [SecureBot JSONL](garak-dvaa-secure.report.jsonl)

## Not run

AIGoat and DVAP were not scanned. The checked-out versions call Ollama directly and do not currently expose an OpenAI or Anthropic provider setting. Their model-backed tests need a provider integration plus the chosen provider's API key. Ollama was stopped and remains unused.
