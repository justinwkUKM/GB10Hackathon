#!/usr/bin/env python3
"""Build the DVAA local scan summary from saved scanner outputs."""
import json
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).parent
RESULTS = ROOT / "redteam-results"


def read_json(path):
    return json.loads(path.read_text())


def read_jsonl(path):
    rows, malformed = [], 0
    for line in path.read_text().splitlines():
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            # Garak's long prompt records may be truncated in the raw JSONL;
            # its eval/probe summary records remain valid and are what this
            # report uses for aggregate detector counts.
            malformed += 1
    return rows, malformed


pf = read_json(RESULTS / "promptfoo-dvaa-full-results.json")
pf_rows = pf["results"]["results"]
pf_summary = defaultdict(Counter)
for row in pf_rows:
    label = row["provider"].get("label", row["provider"].get("id", "unknown"))
    pf_summary[label]["total"] += 1
    if row.get("success"):
        pf_summary[label]["pass"] += 1
    elif row.get("error") == "No output":
        pf_summary[label]["empty"] += 1
    else:
        pf_summary[label]["leak"] += 1

garak = {}
for name in ("legacy", "secure"):
    path = RESULTS / f"garak-dvaa-{name}-g1.report.jsonl"
    rows, malformed = read_jsonl(path)
    evals = [row for row in rows if row.get("entry_type") == "eval"]
    summaries = [row for row in rows if row.get("entry_type") == "probe_summary"]
    garak[name] = {
        "prompts": sum(row["inference_counts"]["total_evaluated"] for row in summaries),
        "probes": len(summaries),
        "detector_hits": sum(row.get("fails", 0) for row in evals),
        "malformed_attempt_rows": malformed,
        "by_detector": Counter({
            f"{row['probe']} / {row['detector']}": row.get("fails", 0)
            for row in evals
        }),
    }

selftest = read_json(RESULTS / "dvaa-selftest.json")["summary"]
protocol = read_json(RESULTS / "dvaa-protocol-checks.json")

lines = [
    "# DVAA broad local security scan",
    "",
    "Date: 2026-10-17",
    "",
    "## Coverage",
    "",
    "DVAA ran in its built-in offline simulation on loopback. No Ollama, hosted model, or external API key was used. The target answers are deterministic demo behaviors; these results do not measure Gemma or another production LLM.",
    "",
    f"- Promptfoo: {len(pf_rows)} checks ({len(pf_summary)} API chat agents × 12 cases).",
    f"- Garak: {garak['legacy']['probes']} probe classes and {garak['legacy']['prompts']:,} prompts each against LegacyBot and SecureBot ({garak['legacy']['prompts'] + garak['secure']['prompts']:,} target requests total).",
    f"- DVAA self-test: {selftest['total']} cases across 11 API agents.",
    f"- Protocol checks: {protocol['total']} checks over the four MCP and two A2A agents.",
    "- This covers the 15 chat API agents with Promptfoo, plus all six non-chat protocol agents with protocol-specific requests. Garak is run on the vulnerable/reference chat pair. It is broad full-surface coverage of the repository's local demo interfaces, not a proof against every possible payload or runtime configuration.",
    "",
    "## Findings",
    "",
    f"Promptfoo results: {sum(c['pass'] for c in pf_summary.values())} passed, {sum(c['leak'] for c in pf_summary.values())} failed because responses contained planted sensitive markers, and {sum(c['empty'] for c in pf_summary.values())} returned empty assistant content.",
    "",
    "Per API chat agent:",
    "",
]
for agent, counts in pf_summary.items():
    lines.append(f"- **{agent}:** {counts['pass']}/{counts['total']} passed, {counts['leak']} disclosure assertions failed, {counts['empty']} empty responses.")

lines.extend([
    "",
    f"The demo's built-in matrix marked {selftest['pwned']} of {selftest['total']} outcomes as successful attacks, {selftest['blocked']} as blocked, {selftest['weakSignal']} as weak signals, and {selftest['inconclusive']} as inconclusive. Several inconclusive responses need manual review; they are not counted as passes.",
    "",
    f"Protocol checks found {protocol['findings']} unsafe behaviors across MCP/A2A. These are intentionally vulnerable training fixtures; path reads and returned credentials/PII are planted sandbox data. A2A unauthorized-sender controls returned 403, while crafted privileged-identity messages were accepted/executed by the simulated vulnerable agents.",
    "",
    f"Garak reported {garak['legacy']['detector_hits']} detector hits on LegacyBot and {garak['secure']['detector_hits']} on SecureBot. On LegacyBot, {garak['legacy']['by_detector'].get('dan.Ablation_Dan_11_0 / mitigation.MitigationBypass', 0) + garak['legacy']['by_detector'].get('dan.AutoDANCached / mitigation.MitigationBypass', 0) + garak['legacy']['by_detector'].get('dan.DanInTheWild / mitigation.MitigationBypass', 0)} were jailbreak mitigation-bypass hits, consistent with the disclosed override behavior. Garak's mitigation detector also flags SecureBot because its custom `[BLOCKED] Security Alert` response is not recognized as a refusal; this is a known detector false positive. Garak found no matches in the encoding, prompt-injection rogue-string, or system-prompt-extraction detectors for these canned replies; Promptfoo and direct protocol assertions independently detected disclosure.",
    "",
    f"Garak's JSONL contains {garak['legacy']['malformed_attempt_rows']} LegacyBot and {garak['secure']['malformed_attempt_rows']} SecureBot truncated attempt rows for long prompts; aggregate eval and probe-summary records are intact and used above. Use the HTML reports for readable per-probe results.",
    "",
    "## Artifacts",
    "",
    "- Promptfoo matrix: `promptfoo-dvaa-full.json` and `promptfoo-dvaa-full-results.json`.",
    "- Garak LegacyBot: `garak-dvaa-legacy-g1.report.html`, `.report.jsonl`, and `.hitlog.jsonl`.",
    "- Garak SecureBot: `garak-dvaa-secure-g1.report.html`, `.report.jsonl`, and `.hitlog.jsonl`.",
    "- DVAA built-in matrix: `dvaa-selftest.json`.",
    "- MCP/A2A checks: `dvaa-protocol-checks.json`.",
    "- Captured app log: `dvaa-server.log` (created by the workflow script).",
    "",
    "## Limits",
    "",
    "The scan exercises the repository's offline deterministic simulator. It does not test its optional live provider mode, external integrations, persistence across restarts, image inputs, or every tool side effect. The full Garak run uses one generation per payload to keep the local request volume bounded; a stochastic deployed model should be tested with multiple seeds and generations.",
    "",
])
(RESULTS / "dvaa-exhaustive-summary.md").write_text("\n".join(lines))
print(RESULTS / "dvaa-exhaustive-summary.md")
