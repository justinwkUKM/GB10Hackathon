/**
 * Stage 7 — Benchmark the brain.
 *
 * Counts VERIFIED successes per verifier category (hard-check only; judge-only
 * successes are ignored for this benchmark). Always runs the scripted attacker
 * as the deterministic baseline; if a brain model endpoint is reachable, it also
 * runs the Pi brain for comparison and prints both tallies so you can decide
 * whether to split the brain and attacker roles (plan §12).
 */

import { runScan } from "../src/orchestrator.ts";
import { loadConfig } from "../src/config.ts";
import { endpointUp, finish, info, ok, section, skip } from "./_util.ts";
import type { Report } from "../src/types.ts";

section("Stage 7: benchmark (verified successes per category)");

function tally(report: Report): Record<string, number> {
	const t: Record<string, number> = {};
	for (const f of report.findings) {
		if (f.verdict.judged) continue; // hard-check only
		t[f.verdict.verifier] = (t[f.verdict.verifier] ?? 0) + 1;
	}
	return t;
}

const cfg = loadConfig();

const scripted = await runScan("bench://scripted", {
	attacker: "scripted",
	spawnDemo: "vulnerable",
	configOverrides: { targetUrl: "http://localhost:8128" },
	reportDir: ".pi-agent/verify-reports",
});
const scriptedTally = tally(scripted);
info(`scripted attacker: ${JSON.stringify(scriptedTally)}`);
ok(Object.keys(scriptedTally).length >= 3, "scripted baseline verifies >=3 distinct categories");

if (await endpointUp(cfg.brain.baseUrl)) {
	const brain = await runScan("bench://brain", {
		attacker: "model",
		spawnDemo: "vulnerable",
		configOverrides: { targetUrl: "http://localhost:8129" },
		reportDir: ".pi-agent/verify-reports",
	});
	const brainTally = tally(brain);
	info(`model brain:        ${JSON.stringify(brainTally)}`);
	info("Compare the two tallies to decide whether to split brain/attacker roles.");
} else {
	skip(`no brain endpoint at ${cfg.brain.baseUrl} — brain-vs-scripted comparison skipped`);
}

finish("verify:7");
