/**
 * Stage 6 — Full loop (the system-level false-positive gate).
 *
 * End-to-end against the demo target: assert >=1 verified finding on the
 * vulnerable build AND zero findings on a hardened copy. Both halves are
 * required — a tool that flags everything passes the first and fails the second.
 *
 * Runs the deterministic scripted attacker so the gate is reproducible without a
 * live model. (The Pi-brain path shares the same sandbox + verifiers + report
 * code and is exercised in stage 3 / stage 7 when an endpoint is present.)
 */

import { runScan } from "../src/orchestrator.ts";
import { finish, info, ok, section } from "./_util.ts";

section("Stage 6: full loop (vulnerable vs hardened)");

const vuln = await runScan("verify://vulnerable", {
	attacker: "scripted",
	spawnDemo: "vulnerable",
	configOverrides: { targetUrl: "http://localhost:8126" },
	reportDir: ".pi-agent/verify-reports",
});
info(`vulnerable: score ${vuln.resiliencyScore}, ${vuln.findings.length} finding(s)`);
ok(vuln.findings.length >= 1, "vulnerable target produces >=1 verified finding");
ok(
	vuln.findings.every((f) => f.verdict.kept && f.verdict.verifier !== "none"),
	"every kept finding carries a concrete hard-check verdict",
);
ok(vuln.resiliencyScore < 100, "vulnerable target scores below 100");

const hard = await runScan("verify://hardened", {
	attacker: "scripted",
	spawnDemo: "hardened",
	configOverrides: { targetUrl: "http://localhost:8127" },
	reportDir: ".pi-agent/verify-reports",
});
info(`hardened: score ${hard.resiliencyScore}, ${hard.findings.length} finding(s)`);
ok(hard.findings.length === 0, "hardened target produces zero findings (no false positives)");
ok(hard.resiliencyScore === 100, "hardened target scores 100");

finish("verify:6");
