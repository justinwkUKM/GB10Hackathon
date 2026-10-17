/**
 * CLI entry point for the red-team harness.
 *
 *   npm run scan -- <repoUrl|path> [--scan-path <dir>] [--attacker model|scripted|auto]
 *                                  [--demo vulnerable|hardened]
 *
 * With no args it runs against the bundled demo target (vulnerable) using the
 * auto attacker (Pi brain if a model endpoint is reachable, else scripted).
 *
 * Scope note: only run this against systems you own or have written permission
 * to test.
 */

import { runScan } from "./orchestrator.ts";

function arg(name: string): string | undefined {
	const i = process.argv.indexOf(`--${name}`);
	return i >= 0 ? process.argv[i + 1] : undefined;
}

async function main(): Promise<void> {
	const positional = process.argv.slice(2).find((a) => !a.startsWith("--"));
	const repoUrl = positional ?? "demo-target (bundled)";
	const demo = (arg("demo") as "vulnerable" | "hardened" | undefined) ?? (positional ? undefined : "vulnerable");
	const attacker = (arg("attacker") as "model" | "scripted" | "auto" | undefined) ?? "auto";

	// eslint-disable-next-line no-console
	console.log(`[harness] scanning ${repoUrl} (attacker=${attacker}, demo=${demo ?? "none"})`);
	const report = await runScan(repoUrl, { scanPath: arg("scan-path"), attacker, spawnDemo: demo });

	// eslint-disable-next-line no-console
	console.log(`\n=== Resiliency ${report.resiliencyScore}/100 — ${report.findings.length} finding(s) ===`);
	for (const f of report.findings) {
		// eslint-disable-next-line no-console
		console.log(`  [${f.severity.toUpperCase()}] ${f.id} ${f.goal} — ${f.verdict.verifier}: ${f.verdict.signal}`);
	}
	// eslint-disable-next-line no-console
	console.log(`\n${report.summary}`);
	// eslint-disable-next-line no-console
	console.log(`\nReports written to ./reports/latest.md and ./reports/latest.json`);
}

main().catch((err) => {
	// eslint-disable-next-line no-console
	console.error("[harness] fatal:", err);
	process.exit(1);
});
