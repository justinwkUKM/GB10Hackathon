/**
 * Stage 0.5 — Demo target.
 *
 * The deliberately vulnerable app builds and answers a health check, and a
 * documented "known vuln" list exists for stage 6 to check against.
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { PROJECT_ROOT } from "../src/config.ts";
import { spawnDemoTarget, waitForHealth } from "../src/target.ts";
import { finish, info, ok, section } from "./_util.ts";

section("Stage 0.5: demo target");

const port = 8120;
const url = `http://localhost:${port}`;
const child = spawnDemoTarget({ port, mode: "vulnerable" });

try {
	await waitForHealth(url);
	ok(true, "demo target answers /health");

	const health = (await (await fetch(`${url}/health`)).json()) as { ok: boolean; mode: string };
	ok(health.ok === true && health.mode === "vulnerable", `health reports mode=${health.mode}`);

	// Known-vuln manifest exists and is non-empty.
	const manifest = JSON.parse(readFileSync(resolve(PROJECT_ROOT, "demo-target/known-vulns.json"), "utf8"));
	ok(Array.isArray(manifest.vulns) && manifest.vulns.length >= 5, `known-vulns.json lists ${manifest.vulns?.length} vulns`);
	ok(
		manifest.vulns.every((v: any) => v.id && v.verifier && v.capability),
		"every known vuln has id + verifier + capability",
	);
	info(`archetype: ${manifest.archetype}`);
} finally {
	child.kill("SIGTERM");
}

finish("verify:0.5");
