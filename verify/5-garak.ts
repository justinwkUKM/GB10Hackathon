/**
 * Stage 5 — garak tool.
 *
 * Run one probe family against the target and assert the summary parses and
 * `hits` is a number. The wrapper summarizes in code and never hands raw garak
 * logs to the model. When garak is not installed it returns a well-formed
 * "not installed" summary, so the tool contract is validated either way.
 */

import { loadConfig } from "../src/config.ts";
import { commandOk, finish, info, ok, section } from "./_util.ts";
import { connectTarget } from "../src/target.ts";

section("Stage 5: garak tool");

const cfg = loadConfig({ targetUrl: "http://localhost:8125" });
const target = await connectTarget(cfg, { spawnDemo: "vulnerable" });

try {
	const installed = await commandOk("garak", ["--version"]);
	info(`garak installed: ${installed}`);

	const summary = await target.runGarak("promptinject");
	ok(summary.probeFamily === "promptinject", "summary echoes the probe family");
	ok(typeof summary.attempts === "number", "attempts is a number");
	ok(typeof summary.hits === "number", "hits is a number");
	ok(Array.isArray(summary.topFindings), "topFindings is an array");
	if (!installed) {
		ok(
			summary.topFindings.some((f) => /not installed/i.test(f)),
			"absent garak yields a well-formed 'not installed' summary",
		);
	}
} finally {
	await target.stop();
}

finish("verify:5");
