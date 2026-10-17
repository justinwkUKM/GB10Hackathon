/**
 * Run the full verification ladder in order. Exits non-zero if any stage fails.
 *
 * Each stage runs headless and assumes no network egress. Stages that need the
 * (optional) model server or garak skip gracefully when those are absent; the
 * deterministic stages (0.5, 2, 4, 6) always run for real.
 */

import { spawn } from "node:child_process";
import { resolve } from "node:path";
import { PROJECT_ROOT } from "../src/config.ts";

const STAGES = [
	"0-image.ts",
	"0_5-demo.ts",
	"2-canaries.ts",
	"3-pi-model.ts",
	"4-verifiers.ts",
	"5-garak.ts",
	"6-loop.ts",
	"7-benchmark.ts",
];

function runStage(file: string): Promise<number> {
	return new Promise((res) => {
		const p = spawn(process.execPath, ["--import", "tsx", resolve(PROJECT_ROOT, "verify", file)], {
			stdio: "inherit",
		});
		p.on("exit", (code) => res(code ?? 1));
	});
}

const results: { file: string; code: number }[] = [];
for (const file of STAGES) {
	const code = await runStage(file);
	results.push({ file, code });
}

console.log("\n========== VERIFICATION LADDER ==========");
let failed = 0;
for (const r of results) {
	const status = r.code === 0 ? "PASS" : "FAIL";
	if (r.code !== 0) failed++;
	console.log(`  ${status}  verify/${r.file}`);
}
console.log("=========================================");
if (failed > 0) {
	console.error(`${failed} stage(s) failed.`);
	process.exit(1);
}
console.log("All stages passed.");
process.exit(0);
