/**
 * Shared helpers for the verification ladder (plan §13).
 *
 * Every verify:<stage> script runs HEADLESS, assumes no network egress, and
 * exits non-zero on failure. These helpers give consistent pass/fail/skip
 * semantics and a non-zero exit on any failed assertion.
 */

let failures = 0;

export function ok(cond: unknown, msg: string): void {
	if (cond) {
		console.log(`  ✓ ${msg}`);
	} else {
		failures++;
		console.error(`  ✗ ${msg}`);
	}
}

export function info(msg: string): void {
	console.log(`  ℹ ${msg}`);
}

export function skip(msg: string): void {
	console.log(`  ○ SKIP: ${msg}`);
}

export function section(title: string): void {
	console.log(`\n=== ${title} ===`);
}

export function finish(stage: string): never {
	if (failures > 0) {
		console.error(`\n[${stage}] FAILED with ${failures} assertion failure(s).`);
		process.exit(1);
	}
	console.log(`\n[${stage}] PASSED.`);
	process.exit(0);
}

/** True when an OpenAI-compatible endpoint answers at baseUrl/models. */
export async function endpointUp(baseUrl: string, timeoutMs = 1500): Promise<boolean> {
	try {
		const ctrl = new AbortController();
		const t = setTimeout(() => ctrl.abort(), timeoutMs);
		const res = await fetch(`${baseUrl.replace(/\/$/, "")}/models`, { signal: ctrl.signal }).catch(() => undefined);
		clearTimeout(t);
		return !!res;
	} catch {
		return false;
	}
}

/** True when a CLI command exists and exits 0. */
export async function commandOk(cmd: string, args: string[]): Promise<boolean> {
	const { spawn } = await import("node:child_process");
	return new Promise((res) => {
		const p = spawn(cmd, args, { stdio: "ignore" });
		p.on("error", () => res(false));
		p.on("exit", (code) => res(code === 0));
	});
}
