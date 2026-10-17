/**
 * The orchestrator (plan §5). Plain Node/TypeScript owns the run; Pi is embedded
 * for the one part that benefits from a model in the loop — choosing and adapting
 * attacks. Everything deterministic (target client, verifiers, scoring, mapping,
 * report) stays as code so it never drifts.
 */

import { mkdirSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import {
	createAgentSession,
	DefaultResourceLoader,
	ModelRuntime,
	SessionManager,
} from "@earendil-works/pi-coding-agent";
import { ensureModelsJson, type HarnessConfig, loadConfig, PROJECT_ROOT } from "./config.ts";
import { Judge } from "./judge.ts";
import { ATTACKER_SYSTEM_PROMPT, buildKickoffPrompt } from "./prompts.ts";
import { Budget, DEFAULT_POLICY_PATTERNS, type RedteamContext, redteamExtension, Scope } from "./redteam-extension.ts";
import { buildReport, renderMarkdown } from "./report.ts";
import { connectTarget } from "./target.ts";
import { staticScan } from "./scan.ts";
import { runScriptedAttacker } from "./scripted-attacker.ts";
import type { Report } from "./types.ts";

export interface RunOptions {
	/** Local directory to statically scan (defaults to the demo target). */
	scanPath?: string;
	/** Force an attacker mode; default auto-detects a reachable brain endpoint. */
	attacker?: "model" | "scripted" | "auto";
	/** Spawn the demo target in this mode instead of connecting to TARGET_URL. */
	spawnDemo?: "vulnerable" | "hardened";
	configOverrides?: Partial<HarnessConfig>;
	/** Where to write report files; default <root>/reports. */
	reportDir?: string;
}

async function endpointReachable(baseUrl: string): Promise<boolean> {
	try {
		const ctrl = new AbortController();
		const t = setTimeout(() => ctrl.abort(), 1500);
		const res = await fetch(`${baseUrl.replace(/\/$/, "")}/models`, { signal: ctrl.signal }).catch(() => undefined);
		clearTimeout(t);
		return !!res;
	} catch {
		return false;
	}
}

export async function runScan(repoUrl: string, opts: RunOptions = {}): Promise<Report> {
	const cfg = loadConfig(opts.configOverrides);
	ensureModelsJson(cfg);

	// 1. Deterministic, no model involved.
	const target = await connectTarget(cfg, { spawnDemo: opts.spawnDemo });
	const scanPath = opts.scanPath ?? resolve(PROJECT_ROOT, "demo-target");
	const profile = staticScan(repoUrl, scanPath);
	await target.plantCanaries();

	// Shared red-team context (used by both the Pi brain and the scripted attacker).
	const cx: RedteamContext = {
		target,
		budget: new Budget(cfg.budgets),
		scope: new Scope(cfg.scopeAllowlist),
		judge: new Judge(cfg.judge),
		policyPatterns: DEFAULT_POLICY_PATTERNS,
	};

	// 2. Decide attacker mode.
	let mode = opts.attacker ?? "auto";
	if (mode === "auto") {
		mode = (await endpointReachable(cfg.brain.baseUrl)) ? "model" : "scripted";
	}

	let garakRuns = 0;
	try {
		if (mode === "model") {
			await runModelBrain(cfg, cx, profile);
			garakRuns = cx.budget.snapshot().run_garak ?? 0;
		} else {
			await runScriptedAttacker(cx, profile);
		}
	} catch (err) {
		profile.notes.push(`attacker loop error (${mode}): ${String(err)}`);
	}

	// 3. Deterministic again: score, map, report, then stop the target client.
	const verifiersUsed = Array.from(new Set(target.findings.map((f) => f.verdict.verifier)));
	const report = buildReport({
		repoUrl,
		profile,
		findings: target.findings,
		coverage: {
			attacksSent: target.captures.length,
			garakRuns,
			verifiersUsed,
			judgeEnabled: cx.judge.enabled,
		},
	});

	await target.stop();
	writeReport(report, opts.reportDir);
	return report;
}

/** Embed Pi as the brain (plan §5). Replaces the default coding toolset entirely. */
async function runModelBrain(cfg: HarnessConfig, cx: RedteamContext, profile: Parameters<typeof buildKickoffPrompt>[0]): Promise<void> {
	const modelRuntime = await ModelRuntime.create({
		modelsPath: resolve(cfg.agentDir, "models.json"),
		allowModelNetwork: false,
	});
	const model = modelRuntime.getModel(cfg.brain.provider, cfg.brain.model);
	if (!model) {
		throw new Error(`brain model ${cfg.brain.provider}/${cfg.brain.model} not found in models.json`);
	}

	const resourceLoader = new DefaultResourceLoader({
		cwd: cx.target.harnessWorkdir,
		agentDir: cfg.agentDir,
		systemPromptOverride: () => ATTACKER_SYSTEM_PROMPT,
		appendSystemPromptOverride: () => [],
		extensionFactories: [redteamExtension(cx)],
	});
	await resourceLoader.reload();

	const { session } = await createAgentSession({
		model,
		modelRuntime,
		thinkingLevel: cfg.brain.thinkingLevel,
		sessionManager: SessionManager.inMemory(), // never write session files to disk
		noTools: "builtin", // drop read/write/edit/bash but keep our typed extension tools
		resourceLoader,
		cwd: cx.target.harnessWorkdir,
	});

	const transcript: unknown[] = [];
	const unsubscribe = session.subscribe((e) => transcript.push(e));
	try {
		await session.prompt(buildKickoffPrompt(profile, cx.target.canaries));
	} finally {
		unsubscribe();
		session.dispose();
		writeFileSync(resolve(cx.target.harnessWorkdir, "transcript.json"), JSON.stringify(transcript, null, 2));
	}
}

function writeReport(report: Report, reportDir?: string): void {
	const dir = reportDir ?? resolve(PROJECT_ROOT, "reports");
	mkdirSync(dir, { recursive: true });
	const stamp = report.generatedAt.replace(/[:.]/g, "-");
	writeFileSync(resolve(dir, `report-${stamp}.json`), JSON.stringify(report, null, 2));
	writeFileSync(resolve(dir, `report-${stamp}.md`), renderMarkdown(report));
	writeFileSync(resolve(dir, `latest.json`), JSON.stringify(report, null, 2));
	writeFileSync(resolve(dir, `latest.md`), renderMarkdown(report));
}
