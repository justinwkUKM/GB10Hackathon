/**
 * Runtime configuration, resolved from environment variables with safe defaults.
 *
 * Also owns resolution of the Pi "brain" model through a project-local
 * models.json, so the harness never depends on a user's global ~/.pi config.
 */

import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
export const PROJECT_ROOT = resolve(__dirname, "..");

function env(name: string, fallback: string): string {
	const v = process.env[name];
	return v === undefined || v === "" ? fallback : v;
}

function num(name: string, fallback: number): number {
	const v = process.env[name];
	if (v === undefined || v === "") return fallback;
	const n = Number(v);
	return Number.isFinite(n) ? n : fallback;
}

export interface HarnessConfig {
	targetUrl: string;
	scopeAllowlist: string[];
	budgets: Record<string, number>;
	brain: {
		provider: string;
		model: string;
		baseUrl: string;
		apiKey: string;
		thinkingLevel: "off" | "low" | "medium" | "high";
	};
	judge: {
		enabled: boolean;
		baseUrl: string;
		model: string;
		apiKey: string;
	};
	harnessWorkdir: string;
	/** Directory holding the generated models.json; passed to Pi as agentDir. */
	agentDir: string;
}

export function loadConfig(overrides: Partial<HarnessConfig> = {}): HarnessConfig {
	const thinking = env("BRAIN_THINKING_LEVEL", "high") as HarnessConfig["brain"]["thinkingLevel"];
	const agentDir = resolve(PROJECT_ROOT, ".pi-agent");
	const cfg: HarnessConfig = {
		targetUrl: env("TARGET_URL", "http://localhost:8099"),
		scopeAllowlist: env("SCOPE_ALLOWLIST", "demo-target,localhost")
			.split(",")
			.map((s) => s.trim())
			.filter(Boolean),
		budgets: {
			send_to_target: num("BUDGET_SEND_TO_TARGET", 40),
			run_garak: num("BUDGET_RUN_GARAK", 6),
			record_finding: num("BUDGET_RECORD_FINDING", 50),
		},
		brain: {
			provider: env("BRAIN_PROVIDER", "local"),
			model: env("BRAIN_MODEL", "nemotron-3.5-lightning"),
			baseUrl: env("MODEL_BASE_URL", "http://localhost:11434/v1"),
			apiKey: env("MODEL_API_KEY", "ollama"),
			thinkingLevel: thinking,
		},
		judge: {
			enabled: env("JUDGE_BASE_URL", "") !== "",
			baseUrl: env("JUDGE_BASE_URL", ""),
			model: env("JUDGE_MODEL", ""),
			apiKey: env("JUDGE_API_KEY", ""),
		},
		harnessWorkdir: resolve(PROJECT_ROOT, env("HARNESS_WORKDIR", ".pi-agent/workdir")),
		agentDir,
	};
	return { ...cfg, ...overrides };
}

/**
 * Write a models.json into agentDir describing the brain's OpenAI-compatible
 * endpoint, so ModelRuntime.getModel(provider, id) resolves offline. Returns the
 * agentDir to pass to Pi.
 */
export function ensureModelsJson(cfg: HarnessConfig): string {
	// models.json contains the configured API key; restrict the directory and file
	// even when upgrading a workdir created by an earlier version of the harness.
	mkdirSync(cfg.agentDir, { recursive: true, mode: 0o700 });
	chmodSync(cfg.agentDir, 0o700);
	const modelsPath = resolve(cfg.agentDir, "models.json");
	if (existsSync(modelsPath)) chmodSync(modelsPath, 0o600);
	const doc = {
		$schema: "https://pi.dev/schemas/models.schema.json",
		providers: {
			[cfg.brain.provider]: {
				baseUrl: cfg.brain.baseUrl,
				api: "openai-completions",
				apiKey: cfg.brain.apiKey,
				models: [
					{
						id: cfg.brain.model,
						reasoning: true,
						input: ["text"],
						samplingParams: { temperature: 0.9, top_p: 0.95 },
						samplingParamsByThinkingLevel: { high: { temperature: 1.0 } },
					},
				],
			},
		},
	};
	// Only rewrite when changed, so we don't churn the file every run.
	const next = JSON.stringify(doc, null, 2);
	if (!existsSync(modelsPath) || readFileSync(modelsPath, "utf8") !== next) {
		writeFileSync(modelsPath, next, { mode: 0o600 });
	}
	return cfg.agentDir;
}
