/**
 * Runtime configuration, resolved from environment variables with safe defaults.
 *
 * Also owns resolution of the Pi "brain" model through a project-local
 * models.json, so the harness never depends on a user's global ~/.pi config.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
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
	/**
	 * How to talk to the target. "demo" (default) is the bundled demo-target API
	 * (POST /chat {conversationId,message} -> {response}). "openai" speaks the
	 * OpenAI chat-completions API (POST <targetUrl> {messages} -> choices[0].message.content),
	 * so the harness can point at any OpenAI-compatible agent (e.g. DVAA).
	 */
	targetProtocol: "demo" | "openai";
	/** Health endpoint to wait on. Defaults to <targetUrl>/health. */
	healthUrl: string;
	/**
	 * Path to a JSON file of pre-existing canaries to also hunt for, shape
	 * {label,value,kind}[]. Lets the harness detect a target leaking its own
	 * hardcoded secrets (targets we can't plant into). Empty = none.
	 */
	canaryFile: string;
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
	const targetUrl = env("TARGET_URL", "http://localhost:8099");
	const cfg: HarnessConfig = {
		targetUrl,
		targetProtocol: env("TARGET_PROTOCOL", "demo") === "openai" ? "openai" : "demo",
		healthUrl: env("HEALTH_URL", `${targetUrl.replace(/\/$/, "")}/health`),
		canaryFile: env("CANARY_FILE", ""),
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
	const merged = { ...cfg, ...overrides };
	// If HEALTH_URL wasn't set explicitly and the (possibly overridden) targetUrl
	// differs from the one healthUrl was derived from, re-derive it so callers that
	// override targetUrl (e.g. the verify ladder) still probe the right port.
	if (!process.env.HEALTH_URL && overrides.healthUrl === undefined) {
		merged.healthUrl = `${merged.targetUrl.replace(/\/$/, "")}/health`;
	}
	return merged;
}

/**
 * Write a models.json into agentDir describing the brain's OpenAI-compatible
 * endpoint, so ModelRuntime.getModel(provider, id) resolves offline. Returns the
 * agentDir to pass to Pi.
 */
export function ensureModelsJson(cfg: HarnessConfig): string {
	mkdirSync(cfg.agentDir, { recursive: true });
	const modelsPath = resolve(cfg.agentDir, "models.json");
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
		writeFileSync(modelsPath, next);
	}
	return cfg.agentDir;
}
