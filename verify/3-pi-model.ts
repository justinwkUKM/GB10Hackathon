/**
 * Stage 3 — Pi + local model.
 *
 * Headless: constructs a Pi session with the default coding toolset dropped
 * (noTools: "builtin") and our red-team extension loaded, then asserts the brain is
 * offered exactly our typed tools — not bash/read/write/edit. If a brain model
 * endpoint is reachable, it also drives one real turn and asserts the brain
 * called send_to_target and received a real target response. No TUI; exits with
 * a status code.
 */

import {
	createAgentSession,
	DefaultResourceLoader,
	ModelRuntime,
	SessionManager,
} from "@earendil-works/pi-coding-agent";
import { ensureModelsJson, loadConfig } from "../src/config.ts";
import { ATTACKER_SYSTEM_PROMPT } from "../src/prompts.ts";
import { Budget, type RedteamContext, DEFAULT_POLICY_PATTERNS, redteamExtension, Scope } from "../src/redteam-extension.ts";
import { Judge } from "../src/judge.ts";
import { connectTarget } from "../src/target.ts";
import { endpointUp, finish, ok, section, skip } from "./_util.ts";

section("Stage 3: Pi + local model (headless)");

const cfg = loadConfig({ targetUrl: "http://localhost:8123" });
ensureModelsJson(cfg);
const target = await connectTarget(cfg, { spawnDemo: "vulnerable" });
await target.plantCanaries();

const cx: RedteamContext = {
	target,
	budget: new Budget(cfg.budgets),
	scope: new Scope(cfg.scopeAllowlist),
	judge: new Judge(cfg.judge),
	policyPatterns: DEFAULT_POLICY_PATTERNS,
};

const modelRuntime = await ModelRuntime.create({
	modelsPath: `${cfg.agentDir}/models.json`,
	allowModelNetwork: false,
});
const model = modelRuntime.getModel(cfg.brain.provider, cfg.brain.model);
ok(!!model, `brain model ${cfg.brain.provider}/${cfg.brain.model} resolves from models.json`);

const resourceLoader = new DefaultResourceLoader({
	cwd: target.harnessWorkdir,
	agentDir: cfg.agentDir,
	systemPromptOverride: () => ATTACKER_SYSTEM_PROMPT,
	appendSystemPromptOverride: () => [],
	extensionFactories: [redteamExtension(cx)],
});
await resourceLoader.reload();

const { session } = await createAgentSession({
	model: model ?? undefined,
	modelRuntime,
	thinkingLevel: cfg.brain.thinkingLevel,
	sessionManager: SessionManager.inMemory(),
	noTools: "builtin",
	resourceLoader,
	cwd: target.harnessWorkdir,
});

try {
	const active = session.getActiveToolNames();
	ok(active.includes("send_to_target"), "send_to_target is offered to the brain");
	ok(active.includes("run_garak"), "run_garak is offered to the brain");
	ok(active.includes("record_finding"), "record_finding is offered to the brain");
	for (const builtin of ["bash", "read", "write", "edit"]) {
		ok(!active.includes(builtin), `built-in '${builtin}' is NOT offered (noTools: builtin)`);
	}

	if (await endpointUp(cfg.brain.baseUrl)) {
		await session.prompt(
			"Call send_to_target with conversationId 'probe' and message 'hello' exactly once, then stop.",
		);
		ok(target.captures.length >= 1, "brain drove at least one real send_to_target call");
	} else {
		skip(`no brain endpoint at ${cfg.brain.baseUrl} — tool wiring verified offline; live turn skipped`);
	}
} finally {
	session.dispose();
	await target.stop();
}

finish("verify:3");
