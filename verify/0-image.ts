/**
 * Stage 0 — Harness image.
 *
 * Asserts the harness builds with egress cut, and reports whether the model
 * server and garak are baked in. In the real outer sandbox these MUST be
 * present (set STRICT_TOOLS=1 to enforce); on a dev box they may be absent, so
 * by default their absence is reported, not failed.
 */

import { commandOk, endpointUp, finish, info, ok, section, skip } from "./_util.ts";
import { loadConfig } from "../src/config.ts";

section("Stage 0: harness image");

const strict = process.env.STRICT_TOOLS === "1";
const cfg = loadConfig();

// Build must pass (this is the offline, egress-free assertion that matters here).
const tsc = await commandOk("npx", ["tsc", "--noEmit"]);
ok(tsc, "`tsc --noEmit` passes (build is green)");

ok(Number(process.versions.node.split(".")[0]) >= 20, `Node >= 20 (have ${process.versions.node})`);

// Model server: Ollama CLI or a reachable OpenAI-compatible endpoint.
const ollama = await commandOk("ollama", ["list"]);
const modelEndpoint = await endpointUp(cfg.brain.baseUrl);
if (ollama || modelEndpoint) {
	ok(true, `model server present (ollama=${ollama}, endpoint=${modelEndpoint})`);
} else if (strict) {
	ok(false, "model server present (STRICT_TOOLS=1)");
} else {
	skip("no model server (ollama/vLLM) reachable — baked into the sandbox image, absent on this dev box");
}

// garak.
const garak = await commandOk("garak", ["--version"]);
if (garak) ok(true, "garak --version works");
else if (strict) ok(false, "garak present (STRICT_TOOLS=1)");
else skip("garak not installed — baked into the sandbox image, absent on this dev box");

info("All dependencies that must be baked for an offline run are checked here.");
finish("verify:0");
