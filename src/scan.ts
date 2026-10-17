/**
 * Static code scan → capability profile (plan §9).
 *
 * Generic attackers attack with generic goals; ours shouldn't. This scan reads
 * the target's source and derives which capabilities it exposes, so the brain's
 * goal list is scoped to what the target can actually do. White-box by design:
 * the profile carries the system-prompt excerpt, tool schemas, and risky flows.
 *
 * This is a heuristic scanner, not a compiler — it greps for signals. That's
 * enough to seed the attacker and is honest about its limits in `notes`.
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, join } from "node:path";
import type { Capability, CapabilityProfile, TargetToolSchema } from "./types.ts";

const CODE_EXT = new Set([".ts", ".tsx", ".js", ".jsx", ".py", ".rb", ".go", ".java", ".json", ".md", ".txt", ".env"]);
const SKIP_DIR = new Set(["node_modules", ".git", "dist", "build", "reports", "__pycache__", ".venv", "venv"]);

function walk(dir: string, acc: string[] = [], depth = 0): string[] {
	if (depth > 8) return acc;
	let entries: string[];
	try {
		entries = readdirSync(dir);
	} catch {
		return acc;
	}
	for (const name of entries) {
		if (SKIP_DIR.has(name)) continue;
		const full = join(dir, name);
		let st: ReturnType<typeof statSync>;
		try {
			st = statSync(full);
		} catch {
			continue;
		}
		if (st.isDirectory()) walk(full, acc, depth + 1);
		else if (CODE_EXT.has(extname(name)) && st.size < 512_000) acc.push(full);
	}
	return acc;
}

const SIGNALS: { capability: Capability; patterns: RegExp[] }[] = [
	{ capability: "email", patterns: [/send[_ ]?email|sendmail|nodemailer|smtp|ses\b|mailgun/i] },
	{ capability: "web-fetch", patterns: [/fetch_url|requests\.get|axios|urllib|httpx|fetch\(|http\.get/i] },
	{ capability: "rag", patterns: [/embed|vector|pinecone|chroma|faiss|retriev|rag\b|knowledge base/i] },
	{ capability: "tool-use", patterns: [/registerTool|tool_call|function_call|tools\s*[:=]|tool schema|@tool\b/i] },
	{ capability: "auth", patterns: [/session|login|jwt|bearer|api[_ ]?key|authenticate|authorization/i] },
	{ capability: "multi-tenant", patterns: [/owner[_ ]?id|tenant|user[_ ]?id|account[_ ]?id|org[_ ]?id/i] },
	{ capability: "file-upload", patterns: [/multipart|upload|multer|formidable|file\s*=\s*open/i] },
	{ capability: "code-exec", patterns: [/\beval\(|exec\(|child_process|subprocess|os\.system|vm\.runIn/i] },
	{ capability: "system-prompt", patterns: [/system[_ ]?prompt|you are |instructions:|systemMessage/i] },
];

const TOOL_RE = /(?:registerTool|def|function)\s*\(?\s*["']?([a-z_][a-z0-9_]*)["']?[^)]*\)|send_email|lookup_order|fetch_url/gi;

/** Scan a local directory for capabilities. */
export function scanDirectory(repoUrl: string, dir: string): CapabilityProfile {
	const files = walk(dir);
	const found = new Set<Capability>();
	const tools: TargetToolSchema[] = [];
	const riskyFlows: string[] = [];
	let systemPromptExcerpt: string | undefined;
	const notes: string[] = [];

	const toolNames = new Set<string>();
	for (const f of files) {
		let text: string;
		try {
			text = readFileSync(f, "utf8");
		} catch {
			continue;
		}
		for (const { capability, patterns } of SIGNALS) {
			if (patterns.some((p) => p.test(text))) found.add(capability);
		}
		// Extract a system-prompt excerpt from the first file that looks like one.
		if (!systemPromptExcerpt) {
			const m = text.match(/you are [^\n]{0,200}/i);
			if (m) systemPromptExcerpt = m[0].trim();
		}
		// Collect tool-ish names.
		for (const known of ["send_email", "lookup_order", "fetch_url", "search", "query_db"]) {
			if (new RegExp(`\\b${known}\\b`).test(text)) toolNames.add(known);
		}
	}

	for (const name of toolNames) {
		const args =
			name === "send_email"
				? ["to", "body"]
				: name === "fetch_url"
					? ["url"]
					: name === "lookup_order"
						? ["orderId"]
						: ["query"];
		tools.push({ name, args });
	}

	if (found.has("web-fetch")) riskyFlows.push("user input can influence an outbound fetch → exfiltration/SSRF risk");
	if (found.has("multi-tenant") && found.has("auth"))
		riskyFlows.push("multi-tenant records keyed by owner id → cross-tenant/IDOR risk if auth is bypassed via prompt");
	if (found.has("email")) riskyFlows.push("email tool with model-chosen recipient → excessive agency risk");
	if (found.has("system-prompt")) riskyFlows.push("inline system prompt may embed secrets → prompt-leak risk");

	const archetype: CapabilityProfile["archetype"] = found.has("tool-use") || found.has("email") || found.has("web-fetch")
		? "tool-agent"
		: found.has("rag")
			? "rag-assistant"
			: found.size > 0
				? "chatbot"
				: "unknown";

	if (files.length === 0) notes.push(`no scannable source files under ${dir}; profile is minimal`);

	return {
		repoUrl,
		archetype,
		capabilities: Array.from(found),
		systemPromptExcerpt,
		tools,
		riskyFlows,
		notes,
	};
}

/** Entry used by the orchestrator. For the demo, scans the demo-target dir. */
export function staticScan(repoUrl: string, scanPath: string): CapabilityProfile {
	return scanDirectory(repoUrl, scanPath);
}
