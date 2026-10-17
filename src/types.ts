/**
 * Shared types for the red-team harness.
 *
 * These describe the deterministic data that flows between the sandbox, the
 * verifiers, the scoring/report layer, and the Pi extension. The model never
 * produces any of these directly — it proposes, and the harness decides.
 */

/** A capability the static scan believes the target exposes. */
export type Capability =
	| "rag"
	| "tool-use"
	| "email"
	| "file-upload"
	| "web-fetch"
	| "code-exec"
	| "auth"
	| "multi-tenant"
	| "system-prompt";

/** Kinds of planted secret we can later detect verbatim in a response. */
export type CanaryKind = "api-key" | "user-record" | "uuid" | "secret";

/** A planted secret. Planted BEFORE the run; a canary you didn't plant can't be verified. */
export interface Canary {
	id: string;
	label: string;
	/** The exact string to hunt for in target output. */
	value: string;
	kind: CanaryKind;
	/** For cross-tenant canaries: the owner session/tenant this record belongs to. */
	ownerId?: string;
}

/** A tool the target app exposes to its own model (discovered by the scan). */
export interface TargetToolSchema {
	name: string;
	description?: string;
	/** Argument names, for tool-argument-injection goals. */
	args: string[];
}

/** White-box capability profile produced by the static scan. */
export interface CapabilityProfile {
	repoUrl: string;
	archetype: "rag-assistant" | "tool-agent" | "chatbot" | "unknown";
	capabilities: Capability[];
	/** A short excerpt of the system prompt if the scan could find one. */
	systemPromptExcerpt?: string;
	tools: TargetToolSchema[];
	/** Human-readable risky data-flow paths the scanner noticed. */
	riskyFlows: string[];
	/** Notes for the report (e.g. "calls a cloud model we had to mock"). */
	notes: string[];
}

/** One raw request/response exchange with the target. Kept out of model context. */
export interface Capture {
	ts: string;
	conversationId: string;
	message: string;
	response: TargetResponse;
}

/** What the sandbox observed when a message was sent to the target. */
export interface TargetResponse {
	/** The target's raw text reply. */
	response: string;
	/** Tool names the target invoked, observed via the instrumented shim. */
	toolCallsObserved: ToolCallObservation[];
	/** Canary labels whose value appeared verbatim in the response. */
	canaryHits: string[];
	/** URLs the target attempted to reach (all blocked; any attempt is a signal). */
	outboundRequests: string[];
	/** Owner IDs present in returned records (for cross-tenant checks). */
	ownerIdsSeen: string[];
	/** HTTP status from the target endpoint. */
	status: number;
}

export interface ToolCallObservation {
	tool: string;
	/** Arguments the target passed to the tool (attacker-controlled args are the signal). */
	args: Record<string, unknown>;
}

/** A finding proposal from the brain, before verification. */
export interface FindingProposal {
	goal: string;
	capability: Capability;
	conversationId: string;
	claimedEvidence: string;
}

/** Verdict from a hard verifier (or the judge, for fuzzy goals). */
export interface Verdict {
	/** Whether the finding is kept (had hard, independent evidence). */
	kept: boolean;
	/** Which verifier decided this (e.g. "canary-token"). */
	verifier: string;
	/** The concrete signal observed, or why it was rejected. */
	signal: string;
	/** True when a fuzzy judge (not a hard check) decided it. */
	judged?: boolean;
	/** Judge confidence / false-positive context, when applicable. */
	judgeMeta?: Record<string, unknown>;
}

/** A finding after verification. Only kept findings reach the report. */
export interface Finding extends FindingProposal {
	id: string;
	verdict: Verdict;
	/** Session attack state snapshot that produced it. */
	capturesRef?: string[];
}

export interface GarakSummary {
	probeFamily: string;
	attempts: number;
	hits: number;
	topFindings: string[];
}

/** The id the scope gate authorizes against. */
export interface ScopeContext {
	targetId: string;
	allowlist: string[];
}

/** Framework mapping for a single kept finding. */
export interface FrameworkMapping {
	owaspLlm?: string;
	owaspAgentic?: string;
	mitreAtlas?: string;
	nistRmf: string;
}

export interface ScoredFinding extends Finding {
	severity: "info" | "low" | "medium" | "high" | "critical";
	mapping: FrameworkMapping;
}

export interface Report {
	repoUrl: string;
	generatedAt: string;
	profile: CapabilityProfile;
	/** Coverage: which verifiers ran, how many attempts, judge calibration. */
	coverage: {
		attacksSent: number;
		garakRuns: number;
		verifiersUsed: string[];
		judgeEnabled: boolean;
		judgeFalsePositiveRate?: number;
	};
	findings: ScoredFinding[];
	/** Resiliency score 0-100 (100 = withstood every attempted attack). */
	resiliencyScore: number;
	/** Honest framing — never a pass/fail or "certified" claim. */
	summary: string;
}
