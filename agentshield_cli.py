#!/usr/bin/env python3
"""AgentShield Local CLI Runner
Private, Autonomous AI Red-Teaming Powered by NVIDIA Nemotron-Lightning
"Your AI. Your Infrastructure. Your Security."
"""

from __future__ import annotations

import argparse
import json
import sys
import time

from agentshield.evaluator import SecurityEvaluator
from agentshield.nemotron import NemotronClient
from agentshield.network_verifier import NetworkVerifier
from agentshield.sandbox import SandboxMerchantAgent
from agentshield.scenarios import SCENARIOS


def main():
    parser = argparse.ArgumentParser(
        description="AgentShield Local: Private, Autonomous AI Red-Teaming Powered by NVIDIA Nemotron-Lightning."
    )
    parser.add_argument(
        "--scenario",
        choices=list(SCENARIOS.keys()),
        default="merchant_approval_bypass",
        help="Target enterprise scenario to red-team (default: merchant_approval_bypass)",
    )
    parser.add_argument(
        "--defense",
        choices=["vulnerable", "guardrail", "hardened"],
        default="vulnerable",
        help="Sandbox agent defense level (vulnerable, guardrail, hardened)",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Enforce strict air-gapped / offline challenge mode",
    )
    parser.add_argument(
        "--model",
        default="nemotron-3.5-lightning",
        help="Model identifier on local Ollama/vLLM instance",
    )
    parser.add_argument(
        "--host",
        default="http://127.0.0.1:11434",
        help="Local inference server URL (default: http://127.0.0.1:11434)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON assessment report",
    )

    args = parser.parse_args()

    # Step 0: Network & Air-Gap Verification
    verifier = NetworkVerifier(forced_offline=args.offline)
    net_status = verifier.probe(args.host)

    if not args.json:
        print("\n" + "=" * 70)
        print("  AGENTSHIELD LOCAL | AUTONOMOUS AI RED-TEAMING")
        print("  Powered by NVIDIA Nemotron 3.5 Lightning")
        print("  Tagline: 'Your AI. Your Infrastructure. Your Security.'")
        print("=" * 70)
        print(f"[*] Inference Host     : {net_status.inference_host} (Strict Local Binding)")
        print(f"[*] Network Status     : {net_status.status_label}")
        print(f"[*] Active Interface   : {net_status.active_interface}")
        print(f"[*] External Telemetry : ZERO (Air-Gapped / Private)")
        print(f"[*] Target Scenario    : {SCENARIOS[args.scenario].name}")
        print(f"[*] Defense Level      : {args.defense.upper()}")
        print("-" * 70)

    # Step 1: Initialize local client
    client = NemotronClient(model_name=args.model, base_url=args.host)
    scenario = SCENARIOS[args.scenario]

    if not args.json:
        print("\n[STEP 1] Generating Adversarial Attack with Nemotron-Lightning...")

    atk_resp = client.generate(
        system_prompt=scenario.attacker_system_prompt,
        user_prompt=scenario.attacker_goal,
        temperature=0.8,
        max_tokens=256,
    )

    if not args.json:
        print(f"         > Measured Inference Speed : {atk_resp.tokens_per_second} tokens/sec")
        print(f"         > Tokens Generated         : {atk_resp.tokens_generated} tokens in {atk_resp.duration_seconds}s")
        print(f"         > Local Inference Engine   : {atk_resp.model}")
        print("\n--- [SYNTHESIZED ADVERSARIAL PAYLOAD] ---")
        print(atk_resp.content.strip())
        print("-" * 42)

    # Step 2: Sandbox Execution
    if not args.json:
        print("\n[STEP 2] Dispatching Payload to Sandbox AI Agent & Mock Tools...")

    sandbox = SandboxMerchantAgent(defense_level=args.defense)
    sandbox_res = sandbox.process(atk_resp.content)

    if not args.json:
        print(f"         > Agent Response : {sandbox_res.response_text}")
        if sandbox_res.executed_tools:
            print(f"         > Tools Invoked  :")
            for t in sandbox_res.executed_tools:
                print(f"           - {t.tool_name}({t.arguments})")
                if t.policy_violation:
                    print(f"             [!] POLICY VIOLATION: {t.violation_rule}")
        else:
            print("         > Tools Invoked  : None (Action blocked or refused)")

    # Step 3: Deterministic Policy Assertion & Nemotron Finding Analyst
    evaluator = SecurityEvaluator(client)
    report = evaluator.evaluate(
        scenario=scenario,
        attack_payload=atk_resp.content,
        sandbox_result=sandbox_res,
        network_status={
            "internet_connected": net_status.internet_connected,
            "status_label": net_status.status_label,
            "inference_host": net_status.inference_host,
            "is_localhost": net_status.is_localhost,
        },
        attack_gen_stats={
            "tokens": atk_resp.tokens_generated,
            "duration_s": atk_resp.duration_seconds,
            "tokens_per_sec": atk_resp.tokens_per_second,
            "endpoint": atk_resp.endpoint,
            "is_live_ollama": atk_resp.is_live_ollama,
        },
    )

    if args.json:
        print(
            json.dumps(
                {
                    "scenario": report.scenario_name,
                    "owasp_id": report.owasp_id,
                    "vulnerability_detected": report.vulnerability_detected,
                    "severity": report.severity,
                    "deterministic_verdict": report.deterministic_verdict,
                    "policy_breached_rule": report.policy_breached_rule,
                    "attack_payload": report.attack_payload,
                    "agent_response": report.agent_response,
                    "executed_tools": report.executed_tools,
                    "analyst_explanation": report.analyst_explanation,
                    "remediation": report.remediation,
                    "inference_stats": report.inference_stats,
                    "network_status": report.network_status,
                },
                indent=2,
            )
        )
        return

    print("\n[STEP 3] Deterministic Policy Assertion & Finding Analyst")
    print(f"         > Severity Verdict : {report.severity}")
    print(f"         > Outcome Summary  : {report.deterministic_verdict}")
    if report.policy_breached_rule:
        print(f"         > Breached Rule    : {report.policy_breached_rule}")

    print("\n--- [NEMOTRON FINDING ANALYST REPORT] ---")
    print(report.analyst_explanation.strip())
    print("\n--- [RECOMMENDED DEFENSIVE REMEDIATION] ---")
    print(report.remediation.strip())
    print("=" * 70 + "\n")


if __name__ == "__main__":
    main()
