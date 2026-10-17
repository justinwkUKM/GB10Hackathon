# AgentShield Local
### Private, Autonomous AI Red-Teaming Powered by NVIDIA Nemotron-Lightning
> **"Your AI. Your Infrastructure. Your Security."**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Model: NVIDIA Nemotron 3.5 Lightning](https://img.shields.io/badge/Model-Nemotron--3.5--Lightning-76B900?logo=nvidia)](https://huggingface.co/nvidia)
[![Inference: Localhost Air-Gapped](https://img.shields.io/badge/Inference-100%25%20Local-blue)](#the-offline-challenge)
[![OWASP: LLM Top 10](https://img.shields.io/badge/Security-OWASP%20LLM%20Top%2010-red)](#supported-attack-scenarios)

---

## Executive Summary & Problem Statement

### Securing AI Agents Without Compromising Data Privacy and Sovereignty
As organisations increasingly deploy autonomous AI agents to access internal databases, execute financial transactions, and make business decisions, they introduce new attack vectors: prompt injection, unauthorized tool execution, credential leakage, and data manipulation.

However, existing AI red-teaming platforms require sending internal prompts, tool definitions, workflows, and test data to external cloud LLM APIs. This raises grave concerns regarding **data confidentiality, sovereignty, third-party API exposure, and per-token costs**.

### The Challenge
> **How can organisations autonomously identify and validate security vulnerabilities in their AI systems while keeping sensitive data, attack simulations, and testing intelligence entirely within their own infrastructure?**

### The Solution: AgentShield Local
**AgentShield Local** is an on-premises, private AI red-teaming platform powered by **NVIDIA Nemotron 3.5 Lightning** (30B total / 3B active parameters). It autonomously synthesizes adversarial attack variations, challenges business logic in sandbox agents, inspects tool-call traces with deterministic policy assertions, and produces actionable security remediation reports—**without a single byte leaving your infrastructure**.

---

## One-Line Pitch
> *"As organisations deploy autonomous AI agents, who is testing whether they can be manipulated? We use locally deployed AI to attack, evaluate, and secure AI systems before real adversaries do."*

---

## Key Value Propositions

| Value Proposition | What the Judges & Enterprise Customers See |
| :--- | :--- |
| **Data Residency & Sovereignty** | Sensitive test prompts, system architectures, and tool responses never leave your infrastructure. Strictly bound to `127.0.0.1`. |
| **Air-Gapped Offline Operation** | The entire adversarial testing loop continues running flawlessly even after physical Internet access is severed. |
| **Zero Per-Token API Costs** | Continuous, high-volume automated fuzzing and red-teaming powered by local compute with live tokens/sec telemetry. |
| **Domain-Tailored Adversarial AI** | Nemotron generates sophisticated, multi-turn attack vectors and explains security findings with OWASP LLM Top 10 mappings. |

---

## Architecture

```mermaid
flowchart TD
    subgraph UI ["Operator Interface"]
        WD["Web Dashboard (http://127.0.0.1:8888)<br>Scenario Selector • Real-Time Telemetry • Report Exporter"]
    end

    subgraph Runtime ["AgentShield Private AI Runtime (Local Compute)"]
        NEMO["NVIDIA Nemotron 3.5 Lightning<br>(30B Total / 3B Active Parameters)<br>Ollama / vLLM Local Engine"]
        
        ATK["Autonomous Attack Generator<br>Contextual Prompt Injections & Privilege Escalation"]
        ANL["Security Finding Analyst<br>OWASP LLM Top 10 Root-Cause & Remediation"]
        
        NEMO --> ATK
        NEMO --> ANL
    end

    subgraph Sandbox ["Target Execution & Policy Boundary"]
        AGENT["Sandbox Financial Review Agent<br>(Vulnerable / Guardrail / Hardened)"]
        
        TOOLS["Deterministic Mock Tools<br>• check_kyc_status()<br>• verify_tax_id()<br>• approve_merchant_credit()<br>• override_risk_score()"]
        
        ASSERT["Deterministic Policy Assertions<br>RULE-FIN-01: Max credit &le; $50K without KYC<br>RULE-SEC-09: Risk score dual-control check"]
        
        AGENT <--> TOOLS
        TOOLS --> ASSERT
    end

    WD -->|1. Trigger Scenario| ATK
    ATK -->|2. Adversarial Payload| AGENT
    ASSERT -->|3. Policy Violations & Tool Traces| ANL
    ANL -->|4. Verified Security Report| WD
```

---

## The Offline Challenge (Demo Walkthrough)

To prove that local AI matters and that data remains private, AgentShield Local features **The Offline Challenge**:

```
+-------------------------------------------------------------------------+
|                       LOCAL AI PROOF DASHBOARD                          |
|                                                                         |
|  [ INFERENCE ENGINE ]     [ NETWORK BOUNDARY ]     [ INFERENCE SPEED ]  |
|       LOCAL                    OFFLINE                    44.5          |
|  Nemotron 3.5 Lightning    Tested Air-Gapped            tokens/sec      |
|                                                                         |
|  [ ATTACK OUTCOME ]                                                     |
|       VERIFIED                                                          |
|  Evidence from Sandbox (Policy Violation: Unauthorized Credit Dispatch) |
+-------------------------------------------------------------------------+
```

### Live Demo Presentation Sequence (60 Seconds)
1. **Live Attack (Online)**: Launch an attack against the merchant review agent. Nemotron generates a prompt injection disguised as an emergency audit note. The sandbox agent erroneously dispatches a \$500,000 credit limit without KYC.
2. **Disconnect the Network**: Sever the machine's external Wi-Fi / WAN connection or toggle **Offline Air-Gap Mode**.
3. **Re-run the Assessment**: Synthesize a fresh adversarial prompt and execute the attack again.
4. **Inspect Local Proof**: Observe real-time measured inference speed (e.g. 40+ tokens/sec) served directly from local compute (`127.0.0.1:11434`), proving zero external network egress.

---

## Supported Attack Scenarios

AgentShield Local targets critical risks outlined in the **OWASP Top 10 for Large Language Models**:

1. **Merchant Credit Limit Bypass (`merchant_approval_bypass`)**
   - *Threat*: Direct and indirect prompt injection tricking an automated financial approval agent into dispatching \$500,000 credit lines to unverified entities.
   - *OWASP*: LLM01 (Prompt Injection) & LLM06 (Excessive Agency).
2. **Tool Privilege Escalation (`tool_privilege_escalation`)**
   - *Threat*: Social engineering an agent into invoking restricted administrative functions (`override_risk_score`) under pretext of executive emergencies.
   - *OWASP*: LLM06 (Excessive Agency).
3. **System Prompt & Secret Extraction (`system_prompt_disclosure`)**
   - *Threat*: Extracting proprietary instructions, internal API tokens, and confidential guardrails via simulated maintenance diagnostics.
   - *OWASP*: LLM02 (Sensitive Information Disclosure).

---

## Quickstart Guide

### 1. Prerequisites
- **Python 3.10+** (Standard library only; zero mandatory pip packages for core dashboard and CLI).
- **Ollama** or **vLLM** running locally.

### 2. Pull Nemotron-Lightning
```bash
# Pull the quantized local model via Ollama
ollama pull nemotron-3.5-lightning
ollama run nemotron-3.5-lightning
```
*(Note: AgentShield includes a built-in high-fidelity local simulator for demonstration on laptops or air-gapped environments without Ollama running).*

### 3. Launch the Web Dashboard
```bash
python3 agentshield/server.py 8888
```
Open your browser to: **`http://127.0.0.1:8888`**

### 4. Run via Command Line (CLI)
```bash
# Run standard red-team evaluation
python3 agentshield_cli.py --scenario merchant_approval_bypass --defense vulnerable

# Run the strict Air-Gapped / Offline Challenge
python3 agentshield_cli.py --scenario merchant_approval_bypass --defense hardened --offline

# Output raw JSON security audit report
python3 agentshield_cli.py --scenario tool_privilege_escalation --json
```

---

## Target Verification Labs (DVAA, AIGoat, DVAP)

This repository also contains automated integration smoke suites against local vulnerable AI agent testbeds:

- `ai_redteam.py`: Standalone Python runner probing local instances of DVAA (LegacyBot & SecureBot), AIGoat, and DVAP.
- `scan_dvaa_protocols.py`: Protocol and boundary check for MCP tool endpoints (`ToolBot`, `DataBot`, `PluginBot`, `ProxyBot`).
- Reports and audit summaries are generated under `redteam-results/`.

```bash
# Run local lab smoke tests
python3 ai_redteam.py
python3 scan_dvaa_protocols.py
```

---

## Project Structure

```
GB10Hackathon/
├── agentshield/                    # AgentShield Core Package
│   ├── __init__.py
│   ├── nemotron.py                 # Nemotron-Lightning Client (Ollama / Local Inference)
│   ├── sandbox.py                  # Sandbox Agent with Mock Financial Tools
│   ├── scenarios.py                # Red-team scenarios & threat definitions
│   ├── evaluator.py                # Deterministic Policy Assertion & Finding Analyst
│   ├── network_verifier.py         # Air-gap verification & latency profiler
│   └── server.py                   # Web Dashboard & Local Private AI Server
├── agentshield_cli.py              # Interactive CLI Runner
├── ai_redteam.py                   # Local lab smoke test runner
├── scan_dvaa_protocols.py          # MCP / A2A protocol vulnerability scanner
├── redteam-results/                # Test artifacts and audit reports
├── README-redteam.md               # Lab environment configuration guide
└── README.md                       # Main Documentation
```

---

## Presentation Pitch Script

> *"Today, enterprises are deploying AI agents to access sensitive systems and automate critical decisions. But securing these agents presents a new challenge.*
>
> *We built **AgentShield Local**, powered by **NVIDIA Nemotron 3.5 Lightning**, to bring autonomous AI red-teaming directly into an organisation's own infrastructure.*
>
> *Our AI generates adversarial tests, challenges business workflows, identifies security weaknesses, and validates defensive controls.*
>
> *And here is the important part: **we can do all of this without relying on an external AI inference service**.*
>
> *We believe the future of AI security assurance should be autonomous, continuous, and privately deployable."*

---

## License
MIT License. Built for the GB10 Hackathon.
