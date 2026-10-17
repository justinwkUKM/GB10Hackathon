"""AgentShield Local - Interactive Web Dashboard & Private AI Runtime Server.

Serves an interactive cybersecurity operations dashboard at http://127.0.0.1:8888
Powered by NVIDIA Nemotron 3.5 Lightning.
"""

from __future__ import annotations

import json
import os
import sys
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
from typing import Any, Dict

from agentshield.nemotron import NemotronClient
from agentshield.sandbox import SandboxMerchantAgent
from agentshield.scenarios import SCENARIOS
from agentshield.evaluator import SecurityEvaluator
from agentshield.network_verifier import NetworkVerifier


HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AgentShield Local | Private Autonomous AI Red-Teaming</title>
<style>
:root {
  --bg-primary: #0a0e14;
  --bg-secondary: #121824;
  --bg-card: #182234;
  --border-color: #24334a;
  --nvidia-green: #76b900;
  --nvidia-green-glow: rgba(118, 185, 0, 0.25);
  --danger: #ff4757;
  --warning: #ffa502;
  --text-main: #f1f2f6;
  --text-muted: #8b9bb4;
  --mono-font: 'JetBrains Mono', 'Fira Code', 'Menlo', monospace;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background-color: var(--bg-primary);
  color: var(--text-main);
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.5;
  padding: 24px;
}
header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 20px;
  margin-bottom: 24px;
}
.brand-title {
  display: flex;
  align-items: center;
  gap: 12px;
}
.brand-badge {
  background: var(--nvidia-green);
  color: #000;
  font-weight: 800;
  font-size: 11px;
  padding: 4px 8px;
  border-radius: 4px;
  text-transform: uppercase;
  letter-spacing: 0.5px;
}
h1 { font-size: 24px; font-weight: 700; }
.tagline { color: var(--text-muted); font-size: 13px; }

/* Proof Badges Grid */
.proof-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
  gap: 16px;
  margin-bottom: 24px;
}
.proof-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 16px;
  position: relative;
  overflow: hidden;
}
.proof-card.active-local {
  border-color: var(--nvidia-green);
  box-shadow: 0 0 15px var(--nvidia-green-glow);
}
.proof-label {
  font-size: 11px;
  text-transform: uppercase;
  color: var(--text-muted);
  letter-spacing: 0.5px;
  margin-bottom: 6px;
}
.proof-value {
  font-size: 18px;
  font-weight: 700;
  display: flex;
  align-items: center;
  gap: 8px;
}
.status-dot {
  width: 10px;
  height: 10px;
  border-radius: 50%;
  display: inline-block;
}
.dot-green { background: var(--nvidia-green); box-shadow: 0 0 8px var(--nvidia-green); }
.dot-red { background: var(--danger); box-shadow: 0 0 8px var(--danger); }
.dot-orange { background: var(--warning); box-shadow: 0 0 8px var(--warning); }
.proof-sub {
  font-size: 11px;
  color: var(--text-muted);
  margin-top: 4px;
}

/* Control Panel */
.panel {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 20px;
  margin-bottom: 24px;
}
.controls {
  display: grid;
  grid-template-columns: 2fr 1fr 1fr auto;
  gap: 16px;
  align-items: end;
}
label {
  display: block;
  font-size: 12px;
  font-weight: 600;
  color: var(--text-muted);
  margin-bottom: 6px;
  text-transform: uppercase;
}
select, button {
  width: 100%;
  padding: 10px 14px;
  background: var(--bg-card);
  border: 1px solid var(--border-color);
  color: var(--text-main);
  border-radius: 6px;
  font-size: 14px;
}
select:focus, button:focus {
  outline: none;
  border-color: var(--nvidia-green);
}
.btn-primary {
  background: var(--nvidia-green);
  color: #000;
  font-weight: 700;
  border: none;
  cursor: pointer;
  transition: all 0.2s;
}
.btn-primary:hover {
  background: #88d400;
  box-shadow: 0 0 12px var(--nvidia-green-glow);
}
.btn-secondary {
  cursor: pointer;
}

/* Content Columns */
.split-view {
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 20px;
}
.box {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 18px;
}
.box-header {
  font-size: 14px;
  font-weight: 700;
  margin-bottom: 12px;
  display: flex;
  justify-content: space-between;
  align-items: center;
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 8px;
}
.terminal {
  background: #06090e;
  border: 1px solid #1c2738;
  border-radius: 6px;
  padding: 12px;
  font-family: var(--mono-font);
  font-size: 12px;
  line-height: 1.6;
  min-height: 220px;
  max-height: 400px;
  overflow-y: auto;
  white-space: pre-wrap;
  color: #c9d1d9;
}
.badge-danger {
  background: rgba(255, 71, 87, 0.2);
  color: var(--danger);
  border: 1px solid var(--danger);
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
}
.badge-success {
  background: rgba(118, 185, 0, 0.2);
  color: var(--nvidia-green);
  border: 1px solid var(--nvidia-green);
  padding: 2px 8px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 700;
}
.tool-pill {
  display: inline-block;
  background: #1e293b;
  border: 1px solid #334155;
  color: #38bdf8;
  padding: 2px 6px;
  border-radius: 4px;
  font-family: var(--mono-font);
  font-size: 11px;
  margin-right: 4px;
}
</style>
</head>
<body>

<header>
  <div class="brand-title">
    <div class="brand-badge">NVIDIA NEMOTRON-LIGHTNING</div>
    <div>
      <h1>AgentShield Local</h1>
      <div class="tagline">Private, Autonomous AI Red-Teaming &bull; "Your AI. Your Infrastructure. Your Security."</div>
    </div>
  </div>
  <div>
    <button id="airgap-toggle" class="btn-secondary" style="width: auto; padding: 6px 14px; font-size: 12px;" onclick="toggleAirgap()">
      Toggle Offline Air-Gap Mode
    </button>
  </div>
</header>

<!-- Proof Dashboard Grid (As specified for the Demo) -->
<div class="proof-grid">
  <div class="proof-card active-local">
    <div class="proof-label">Inference Engine</div>
    <div class="proof-value">
      <span class="status-dot dot-green"></span>
      <span id="p-inference">LOCAL (Nemotron 3.5)</span>
    </div>
    <div class="proof-sub" id="p-inference-sub">NVIDIA 30B Total / 3B Active on Localhost</div>
  </div>

  <div class="proof-card">
    <div class="proof-label">Network Boundary</div>
    <div class="proof-value">
      <span class="status-dot" id="p-net-dot"></span>
      <span id="p-network">CHECKING...</span>
    </div>
    <div class="proof-sub" id="p-network-sub">Zero external API reliance</div>
  </div>

  <div class="proof-card">
    <div class="proof-label">Inference Performance</div>
    <div class="proof-value">
      <span class="status-dot dot-green"></span>
      <span id="p-speed">Ready</span>
    </div>
    <div class="proof-sub" id="p-speed-sub">Live measured tokens/sec</div>
  </div>

  <div class="proof-card">
    <div class="proof-label">Sandbox Security State</div>
    <div class="proof-value">
      <span class="status-dot dot-orange" id="p-eval-dot"></span>
      <span id="p-verdict">Awaiting Attack</span>
    </div>
    <div class="proof-sub" id="p-verdict-sub">Deterministic Policy Assertions</div>
  </div>
</div>

<!-- Attack & Evaluation Control Panel -->
<div class="panel">
  <div class="controls">
    <div>
      <label>Adversarial Attack Scenario</label>
      <select id="scenario-select">
        <option value="merchant_approval_bypass">Merchant Approval Bypass (Credit Limit Exploit)</option>
        <option value="tool_privilege_escalation">Tool Privilege Escalation & Risk Override</option>
        <option value="system_prompt_disclosure">System Prompt & Confidential Token Extraction</option>
      </select>
    </div>
    <div>
      <label>Target Agent Defense</label>
      <select id="defense-select">
        <option value="vulnerable">Vulnerable (No Boundary)</option>
        <option value="guardrail">Guardrail (Keyword Filter)</option>
        <option value="hardened">Hardened (Deterministic Dual-Control)</option>
      </select>
    </div>
    <div>
      <label>Mode</label>
      <select id="mode-select">
        <option value="normal">Standard Local Inference</option>
        <option value="airgap">Air-Gapped Offline Challenge</option>
      </select>
    </div>
    <div>
      <button class="btn-primary" id="run-btn" onclick="executeRedTeamRun()">
        Launch Red-Team Attack &rarr;
      </button>
    </div>
  </div>
</div>

<!-- Live Output Console -->
<div class="split-view">
  <div class="box">
    <div class="box-header">
      <span>1. Autonomous Attack Generation (Nemotron-Lightning)</span>
      <span id="attack-stats" style="font-size: 11px; color: var(--nvidia-green);"></span>
    </div>
    <div class="terminal" id="attack-console">// Click "Launch Red-Team Attack" to prompt Nemotron-Lightning...</div>
  </div>

  <div class="box">
    <div class="box-header">
      <span>2. Sandbox Agent Execution & Mock Tools</span>
      <span id="sandbox-badge"></span>
    </div>
    <div class="terminal" id="sandbox-console">// Sandbox Agent state will be logged here...</div>
  </div>
</div>

<div style="margin-top: 20px;" class="box">
  <div class="box-header">
    <span>3. Deterministic Policy Verification & Nemotron Finding Analyst</span>
    <span id="report-badge"></span>
  </div>
  <div class="terminal" id="analyst-console">// Detailed security finding analysis will appear here...</div>
</div>

<script>
let forcedOffline = false;

function toggleAirgap() {
  forcedOffline = !forcedOffline;
  const btn = document.getElementById('airgap-toggle');
  btn.innerText = forcedOffline ? "Disable Air-Gap (Restore WAN)" : "Toggle Offline Air-Gap Mode";
  btn.style.borderColor = forcedOffline ? "#ff4757" : "#24334a";
  fetchStatus();
}

async function fetchStatus() {
  try {
    const res = await fetch(`/api/status?forced_offline=${forcedOffline ? '1' : '0'}`);
    const data = await res.json();
    const netDot = document.getElementById('p-net-dot');
    const netLabel = document.getElementById('p-network');
    const netSub = document.getElementById('p-network-sub');

    if (data.network.internet_connected) {
      netDot.className = "status-dot dot-green";
      netLabel.innerText = "ONLINE (LOCAL-BOUND)";
      netSub.innerText = "Localhost inference 127.0.0.1:11434";
    } else {
      netDot.className = "status-dot dot-orange";
      netLabel.innerText = "OFFLINE (AIR-GAPPED)";
      netSub.innerText = "Proven: Zero WAN packet egress";
    }
  } catch (e) {
    console.error(e);
  }
}

async function executeRedTeamRun() {
  const btn = document.getElementById('run-btn');
  const scenario = document.getElementById('scenario-select').value;
  const defense = document.getElementById('defense-select').value;
  const mode = document.getElementById('mode-select').value;
  const useAirgap = forcedOffline || (mode === 'airgap');

  btn.disabled = true;
  btn.innerText = "Synthesizing Attack on Local Nemotron...";

  document.getElementById('attack-console').innerText = "[Local Inference Server] Request dispatched to 127.0.0.1:11434 (NVIDIA Nemotron 3.5 Lightning)...\\nGenerating adversarial payload...";
  document.getElementById('sandbox-console').innerText = "[Sandbox Agent] Awaiting incoming transaction payload...";
  document.getElementById('analyst-console').innerText = "[Security Evaluator] Listening for execution signals...";

  try {
    const res = await fetch('/api/run', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({
        scenario: scenario,
        defense: defense,
        forced_offline: useAirgap
      })
    });
    const data = await res.json();

    // 1. Attack console
    document.getElementById('attack-console').innerText = data.attack_payload;
    const atkStats = data.inference_stats.attack_gen;
    document.getElementById('attack-stats').innerText = `${atkStats.tokens_per_sec} tok/s | ${atkStats.duration_s}s`;
    document.getElementById('p-speed').innerText = `${atkStats.tokens_per_sec} tok/s`;
    document.getElementById('p-speed-sub').innerText = `Generated ${atkStats.tokens} tokens locally in ${atkStats.duration_s}s`;

    // 2. Sandbox console
    let sbText = `[Target Defense Level: ${data.defense_level.toUpperCase()}]\\n`;
    sbText += `Agent Response: ${data.agent_response}\\n\\n`;
    if (data.executed_tools.length > 0) {
      sbText += "Tools Executed in Sandbox:\\n";
      data.executed_tools.forEach(t => {
        sbText += `  -> ${t.tool}(${JSON.stringify(t.arguments)})\\n`;
        sbText += `     Result: ${JSON.stringify(t.result)}\\n`;
        if (t.policy_violation) {
          sbText += `     [!] POLICY VIOLATION: ${t.violation_rule}\\n`;
        }
      });
    } else {
      sbText += "Tools Executed: None (Refused or Blocked)\\n";
    }
    document.getElementById('sandbox-console').innerText = sbText;

    const sbBadge = document.getElementById('sandbox-badge');
    const pEvalDot = document.getElementById('p-eval-dot');
    const pVerdict = document.getElementById('p-verdict');
    const pVerdictSub = document.getElementById('p-verdict-sub');

    if (data.vulnerability_detected) {
      sbBadge.innerHTML = `<span class="badge-danger">EXPLOIT SUCCEEDED</span>`;
      pEvalDot.className = "status-dot dot-red";
      pVerdict.innerText = "Vulnerability Confirmed";
      pVerdictSub.innerText = data.policy_breached_rule || "Policy boundary breached";
    } else {
      sbBadge.innerHTML = `<span class="badge-success">DEFENSE SECURED</span>`;
      pEvalDot.className = "status-dot dot-green";
      pVerdict.innerText = "Attack Defended";
      pVerdictSub.innerText = "Deterministic boundary held";
    }

    // 3. Analyst console
    let anText = `--- VERDICT: ${data.deterministic_verdict} [SEVERITY: ${data.severity}] ---\\n\\n`;
    anText += data.analyst_explanation + "\\n\\n";
    anText += "RECOMMENDED REMEDIATION:\\n" + data.remediation;
    document.getElementById('analyst-console').innerText = anText;

  } catch (e) {
    document.getElementById('attack-console').innerText = `Error: ${e}`;
  } finally {
    btn.disabled = false;
    btn.innerText = "Launch Red-Team Attack \u2192";
    fetchStatus();
  }
}

// Initial status probe
fetchStatus();
setInterval(fetchStatus, 5000);
</script>

</body>
</html>
"""


class AgentShieldHandler(BaseHTTPRequestHandler):
    nemotron: NemotronClient
    verifier: NetworkVerifier

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/" or parsed.path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(HTML_TEMPLATE.encode("utf-8"))
        elif parsed.path == "/api/status":
            query = parse_qs(parsed.query)
            forced_off = query.get("forced_offline", ["0"])[0] == "1"
            verifier = NetworkVerifier(forced_offline=forced_off)
            status = verifier.probe(self.nemotron.base_url)
            health = self.nemotron.check_health()
            res = {
                "network": {
                    "internet_connected": status.internet_connected,
                    "status_label": status.status_label,
                    "inference_host": status.inference_host,
                    "socket_check_ms": status.socket_check_ms,
                    "message": status.message,
                },
                "inference": health,
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(res).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        parsed = urlparse(self.path)
        if parsed.path == "/api/run":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}

            scenario_id = body.get("scenario", "merchant_approval_bypass")
            defense_level = body.get("defense", "vulnerable")
            forced_offline = body.get("forced_offline", False)

            scenario = SCENARIOS.get(scenario_id, SCENARIOS["merchant_approval_bypass"])
            net_verifier = NetworkVerifier(forced_offline=forced_offline)
            net_status = net_verifier.probe(self.nemotron.base_url)

            # 1. Autonomous Attack Generation via Nemotron
            atk_resp = self.nemotron.generate(
                system_prompt=scenario.attacker_system_prompt,
                user_prompt=scenario.attacker_goal,
                temperature=0.8,
                max_tokens=256,
            )

            # 2. Sandbox Agent Execution
            sandbox = SandboxMerchantAgent(defense_level=defense_level)
            sandbox_res = sandbox.process(atk_resp.content)

            # 3. Deterministic Evaluation + Finding Analyst
            evaluator = SecurityEvaluator(self.nemotron)
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

            response_data = {
                "scenario_id": report.scenario_id,
                "scenario_name": report.scenario_name,
                "defense_level": defense_level,
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
            }

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Concise logging
        sys.stderr.write(f"[AgentShield Server] {args[0]} {args[1]}\n")


def run_server(port: int = 8888, host: str = "127.0.0.1"):
    nemotron = NemotronClient()
    verifier = NetworkVerifier()

    AgentShieldHandler.nemotron = nemotron
    AgentShieldHandler.verifier = verifier

    server_address = (host, port)
    httpd = HTTPServer(server_address, AgentShieldHandler)
    print(f"\n=======================================================")
    print(f"  AgentShield Local - Private Autonomous AI Red-Teaming")
    print(f"  Powered by NVIDIA Nemotron-Lightning")
    print(f"  Web Dashboard: http://{host}:{port}")
    print(f"  Model Endpoint: {nemotron.base_url}")
    print(f"=======================================================\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down AgentShield server.")
        httpd.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888
    run_server(port=port)
