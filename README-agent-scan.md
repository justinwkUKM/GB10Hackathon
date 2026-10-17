# Agent application scan planner

`agent_scan.py` accepts a running HTTP(S) endpoint, a local source checkout, or a GitHub repository URL. It classifies what it can observe, chooses compatible checks, and explains what it skipped. Planning is offline and does not contact the supplied URL or clone a repository.

## Plan first

```bash
python3 agent_scan.py plan https://your-agent.example/v1/chat/completions
python3 agent_scan.py plan https://github.com/org/agent-repo
python3 agent_scan.py plan /path/to/local/checkout --json
```

For a repository, the planner reads source and dependency manifests. It looks for agent frameworks, HTTP routes, OpenAI-compatible chat surfaces, MCP, and A2A. It chooses local credential-pattern and risky-code checks, inventories dependencies, and records runtime or package audits as skipped when they need a running service, extra configuration, or external package registries.

For a URL, it infers the interface from the path. It chooses bounded chat checks only for an OpenAI-compatible `/v1/chat/completions` endpoint. A generic URL gets a small HTTP surface check; the planner skips model prompts because it cannot identify a chat API.

## Run

```bash
# Static checks against an existing checkout; no app is started.
python3 agent_scan.py scan /path/to/local/checkout

# Remote repository: shallow-clones to a temporary directory, then runs static checks.
python3 agent_scan.py scan https://github.com/org/agent-repo --authorized

# URL scan: remote targets need explicit authorization. Localhost does not.
python3 agent_scan.py scan http://127.0.0.1:8000/v1/chat/completions
python3 agent_scan.py scan https://your-agent.example/v1/chat/completions --authorized

# Private OpenAI-compatible endpoint: keep the key in the environment.
export AGENT_API_KEY='...'
python3 agent_scan.py scan https://your-agent.example/v1/chat/completions \
  --authorized --api-key-env AGENT_API_KEY --model your-model
```

Reports are written as timestamped Markdown and JSON under `agent-scan-results/`. Credential values are not included in static findings. Remote Git checkouts are shallow and temporary. The runner never builds or launches repository code and never runs package-manager audits by default. URL scans send a GET to the exact supplied URL; for a recognized chat-completion route they also send two bounded prompts. Use only against systems you are authorized to assess.

## Current coverage

The built-in repository scan checks likely hard-coded credentials and a small set of risky code patterns, and lists dependency manifests. These are heuristics, so findings need review and a clean result does not establish that code is secure. The built-in URL scan checks reachability and common response security headers; compatible chat endpoints also get an instruction-override canary and a prompt-disclosure request. The disclosure check needs the expected system prompt for confirmation.

The planner detects whether Garak, Promptfoo, and Semgrep executables are installed and reports when a scanner is missing or when a compatible runtime/configuration is not known. It does not silently invoke these larger suites. This first version is a safe triage layer; use the plan to decide whether to add tool-specific configuration for deeper Garak, Promptfoo, MCP/A2A, or dependency-vulnerability scans.

Run its offline unit tests with:

```bash
python3 -m unittest -v test_agent_scan.py
```
