# Agent application scan planner

`agent_scan.py` accepts a running HTTP(S) endpoint, a local source checkout, or a GitHub repository URL. It classifies observable interfaces, selects active checks, and reports any remaining setup gaps. Planning is offline and does not contact the supplied URL or clone a repository.

## Plan first

```bash
python3 agent_scan.py plan https://your-agent.example/v1/chat/completions
python3 agent_scan.py plan https://github.com/org/agent-repo
python3 agent_scan.py plan /path/to/local/checkout --json
```

For a repository, the planner reads source and dependency manifests. It looks for agent frameworks, HTTP routes, OpenAI-compatible chat surfaces, MCP, and A2A. It chooses local credential-pattern and risky-code checks and inventories dependencies. The preconfigured local DVAA checkout additionally runs its full offline training-lab workflow, including the runtime matrix, Promptfoo, Garak, MCP, and A2A tests. Other repositories are not launched automatically.

For a URL, it checks the HTTP surface, probes the target and common MCP paths with read-only JSON-RPC discovery and inventory requests, and checks the standard A2A Agent Card locations. If an A2A card is found, it may send a harmless lookup for a random nonexistent task ID to the same origin. It sends chat prompts only when the supplied URL identifies an OpenAI-compatible chat endpoint. These generic URL checks are bounded protocol discovery checks; they are not a replacement for a target-specific Garak or Promptfoo provider configuration.

## Run

```bash
# Static checks against a repository; ordinary project code is not started.
python3 agent_scan.py scan /path/to/local/checkout

# Full offline suite for the preconfigured DVAA training lab.
python3 agent_scan.py scan .targets/dvaa

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

Reports are written as timestamped Markdown and JSON under `agent-scan-results/`. Credential values are not included in static findings or copied into the dashboard's protocol summaries. Remote Git checkouts are shallow and temporary. Runtime execution is restricted to the known local DVAA training checkout; arbitrary repository code is not launched. URL scans send bounded HTTP, MCP, and A2A discovery requests. A recognized chat-completion route also receives two prompt probes. Use only against systems you are authorized to assess.

## Current coverage

The built-in repository scan checks likely hard-coded credentials and a small set of risky code patterns, and lists dependency manifests. These are heuristics, so findings need review and a clean result does not establish that code is secure. The URL scan checks reachability and common response security headers, actively discovers MCP and A2A surfaces, and tests compatible chat endpoints with an instruction-override canary and a prompt-disclosure request. The disclosure check needs the expected system prompt for confirmation.

The known DVAA workflow runs Garak and Promptfoo with the lab's supplied configurations and executes 18 local MCP/A2A checks. Other targets get the native protocol checks; Garak and Promptfoo remain listed as needing target-specific provider configuration when their request format or model is unknown. Dependency vulnerability audits and Semgrep remain separately configured checks.

Run its offline unit tests with:

```bash
python3 -m unittest -v test_agent_scan.py
```

## Web UI

Start the loopback-only local UI with:

```bash
python3 agent_scan_ui.py
```

Then open <http://127.0.0.1:8765>. Paste a target and build the plan before running it. The report dashboard charts findings by severity and rule, shows MCP/A2A test outcomes and DVAA suite counts, and lists any remaining gaps. Recent saved reports can be reopened in the dashboard. It also links to the Markdown and JSON reports. The UI accepts only an API-key environment-variable name; set the actual key in the shell before starting the UI if the target requires one. Remote scans require checking the authorization box. Stop the server with Ctrl+C.
