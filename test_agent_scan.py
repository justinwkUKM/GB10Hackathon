import tempfile
import unittest
from pathlib import Path

import agent_scan


class PlannerTests(unittest.TestCase):
    def test_openai_chat_url_selects_bounded_chat_checks(self):
        plan = agent_scan.plan_for_url("https://example.test/v1/chat/completions", {"garak": None, "promptfoo": None})
        selected = {item["id"] for item in plan["selected"]}
        skipped = {item["id"] for item in plan["skipped"]}
        self.assertIn("bounded-chat-safety", selected)
        self.assertIn("mcp-discovery", selected)
        self.assertIn("a2a-discovery", selected)
        self.assertIn("garak", skipped)
        self.assertIn("promptfoo", skipped)

    def test_generic_url_does_not_select_model_prompts(self):
        plan = agent_scan.plan_for_url("https://example.test/", {"garak": None, "promptfoo": None})
        self.assertNotIn("bounded-chat-safety", {item["id"] for item in plan["selected"]})
        self.assertTrue(any(item["id"] == "llm-redteam" for item in plan["skipped"]))
        self.assertIn("mcp-discovery", {item["id"] for item in plan["selected"]})
        self.assertIn("a2a-discovery", {item["id"] for item in plan["selected"]})

    def test_preconfigured_dvaa_plan_runs_protocol_and_runtime_suite(self):
        root = Path(agent_scan.__file__).resolve().parent / ".targets" / "dvaa"
        if not root.is_dir():
            self.skipTest("preconfigured DVAA checkout is absent")
        plan, info = agent_scan.plan_for_repo(root, str(root), {"semgrep": None})
        selected = {item["id"] for item in plan["selected"]}
        skipped = {item["id"] for item in plan["skipped"]}
        self.assertTrue(info["dvaa"])
        self.assertIn("dvaa-exhaustive-suite", selected)
        self.assertNotIn("runtime-redteam", skipped)
        self.assertNotIn("mcp-protocol-tests", skipped)
        self.assertNotIn("a2a-protocol-tests", skipped)

    def test_repo_planner_detects_agent_surface_and_secret_redacts_value(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("fastapi\nlangchain\n")
            (root / "app.py").write_text(
                'import subprocess\nAPI_KEY = "sk_test_123456789abcdef"\n'
                'subprocess.run(command, shell=True)\n'
                'from fastmcp import FastMCP\n'
            )
            plan, info = agent_scan.plan_for_repo(root, str(root), {"semgrep": None})
            findings = agent_scan.scan_repository(root, str(root), info)
        self.assertIn("agent-framework", plan["signals"])
        self.assertIn("mcp", plan["signals"])
        self.assertIn("dependency-inventory", {item["id"] for item in plan["selected"]})
        self.assertIn("possible-hard-coded-secret", {item["rule"] for item in findings})
        self.assertIn("shell-true", {item["rule"] for item in findings})
        self.assertNotIn("sk_test_123456789abcdef", str(findings))

    def test_github_repo_url_is_identified_as_repository(self):
        self.assertTrue(agent_scan.is_github_repo_url("https://github.com/acme/agent-app"))
        self.assertFalse(agent_scan.is_github_repo_url("https://github.com/acme/agent-app/tree/main"))

    def test_report_target_redacts_secret_query_parameters(self):
        target = agent_scan.display_target("https://example.test/chat?api_key=private&tenant=demo")
        self.assertIn("api_key=%5BREDACTED%5D", target)
        self.assertIn("tenant=demo", target)
        self.assertNotIn("private", target)


if __name__ == "__main__":
    unittest.main()
