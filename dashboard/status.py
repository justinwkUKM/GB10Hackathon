#!/usr/bin/env python3
"""Maintains dashboard/status.json as the controller advances a run.

Subcommands (all operate on the file given by --file, default dashboard/status.json):
  init      --run-id --repo --runtime --stages a,b,c
  stage     NAME STATE            (pending|active|done|fail)
  isolation NAME OK               (OK = true/false)
  agent     ID LEVEL STATE        (--findings N --score N --report FILE)
  finalize  --score N --report FILE
Writes atomically so the polling page never reads a half-written file.
"""
import argparse
import json
import os
import sys
import time

DEFAULT = os.path.join(os.path.dirname(__file__), "status.json")


def load(path):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save(path, data):
    tmp = f"{path}.tmp"
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def elapsed(data):
    return round(time.time() - data.get("_started", time.time()), 1)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", default=DEFAULT)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init")
    p.add_argument("--run-id", required=True)
    p.add_argument("--repo", default="")
    p.add_argument("--runtime", default="")
    p.add_argument("--stages", required=True)

    p = sub.add_parser("stage")
    p.add_argument("name")
    p.add_argument("state")

    p = sub.add_parser("isolation")
    p.add_argument("name")
    p.add_argument("ok")

    p = sub.add_parser("agent")
    p.add_argument("id")
    p.add_argument("level")
    p.add_argument("state")
    p.add_argument("--findings", type=int)
    p.add_argument("--score", type=int)
    p.add_argument("--report")

    p = sub.add_parser("finalize")
    p.add_argument("--score", type=int)
    p.add_argument("--report")

    a = ap.parse_args()
    data = load(a.file)

    if a.cmd == "init":
        data = {
            "run_id": a.run_id,
            "repo": a.repo,
            "runtime": a.runtime,
            "started": time.strftime("%Y-%m-%d %H:%M:%S"),
            "_started": time.time(),
            "stages": [{"name": s, "state": "pending", "t": None} for s in a.stages.split(",")],
            "isolation": [],
            "agents": [],
            "score": None,
            "findings": [],
            "done": False,
        }
    elif a.cmd == "stage":
        for s in data.get("stages", []):
            if s["name"] == a.name:
                s["state"] = a.state
                s["t"] = elapsed(data)
    elif a.cmd == "isolation":
        ok = a.ok.lower() in ("1", "true", "yes", "ok")
        row = next((r for r in data["isolation"] if r["name"] == a.name), None)
        if row:
            row["ok"] = ok
        else:
            data["isolation"].append({"name": a.name, "ok": ok})
    elif a.cmd == "agent":
        row = next((r for r in data["agents"] if r["id"] == a.id), None)
        if not row:
            row = {"id": a.id, "level": a.level, "state": a.state, "findings": None, "score": None}
            data["agents"].append(row)
        row["state"] = a.state
        row["level"] = a.level
        if a.findings is not None:
            row["findings"] = a.findings
        if a.score is not None:
            row["score"] = a.score
        if a.report and os.path.exists(a.report):
            rep = load(a.report)
            row["findings"] = len(rep.get("findings", []))
            row["score"] = rep.get("resiliencyScore")
            # Carry each finding up to the top-level list for the report panel.
            for fdg in rep.get("findings", []):
                data["findings"].append({
                    "agent": a.id,
                    "severity": fdg.get("severity"),
                    "goal": fdg.get("goal"),
                    "verifier": fdg.get("verdict", {}).get("verifier"),
                    "signal": fdg.get("verdict", {}).get("signal"),
                    "mapping": fdg.get("mapping"),
                })
    elif a.cmd == "finalize":
        if a.score is not None:
            data["score"] = a.score
        data["done"] = True

    save(a.file, data)


if __name__ == "__main__":
    main()
