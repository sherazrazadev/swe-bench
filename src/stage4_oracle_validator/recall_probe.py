"""Recall probe: can the target models name the fix location from the REPORT ALONE?

No repo, no tools, no container - a single chat completion per model. If a model names a file or function the oracle patch
really changes, then either the report leaks the location or the model remembers the project/fix from training. Either way
localization is trivially cheap for it, and the task is likely to come back "too easy" after expensive container runs.

The probe is advisory by default (recorded in the knowledge base and results.md so the generator learns which report styles
leak); `--probe-reject` turns a hit on BOTH models into a rejection.
"""
from __future__ import annotations

import json
import logging
import re
from pathlib import Path, PurePosixPath
from typing import Any

import requests

from src.common.classify import is_test_path
from src.common.config import ModelEndpoint

log = logging.getLogger(__name__)

PROMPT = """\
Below is a vulnerability report for an open-source project. You have NO access to the code. Using only your own knowledge of \
the project and of this kind of bug, state where the root cause most likely lives.

Reply with ONLY a JSON object: {{"files": ["<repo-relative file paths, best guesses>"], "functions": ["<function/class names>"], \
"fix_summary": "<one or two sentences>"}}. If you do not recognise the project, still give your best guess.

# Report
{report}
"""


def patch_targets(patch: str) -> tuple[set[str], set[str]]:
    """(file basenames, function/class names) the oracle patch touches, tests excluded."""
    files, funcs = set(), set()
    for chunk in re.split(r"(?m)^(?=diff --git )", patch):
        m = re.match(r"diff --git a/.+? b/(.+)", chunk)
        if not m or is_test_path(m.group(1)):
            continue
        files.add(PurePosixPath(m.group(1)).name.lower())
        for h in re.findall(r"(?m)^@@[^@]*@@\s*(.*)$", chunk):
            for name in re.findall(r"(?:def|class|function)\s+([A-Za-z_]\w+)", h):
                funcs.add(name.lower())
    return files, funcs


def _ask(ep: ModelEndpoint, report: str) -> str:
    if not ep.check_url:
        return ""
    model = ep.model.split("/")[-1]
    r = requests.post(f"{ep.check_url}/chat/completions", timeout=180,
                      headers={"Authorization": f"Bearer {ep.api_key}", "Content-Type": "application/json"},
                      json={"model": model, "messages": [{"role": "user", "content": PROMPT.format(report=report)}],
                            "max_tokens": 3000})
    r.raise_for_status()
    msg = (r.json().get("choices") or [{}])[0].get("message") or {}
    return msg.get("content") or ""


def probe(env_dir: Path, endpoints: list[ModelEndpoint]) -> dict[str, Any]:
    patch = (env_dir / "oracle_solution.patch").read_text(encoding="utf-8", errors="replace")
    files, funcs = patch_targets(patch)
    report = (env_dir / "instruction.md").read_text()
    result: dict[str, Any] = {"targets": {"files": sorted(files), "functions": sorted(funcs)}, "models": {}}
    for ep in endpoints:
        try:
            answer = _ask(ep, report)
        except (requests.RequestException, ValueError) as e:
            result["models"][ep.tag] = {"error": str(e)[:200]}
            continue
        low = answer.lower()
        file_hit = sorted(f for f in files if f in low)
        func_hit = sorted(fn for fn in funcs if len(fn) >= 5 and re.search(rf"\b{re.escape(fn)}\b", low))
        result["models"][ep.tag] = {"file_hit": file_hit, "func_hit": func_hit, "answer": answer[:600]}
    hits = [t for t, v in result["models"].items() if v.get("file_hit")]
    result["risk"] = "high" if len(hits) == len(endpoints) and hits else ("medium" if hits else "low")
    (env_dir / "recall_probe.json").write_text(json.dumps(result, indent=2))
    return result
