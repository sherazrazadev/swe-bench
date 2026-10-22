"""Plan probe: a cheap pre-trial check that skips tasks the target models would find easy.

DeepSeek and MiMo each get the task's report plus the repository's source-file LIST (no contents) and name every file
they would change to fix the problem completely. If the fix spans >= 2 places and BOTH models already name at least half
of them, nothing is hidden and the task is predicted easy.

Backtest on the 32 measurable evaluated tasks (data/logs/runs/2026-10-20_1359_plan-probe-backtest): this rule would have
skipped 18 of 27 solved tasks (66%) and kept all 5 measurable breakers (AUC 0.70). The ">= 2 places" condition was added
after seeing fast-jwt x937 (one-file fix, trap inside the file - a file list cannot reveal it): treat it as fitted on
little data. Safety valves:
  * fail open - an error, an empty answer or an oversized file list means the trial runs;
  * audit - every AUDIT_EVERY-th predicted-easy task still goes to the trial, so the gate keeps measuring what it drops;
  * PLAN_PROBE=off | advisory (record only) | gate (default).
Only the target models' own APIs are called, never Claude.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any, Optional

import requests

from src.common.classify import classify
from src.common.llm import extract_json_object

MAX_LIST_CHARS = 60_000
MIN_PLACES = 2
COVERAGE_THRESHOLD = float(os.environ.get("PLAN_PROBE_THRESHOLD", "0.5"))
AUDIT_EVERY = int(os.environ.get("PLAN_PROBE_AUDIT_EVERY", "4"))
SKIP_DIRS = {".git", "node_modules", "vendor", "dist", "build", ".venv", "third_party"}
NON_SOURCE = re.compile(r"(^|/)(tests?|__tests__|spec|fixtures?|docs?|examples?|testdata)/|[._-](test|spec)\.|"
                        r"\.(md|rst|txt|json|ya?ml|toml|lock|snap)$|(^|/)CHANGELOG|\.d\.ts$", re.I)

PROMPT = """\
You are about to repair a security vulnerability in an open-source project. You cannot read any file contents yet. From the
report and the list of the project's source files below, decide which files you will open and change so that the
vulnerability is fixed COMPLETELY - every place where the root cause lives, not only the place the report shows.

Reply with ONLY a JSON object: {{"files": ["<repo-relative paths copied exactly from the list>"], "plan": "<2-4 sentences>"}}

# Report
{report}

# Source files ({n} files)
{files}
"""


def source_files(repo: Path, eco: str) -> list[str]:
    out = []
    for root, dirs, fs in os.walk(repo):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
        for f in fs:
            rel = os.path.relpath(os.path.join(root, f), repo)
            if classify(rel, eco) == "source":
                out.append(rel)
    return sorted(out)


def fix_places(env: Path, existing: set[str]) -> list[str]:
    try:
        declared = json.loads((env / "task_metadata.json").read_text()).get("fix_places") or []
    except (OSError, ValueError):
        declared = []
    if not declared:
        patch = (env / "oracle_solution.patch").read_text(errors="replace")
        declared = [m for m in re.findall(r"(?m)^diff --git a/\S+ b/(\S+)", patch) if not NON_SOURCE.search(m)]
    return sorted({p for p in declared if p in existing})     # a file the fix creates cannot be named in advance


def ask(ep, prompt: str) -> str:
    r = requests.post(f"{ep.check_url}/chat/completions", timeout=900,
                      headers={"Authorization": f"Bearer {ep.api_key}", "Content-Type": "application/json"},
                      # reasoning models spend the budget on thinking first: 8000 left DeepSeek's answer empty on 29/33
                      json={"model": ep.model.split("/")[-1], "max_tokens": int(os.environ.get("PROBE_MAX_TOKENS", "64000")),
                            "messages": [{"role": "user", "content": prompt}]})
    r.raise_for_status()
    content = ((r.json().get("choices") or [{}])[0].get("message") or {}).get("content") or ""
    if not content.strip():       # an empty answer is a failed measurement, never "0% coverage"
        raise ValueError("empty answer (token budget used up by reasoning?)")
    return content


def coverage(answer: str, places: list[str]) -> tuple[float, list[str]]:
    try:
        named = [str(f).strip().lstrip("./") for f in extract_json_object(answer).get("files") or []]
    except ValueError:
        named = re.findall(r"[\w./-]+\.\w+", answer)
    hit = [p for p in places if any(n == p or n.endswith("/" + p) or p.endswith("/" + n) for n in named)]
    return (len(hit) / len(places) if places else 0.0), hit


def decide(env_dir: Path, ecosystem: str, endpoints: list) -> dict[str, Any]:
    """-> {"verdict": "skip" | "trial" | "audit" | "n/a", "why": ..., "models": {...}}; written to plan_probe.json."""
    out: dict[str, Any] = {"verdict": "n/a", "threshold": COVERAGE_THRESHOLD, "models": {}}
    eps = [ep for ep in endpoints if ep.check_url]
    files = source_files(env_dir / "repo", ecosystem) if (env_dir / "repo").is_dir() else []
    listing = "\n".join(files)
    places = fix_places(env_dir, set(files))
    out["places"] = places
    if not eps or not files:
        out["why"] = "no endpoints or no repo"
    elif len(listing) > MAX_LIST_CHARS:
        out["why"] = f"file list {len(listing)} chars > {MAX_LIST_CHARS} (not measured)"
    elif len(places) < MIN_PLACES:
        out["why"] = f"{len(places)} fix place(s): a file list cannot reveal a trap inside one file"
    else:
        prompt = PROMPT.format(report=(env_dir / "instruction.md").read_text(), n=len(files), files=listing)
        for ep in eps:
            try:
                cov, hit = coverage(ask(ep, prompt), places)
                out["models"][ep.tag] = {"coverage": round(cov, 3), "hit": hit}
            except Exception as e:    # fail open: an unmeasured model never predicts "easy"
                out["models"][ep.tag] = {"error": repr(e)[:200]}
        covs = [m["coverage"] for m in out["models"].values() if "coverage" in m]
        if len(covs) < len(eps):
            out["verdict"], out["why"] = "trial", "a model gave no usable answer (fail open)"
        elif min(covs) >= COVERAGE_THRESHOLD:
            audit = int(hashlib.sha1(env_dir.name.encode()).hexdigest(), 16) % AUDIT_EVERY == 0
            out["verdict"] = "audit" if audit else "skip"
            out["why"] = (f"both models named >= {COVERAGE_THRESHOLD:.0%} of the {len(places)} fix places "
                          f"(min {min(covs):.0%})" + (" - audit sample, trial runs anyway" if audit else ""))
        else:
            out["verdict"], out["why"] = "trial", f"a model named only {min(covs):.0%} of the {len(places)} fix places"
    (env_dir / "plan_probe.json").write_text(json.dumps(out, indent=2))
    return out


def mode() -> str:
    return os.environ.get("PLAN_PROBE", "gate").strip().lower()
