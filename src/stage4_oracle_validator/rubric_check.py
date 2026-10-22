"""Task rubric check: an LLM review of a generated task BEFORE any Docker time or model budget is spent.

A failure of a target model only counts if the task passes this rubric (see skills/adversarial_research.md).
The reviewer sees the instruction, hidden tests, oracle patch and entry point and answers each criterion
pass/fail with a reason. CRITICAL criteria must all pass.

Caveat: the reviewer is the same model family as the author. It catches mechanical defects well; it is a filter, not
a proof. Trial analysis (stage 5) and a human spot-check of accepted tasks are the second and third lines.
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass
from pathlib import Path

from src.common.llm import CliBackend, extract_json_object
from src.stage6_packager.harbor_packager import split_patch_without_tests

log = logging.getLogger(__name__)

# name -> (critical?, description)
CRITERIA: dict[str, tuple[bool, str]] = {
    "no_hints": (True, "instruction.md names no file, module, path, line number, or function/class the fix changes AND does "
                       "not prescribe the fix: an 'expected behaviour' part may state the security property and the legitimate "
                       "behaviour to keep, but must not describe validation rules, accepted token formats, ordering of checks, "
                       "or logging-vs-returning choices that amount to the fix design"),
    "accurate_report": (True, "the report describes the vulnerability the oracle patch actually fixes (impact + how it is "
                              "triggered), without inventing a different flaw"),
    "solvable_from_report": (True, "a skilled engineer who reads the report and the code could determine every behaviour the "
                                   "hidden tests require; no test demands undisclosed or arbitrary behaviour"),
    "real_entry_point": (True, "security tests reach the bug through a real entry point (public API/route/CLI), not by "
                               "calling the internal function the patch edits"),
    "variants_share_root_cause": (True, "extra exploit variants share the root cause and are all blocked by the oracle patch "
                                        "(no extra hardening the oracle does not provide)"),
    "implementation_agnostic": (True, "tests never import/assert anything the patch adds, never assert exact error text, and "
                                      "accept any reasonable way of blocking the attack"),
    "functional_meaningful": (True, "functional tests would FAIL if the feature were removed, disabled or over-blocked, yet "
                                    "pass on the vulnerable code"),
    "deterministic_offline": (True, "no network, no timing/sleep-based races, no randomness that can flip a result"),
    "realistic": (True, "the scenario is a realistic use of the project, not a contrived snippet or unreachable code"),
    "security_not_trivial_config": (True, "the vulnerability is in program logic, not a dependency bump or config toggle"),
}

PROMPT = """\
You are a strict reviewer of tasks in a security-fix benchmark. An AI agent will receive ONLY the report (instruction.md) and
the vulnerable repository, must fix the vulnerability, and is graded by the hidden tests. The oracle patch is the historical
human fix and must pass every test. Judge the task, not the code style.

# instruction.md (given to the agent)
{instruction}

# hidden_tests.py (never shown to the agent)
```python
{tests}
```

# Oracle patch (source files only)
```diff
{patch}
```

# Declared entry point (internal metadata)
{entry_point}

# Criteria (answer each; "critical" ones must all pass)
{criteria}

Respond with ONLY a JSON object:
{{"criteria": {{"<name>": {{"pass": true|false, "reason": "<one or two sentences, cite the offending text if failing>"}}, ...}},
  "blocking_issues": ["<short issue>", ...]}}
"""


@dataclass
class RubricResult:
    passed: bool
    criteria: dict[str, dict]
    blocking_issues: list[str]


def evaluate_reply(reply: dict) -> RubricResult:
    got = reply.get("criteria", {})
    blocking = list(reply.get("blocking_issues") or [])
    passed = True
    for name, (critical, _) in CRITERIA.items():
        entry = got.get(name)
        if not isinstance(entry, dict) or "pass" not in entry:
            if critical:
                passed = False
                blocking.append(f"{name}: not answered by reviewer")
            continue
        if critical and not entry["pass"]:
            passed = False
            blocking.append(f"{name}: {entry.get('reason', '')}")
    return RubricResult(passed, got, blocking)


def _verdict(text: str) -> dict:
    """A reply that answers none of the criteria is a reviewer malfunction, not a rejection: it must not cost the task
    a regeneration round (GHSA-rqx4, 2026-10-20: JSON without criteria became 9x 'not answered by reviewer')."""
    reply = extract_json_object(text)
    got = reply.get("criteria")
    if not isinstance(got, dict) or not any(isinstance(got.get(n), dict) and "pass" in got[n] for n in CRITERIA):
        raise ValueError(f"rubric reply answers no criterion: {text[:300]!r}")
    return reply


def check_task(env_dir: Path, backend: CliBackend, model: str, timeout_note: str = "") -> RubricResult:
    patch = split_patch_without_tests((env_dir / "oracle_solution.patch").read_text(encoding="utf-8", errors="replace"))
    meta_path = env_dir / "task_metadata.json"
    entry = json.loads(meta_path.read_text()).get("entry_point", "unknown") if meta_path.is_file() else "unknown"
    prompt = PROMPT.format(
        instruction=(env_dir / "instruction.md").read_text(),
        tests=(env_dir / "hidden_tests.py").read_text(),
        patch=patch[:60_000],
        entry_point=entry,
        criteria="\n".join(f"- {n} ({'critical' if c else 'advisory'}): {d}" for n, (c, d) in CRITERIA.items()),
    )
    system = "You are a meticulous benchmark-quality reviewer. Output JSON only."
    # DeepSeek Flash often needs >32k for long CoT before the JSON verdict (observed 2026-10-18).
    max_out = int(os.environ.get("RUBRIC_MAX_OUTPUT_TOKENS", "64000"))
    text, _ = backend.complete(model, system, [{"role": "user", "content": prompt}], max_out)
    try:
        reply = _verdict(text)
    except ValueError:
        # The reviewer's output was stopped (safety filter) or malformed: same fallback model as task generation.
        from src.common.llm import review_fallback_model
        fallback = review_fallback_model(model)
        if not fallback:
            raise
        log.warning("Rubric reviewer gave no verdict; retrying with the fallback model", extra={"model": fallback})
        text, _ = backend.complete(fallback, system, [{"role": "user", "content": prompt}], max_out)
        reply = _verdict(text)
    result = evaluate_reply(reply)
    (env_dir / "rubric_check.json").write_text(json.dumps(
        {"passed": result.passed, "criteria": result.criteria, "blocking_issues": result.blocking_issues}, indent=2))
    return result
