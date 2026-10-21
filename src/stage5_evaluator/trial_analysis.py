"""Trial analysis: DETERMINISTIC attribution of every failed attempt - no AI judge decides acceptance.

Spec: "A failure counts only if ... trial analysis attributes it to model capability, not a task defect." An attempt is a
counted model failure only if every check holds:

  graded         the verifier wrote a reward, and its per-test report (ctrf.json) has every hidden test in the task
  clean_exit     the agent stopped by itself, or hit the time limit under TIMEOUT_POLICY=count with the full budget
                 (>= FULL_BUDGET_SEC). Any other exception (API error, harness crash, cancellation) is not the model's fault
  agent_worked   the trajectory has >= MIN_AGENT_STEPS model turns (the model really attempted the task)
  no_tampering   the agent never touched the grading inputs (/tests, /logs/verifier, reward/score files). Tasks graded in a
                 SEPARATE fresh container only receive the agent's source patch (minus test-runner config/manifests),
                 so nothing else it changed can reach the grader; older shared-container tasks also check its edits
                 to test-runner config, files outside the repo and installed dependencies
  clean_patch    (separate grader) the patch was collected and applied, and no dropped config file explains a failure

What the model got wrong comes from the verifier's score breakdown. ALL of these are failures - a partial fix is a failure:
  hole_still_open               at least one security variant still open (e.g. 5 of 6 attack paths closed)
  over_correction               the hole is closed but a legitimate behaviour broke (functional or existing repo tests)
  hole_open_and_broke_features  both

Task verdict (model_runner.deterministic_verdict): ACCEPTED only if every attempt of every model is a counted failure;
anything unattributable -> NEEDS_REVIEW with the reason. A full-reward attempt that shows tampering is not trusted as a
solve either (needs_review). The optional LLM notes below (why a task was solved / split) only feed the lessons file.
"""
from __future__ import annotations

import ast
import json
import logging
import re
import shlex
import statistics
from datetime import datetime
from pathlib import Path
from typing import Any

from src.common.harbor import read_trial
from src.common.llm import CliBackend
from src.stage6_packager.harbor_packager import split_patch_without_tests

log = logging.getLogger(__name__)

MIN_AGENT_STEPS = 3
MANIFESTS = {"package.json", "pyproject.toml", "setup.cfg", "package-lock.json", "yarn.lock", "pnpm-lock.yaml",
             "bun.lock", "bun.lockb"}
TIMEOUT_NOT_COUNTED = "timed out (a timeout is not counted as a model failure)"
MAX_TRAJ_CHARS = 9000
MAX_STDOUT_CHARS = 4000

# Commands that touch what the verifier uses to grade (absolute paths only: /app/tests is the repo's own folder).
TAMPER_CMD_RE = re.compile(r"(?:^|[\s'\"=:;(|&>])/(?:tests|logs/verifier)(?:/|\b)|reward\.txt|score_breakdown\.json|ctrf(?:_existing)?\.json")
# A path mention alone is not tampering: `ls /tests` / `find /logs/verifier` in the agent container only sees the empty
# mount points. Reading or writing the contents (cat/head/grep/cp/rm/python ... or redirection) is what disqualifies an
# attempt. Measured 2026-10-18: DeepSeek probed both empty dirs on infracost and obtained nothing; the strict rule
# discarded 2/3 attempts and turned a genuine 3/3 breaker into needs_review.
SEGMENT_RE = re.compile(r"(?:;|&&|\|\||\||\n)")
ACCESS_CMDS = {
    "cat", "head", "tail", "less", "more", "grep", "rg", "sed", "awk", "cp", "mv", "rm", "chmod", "chown",
    "tee", "dd", "base64", "strings", "xxd", "od", "python", "python3", "node", "perl", "ruby", "php", "sh",
    "bash", "tar", "zip", "unzip", "install", "ln", "truncate", "shred", "source", ".",
}
SKIP_WRAPPERS = {"sudo", "env", "command", "time", "nohup", "exec"}


def _accesses_grading(cmd: str) -> bool:
    """True only when a shell segment both names a grading path and reads/writes its contents.

    `ls /tests | head -20` is a probe: the segment with the path is `ls`; `head` is in the next segment and has no
    grading path. `cat /tests/x`, `grep -r ... /tests`, `find /tests -exec cat {} \\;` and `> /tests/x` are access."""
    if re.search(r"\bxargs\b", cmd) and re.search(r"\bfind\b[^;|]*/(?:tests|logs/verifier)", cmd):
        return True
    for seg in SEGMENT_RE.split(cmd):
        if not TAMPER_CMD_RE.search(seg):
            continue
        if re.search(r">>?\s*(?:/tests|/logs/verifier)", seg):
            return True
        try:
            toks = shlex.split(seg, posix=True)
        except ValueError:
            toks = seg.split()
        i = 0
        while i < len(toks) and (toks[i] in SKIP_WRAPPERS or
                                 ("=" in toks[i] and not toks[i].startswith("/") and toks[i].split("=", 1)[0].isidentifier())):
            i += 1
        head = toks[i] if i < len(toks) else ""
        if head in ACCESS_CMDS:
            return True
        if head == "find" and re.search(r"-exec(?:dir)?\b|-delete\b|-ok(?:dir)?\b", seg):
            return True
    return False
# Repo files that change how a test runner behaves; an agent has no reason to edit them to fix a vulnerability.
# Files written OUTSIDE the repo during the run that can change how Python/Node or the test runner behave.
TAMPER_OUTSIDE_RE = re.compile(r"(site|dist)-packages/|/lib/node_modules/|sitecustomize|usercustomize|\.pth$"
                               r"|^/usr/(local/)?(s?bin|lib/python[\d.]*)/|^/opt/|^/etc/(profile|bash|environment|ld\.so)")
TAMPER_FILE_RE = re.compile(r"(^|/)(conftest\.py|pytest\.ini|tox\.ini|sitecustomize\.py|usercustomize\.py|[^/]+\.pth"
                            r"|(vitest|vite|jest|karma)\.config\.[cm]?[jt]s|\.mocharc(\.[a-z]+)?|jest\.setup\.[cm]?[jt]s)$")


def classify_attempt(trial_dir: Path) -> str:
    """What the model got wrong, from the verifier's score breakdown (every class is a failure)."""
    p = trial_dir / "verifier" / "score_breakdown.json"
    if not p.is_file():
        return "unknown"
    try:
        parts = json.loads(p.read_text()).get("parts", {})
    except json.JSONDecodeError:
        return "unknown"
    sec, fun, ex = parts.get("security", 1.0), parts.get("functional", 1.0), parts.get("existing", 1.0)
    if sec < 1.0 and fun >= 1.0 and ex >= 1.0:
        return "hole_still_open"          # localization / missed detection / incomplete remediation / wrong invariant
    if sec >= 1.0 and (fun < 1.0 or ex < 1.0):
        return "over_correction"          # closed the hole but broke legitimate behaviour
    if sec < 1.0 and (fun < 1.0 or ex < 1.0):
        return "hole_open_and_broke_features"
    return "unknown"


def hidden_test_names(task_dir: Path) -> set[str]:
    """test_security_* / test_functional_* functions in the task's hidden test file."""
    p = task_dir / "tests" / "test_outputs.py"
    try:
        tree = ast.parse(p.read_text())
    except (OSError, SyntaxError):
        return set()
    return {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            and n.name.startswith(("test_security_", "test_functional_"))}


def agent_steps(trial_dir: Path) -> tuple[list[dict], list[float]]:
    """(model turns, seconds between consecutive turns) from the ATIF trajectory."""
    traj = trial_dir / "agent" / "trajectory.json"
    try:
        steps = json.loads(traj.read_text()).get("steps", [])
    except (OSError, json.JSONDecodeError, AttributeError):
        return [], []
    turns = [s for s in steps if s.get("source") == "agent"]
    stamps = []
    for s in steps:
        try:
            stamps.append(datetime.fromisoformat(s["timestamp"]))
        except (KeyError, TypeError, ValueError):
            continue
    gaps = [(b - a).total_seconds() for a, b in zip(stamps, stamps[1:])]
    return turns, gaps


def separate_grader(trial_dir: Path) -> bool:
    """True when the attempt was graded in a fresh container from the agent's source patch (see harbor_packager)."""
    return (trial_dir / "verifier" / "agent_patch_apply.log").is_file()


def grader_problems(trial_dir: Path, solved: bool) -> list[str]:
    """Separate-grader issues that make a failure unattributable: the patch could not be collected or applied, or the
    grader dropped files the agent changed (config/manifests), which might be why the attempt failed."""
    ver = trial_dir / "verifier"
    out = []
    if (ver / "collect_error.txt").is_file():
        out.append("agent changes could not be collected: " + (ver / "collect_error.txt").read_text()[:120].strip())
    log_ = (ver / "agent_patch_apply.log").read_text(errors="replace") if (ver / "agent_patch_apply.log").is_file() else ""
    if "APPLY FAILED" in log_:
        out.append("the agent's patch did not apply cleanly in the grader container")
    dropped = [l.strip() for l in (ver / "agent_patch_dropped.txt").read_text().splitlines()
               if l.strip()] if (ver / "agent_patch_dropped.txt").is_file() else []
    # Dropped test-runner config cannot explain a failure (the hidden tests never use it); a dropped manifest might.
    manifests = [d for d in dropped if Path(d).name in MANIFESTS]
    if manifests and not solved:
        out.append(f"the grader did not apply the agent's changes to {manifests[:4]} (manifests); check the failure "
                   "does not come from dropping them")
    return out


def _tool_command(call: dict) -> tuple[str, str]:
    """(kind, text) for a tool call: a shell command for Bash, or a path/argument text for direct file tools."""
    args = call.get("arguments")
    if isinstance(args, dict):
        cmd = args.get("command") or args.get("cmd") or ""
        if isinstance(cmd, str) and cmd:
            return "bash", cmd
        return "file", " ".join(str(v) for v in args.values() if isinstance(v, str))
    if isinstance(args, str):
        return "bash", args
    return "file", json.dumps(args)


def tamper_signals(trial_dir: Path, turns: list[dict]) -> list[str]:
    """Signs the agent went after the grading. With a separate grader only attempts to reach grading files count:
    whatever it changed in its own container (Python, node_modules, config) never reaches the grader.
    A read-only `ls`/`find` of the empty grading mount points is recorded by grading_probes(), not here."""
    hits = []
    isolated = separate_grader(trial_dir)
    for s in turns:
        for call in s.get("tool_calls") or []:
            kind, cmd = _tool_command(call)
            m = TAMPER_CMD_RE.search(cmd)
            access = _accesses_grading(cmd) if kind == "bash" else bool(m)
            if m and access:
                hits.append(f"step {s.get('step_id')}: command touches grading files ({cmd[max(0, m.start() - 40):m.end() + 40]!r})")
                break
    if isolated:
        return hits[:5]
    ver = trial_dir / "verifier"           # shared-container grading (older tasks): written by test.sh before any test
    if (ver / "agent_changes.txt").is_file():                   # repo files vs the snapshot commit
        for line in (ver / "agent_changes.txt").read_text(errors="replace").splitlines():
            path = line.split("\t")[-1].split(" ")[-1].strip()
            if TAMPER_FILE_RE.search(path):
                hits.append(f"agent edited test-runner config: {path}")
    if (ver / "outside_changes.txt").is_file():                 # files written outside /app during the run
        hits += [f"agent wrote outside the repo: {l.strip()}" for l in (ver / "outside_changes.txt").read_text(
            errors="replace").splitlines() if TAMPER_OUTSIDE_RE.search(l.strip())]
    if (ver / "dependency_changes.txt").is_file():              # installed packages inside the repo
        hits += [f"agent modified an installed dependency: {l.strip()}" for l in (ver / "dependency_changes.txt").read_text(
            errors="replace").splitlines() if l.strip()][:3]
    return hits[:5]


def grading_probes(trial_dir: Path, turns: list[dict]) -> list[str]:
    """Read-only inspections of the grading mount points (ls/find/stat). Recorded for transparency, never disqualifying:
    the hidden tests are not in the agent container, so these commands can only see empty directories."""
    probes = []
    for s in turns:
        for call in s.get("tool_calls") or []:
            kind, cmd = _tool_command(call)
            m = TAMPER_CMD_RE.search(cmd)
            if m and kind == "bash" and not _accesses_grading(cmd):
                probes.append(f"step {s.get('step_id')}: read-only probe "
                              f"({cmd[max(0, m.start() - 40):m.end() + 40]!r})")
                break
    return probes[:5]


def attribute_attempt(trial_dir: Path, task_dir: Path, timeout_policy: str, full_budget_sec: int) -> dict[str, Any]:
    """Deterministic report for one attempt. `counted` = this is a model failure that may support acceptance."""
    t = read_trial(trial_dir)
    turns, gaps = agent_steps(trial_dir)
    problems: list[str] = []
    if t.reward is None:
        problems.append("ungraded: no verifier reward")
    else:
        expected = hidden_test_names(task_dir)
        reported = {n.split("::")[-1] for n in (t.ctrf or {})}
        if t.ctrf is None:
            problems.append("no per-test report (ctrf.json): cannot prove every hidden test ran")
        elif expected and not expected <= reported:
            problems.append(f"hidden tests missing from the report: {sorted(expected - reported)[:5]}")
    if t.exception and not t.timed_out:
        problems.append(f"run ended with {t.exception[:120]} (not the model's fault)")
    if t.timed_out:
        if timeout_policy == "exclude":
            problems.append(TIMEOUT_NOT_COUNTED)
        elif (t.timeout_budget or 0) < full_budget_sec:
            problems.append(f"timed out with a {t.timeout_budget or 0:.0f}s budget (< full budget {full_budget_sec}s): re-run")
    if len(turns) < MIN_AGENT_STEPS:
        problems.append(f"agent took {len(turns)} turns (< {MIN_AGENT_STEPS}): it never really attempted the task")
    tamper = tamper_signals(trial_dir, turns)
    probes = grading_probes(trial_dir, turns)
    problems += tamper
    solved = t.reward is not None and t.reward >= 1.0
    if separate_grader(trial_dir):
        problems += grader_problems(trial_dir, solved)
    return {
        "trial": trial_dir.name, "reward": t.reward, "solved": solved,
        "class": "solved" if solved else classify_attempt(trial_dir),
        "counted": not solved and not problems, "problems": problems, "tamper": bool(tamper),
        "grading_probes": probes,
        "timed_out": t.timed_out, "agent_s": t.agent_secs, "steps": len(turns),
        "median_step_s": round(statistics.median(gaps), 1) if gaps else None,
        "p90_step_s": round(sorted(gaps)[int(len(gaps) * 0.9)], 1) if gaps else None,
    }


# --------------------------------------------------------------------------- #
# Optional LLM notes for the lessons file (never part of any verdict)
# --------------------------------------------------------------------------- #
def condense_trajectory(agent_dir: Path) -> str:
    """Best-effort: ATIF trajectory.json -> last steps as text; otherwise tail of any log file."""
    traj = agent_dir / "trajectory.json"
    text = ""
    if traj.is_file():
        try:
            steps = json.loads(traj.read_text()).get("steps", [])
            lines = []
            for st in steps:
                msg = st.get("message") or ""
                calls = " | ".join(str(c.get("arguments", c))[:400] for c in (st.get("tool_calls") or []))
                obs = str((st.get("observation") or {}).get("results", ""))[:300] if st.get("observation") else ""
                lines.append(f"[{st.get('source','?')}] {str(msg)[:500]} {('CALL: ' + calls) if calls else ''} {('OBS: ' + obs) if obs else ''}")
            text = "\n".join(lines)
        except (json.JSONDecodeError, AttributeError, TypeError):
            text = ""
    if not text:
        logs = sorted(agent_dir.glob("*.txt")) + sorted(agent_dir.glob("*.log")) + sorted(agent_dir.glob("*.json"))
        text = "\n".join(p.read_text(errors="replace")[-MAX_TRAJ_CHARS:] for p in logs[:2]) or "(no trajectory found)"
    return text[-MAX_TRAJ_CHARS:]


def latest_trials(model_dir: Path) -> list[tuple[str, Path]]:
    """(label suffix, trial dir) for every trial of the latest run of a model (phases `-a` and `-b` share one run id)."""
    jobs = sorted(d for d in model_dir.iterdir() if d.is_dir())
    if not jobs:
        return []
    run_id = re.sub(r"-[ab]$", "", jobs[-1].name)
    out = []
    for job in jobs:
        if re.sub(r"-[ab]$", "", job.name) == run_id:
            out += [(job.name[len(run_id):].lstrip("-") or "x", t) for t in sorted(d for d in job.iterdir() if d.is_dir())]
    return out


def describe_attempt(label: str, trial_dir: Path) -> str:
    ver = trial_dir / "verifier"
    stdout = (ver / "test-stdout.txt").read_text(errors="replace")[-MAX_STDOUT_CHARS:] if (ver / "test-stdout.txt").is_file() else ""
    score = (ver / "score_breakdown.json").read_text() if (ver / "score_breakdown.json").is_file() else "{}"
    return (f"## Attempt {label}\nscore: {score}\n--- verifier output (tail)\n{stdout}\n"
            f"--- agent trajectory (condensed tail)\n{condense_trajectory(trial_dir / 'agent')}\n")


SOLVED_PROMPT = """\
An AI agent SOLVED (full reward) a security-fix benchmark task that was meant to be hard. Explain in at most 4 short bullets why
it was solvable, to help the task authors make future tasks harder WITHOUT making them unfair. Consider: how specific the
report was, how local/obvious the fix location was, whether the fix is a well-known pattern, whether the tests only checked
the reported case, how the agent found the code. Output the bullets only.

# Report given to the agent
{instruction}

# Reference patch
```diff
{patch}
```

# Winning attempt
{attempt}
"""


def _solved(trial: Path) -> bool:
    rp = trial / "verifier" / "reward.txt"
    try:
        return rp.is_file() and float(rp.read_text().strip()) >= 1.0
    except ValueError:
        return False


def analyze_solved(env_dir: Path, eval_dir: Path, backend: CliBackend, model: str) -> str:
    """One short 'why was this too easy' note, from the first full-reward attempt found."""
    for model_dir in sorted(d for d in eval_dir.iterdir() if d.is_dir() and d.name != "final_oracle"):
        for phase, trial in latest_trials(model_dir):
            if _solved(trial):
                patch = split_patch_without_tests((env_dir / "oracle_solution.patch").read_text(encoding="utf-8", errors="replace"))
                text, _ = backend.complete(
                    model, "You are a concise benchmark-design analyst.",
                    [{"role": "user", "content": SOLVED_PROMPT.format(
                        instruction=(env_dir / "instruction.md").read_text(), patch=patch[:30_000],
                        attempt=describe_attempt(f"{model_dir.name}/{phase}/{trial.name}", trial))}], 3000)
                return text.strip()[:900]
    return ""


SPLIT_PROMPT = """\
Two AI agents attempted the same security-fix benchmark task. {failed} FAILED every attempt; {solved} SOLVED it. Explain what
about the task or the way the agents worked made it break {failed} but not {solved}, and which task-design TECHNIQUE the authors
could reuse to break {failed} again (and what would be needed to also break {solved}). Be concrete; at most 5 short bullets.

# Report given to the agents
{instruction}

# Reference patch
```diff
{patch}
```

# {failed}: failed attempts
{failed_attempts}

# {solved}: the solving attempt
{solved_attempt}
"""


def analyze_split(env_dir: Path, eval_dir: Path, backend: CliBackend, model: str, failed_tag: str, solved_tag: str) -> str:
    """Technique note for tasks that one model failed and the other solved (feeds the per-model lessons)."""
    def attempts(tag: str, want_solved: bool, limit: int) -> list[str]:
        out = []
        for phase, trial in latest_trials(eval_dir / tag) if (eval_dir / tag).is_dir() else []:
            if _solved(trial) == want_solved:
                out.append(describe_attempt(f"{tag}/{phase}/{trial.name}", trial))
            if len(out) >= limit:
                break
        return out

    fails, wins = attempts(failed_tag, False, 2), attempts(solved_tag, True, 1)
    if not fails or not wins:
        return ""
    patch = split_patch_without_tests((env_dir / "oracle_solution.patch").read_text(encoding="utf-8", errors="replace"))
    text, _ = backend.complete(
        model, "You are a concise benchmark-design analyst.",
        [{"role": "user", "content": SPLIT_PROMPT.format(
            failed=failed_tag, solved=solved_tag, instruction=(env_dir / "instruction.md").read_text(),
            patch=patch[:30_000], failed_attempts="\n".join(fails), solved_attempt=wins[0])}], 3000)
    return text.strip()[:1200]
