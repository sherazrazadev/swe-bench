"""Run the repo's own JS/TS test files (/tests/existing_files.txt) with the project's runner -> ctrf_existing.json.
One runner call per file (so every result maps to its file); names are "<file>::<suite / test title>"."""
import json
import os
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

APP, OUT = Path("/app"), Path("/logs/verifier/ctrf_existing.json")
RUNNERS = ("vitest", "jest", "mocha")


def manifest(d):
    try:
        return json.loads((d / "package.json").read_text())
    except (OSError, ValueError):
        return {}


def runner_for(test_file):
    """Nearest package.json (up to /app) that names a runner in its deps or test script -> (runner, package dir)."""
    d = (APP / test_file).parent
    while True:
        m = manifest(d)
        deps = {**m.get("dependencies", {}), **m.get("devDependencies", {})}
        script = (m.get("scripts") or {}).get("test", "")
        for r in RUNNERS:
            if r in deps or r in script:
                return r, d
        if "node --test" in script:
            return "node", d
        if d == APP:
            return None, APP
        d = d.parent


def binary(name, start):
    d = start
    while True:
        b = d / "node_modules" / ".bin" / name
        if b.exists():
            return str(b)
        if d == APP:
            return None
        d = d.parent


def junit(path, prefix):
    out = {}
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return out
    for case in root.iter("testcase"):
        status = "failed" if case.find("failure") is not None or case.find("error") is not None else (
            "skipped" if case.find("skipped") is not None else "passed")
        name = f"{prefix}::{case.get('classname', '')} > {case.get('name', '')}"
        while name in out:
            name += "'"
        out[name] = status
    return out


def run_file(rel):
    runner, pkg = runner_for(rel)
    target = str((APP / rel).relative_to(pkg)) if pkg != APP else rel
    xml, js = Path("/tmp/existing.xml"), Path("/tmp/existing.json")
    for p in (xml, js):
        p.unlink(missing_ok=True)
    exe = binary(runner, pkg) if runner in RUNNERS else None
    if runner == "vitest" and exe:
        cmd = [exe, "run", target, "--reporter=junit", f"--outputFile={xml}"]
    elif runner == "jest" and exe:
        cmd = [exe, "--ci", "--watchAll=false", "--runTestsByPath", target, "--json", f"--outputFile={js}"]
    elif runner == "mocha" and exe:
        cmd = [exe, target, "--reporter", "xunit", "--reporter-option", f"output={xml}"]
    elif runner == "node":
        cmd = ["node", "--test", "--test-reporter=junit", f"--test-reporter-destination={xml}", target]
    else:
        return {f"{rel}::(no runnable test runner)": "failed"}
    try:
        subprocess.run(cmd, cwd=pkg, timeout=300, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       env={**os.environ, "CI": "1", "NO_COLOR": "1"})
    except (OSError, subprocess.TimeoutExpired):
        return {f"{rel}::(runner timed out or failed to start)": "failed"}
    if runner == "jest":
        out = {}
        try:
            for res in json.loads(js.read_text()).get("testResults", []):
                for a in res.get("assertionResults", []):
                    out[f"{rel}::{a.get('fullName') or a.get('title')}"] = "passed" if a.get("status") == "passed" else (
                        "skipped" if a.get("status") in ("pending", "skipped", "todo") else "failed")
        except (OSError, ValueError):
            pass
        return out or {f"{rel}::(no results)": "failed"}
    return junit(xml, rel) or {f"{rel}::(no results)": "failed"}


tests = {}
for rel in [l.strip() for l in open("/tests/existing_files.txt") if l.strip()]:
    tests.update(run_file(rel))
OUT.parent.mkdir(parents=True, exist_ok=True)
OUT.write_text(json.dumps({"results": {"tests": [{"name": n, "status": s} for n, s in tests.items()]}}))
print(f"existing tests: {sum(s == 'passed' for s in tests.values())}/{len(tests)} passed")
