"""reward = passed / total. Root-side: the expected hidden test names come from the suite's own AST (nothing executed),
the expected existing tests from /tests/existing_expected.txt; reports written by the graded processes are only read,
and every expected test without a result counts as failed."""
import ast
import json
import sys
import xml.etree.ElementTree as ET

OUT, LOGS = sys.argv[1], "/logs/verifier"


def hidden_defs():
    tree = ast.parse(open("/tests/test_outputs.py").read())
    names = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test"):
            names.append(node.name)
        elif isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            names += [n.name for n in node.body
                      if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name.startswith("test")]
    return list(dict.fromkeys(names))


def junit_cases(path):
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError):
        return []
    out = []
    for case in root.iter("testcase"):
        status = ("failed" if case.find("failure") is not None else "error" if case.find("error") is not None
                  else "skipped" if case.find("skipped") is not None else "passed")
        out.append((case.get("name") or "", status))
    return out


def load_ctrf(path):
    try:
        return {t["name"]: t["status"] for t in json.load(open(path))["results"]["tests"]}
    except Exception:
        return {}


cases = junit_cases(f"{OUT}/hidden.xml")
units = []                                    # (kind, name, status)
for d in hidden_defs():
    kind = "security" if d.startswith("test_security_") else "functional" if d.startswith("test_functional_") else "other"
    got = [(n, s) for n, s in cases if n.split("[", 1)[0] == d]
    units += [(kind, n, s) for n, s in got] or [(kind, d, "missing")]
try:
    expected = [l.strip() for l in open("/tests/existing_expected.txt") if l.strip()]
except OSError:
    expected = []
existing = load_ctrf(f"{OUT}/ctrf_existing.json")
units += [("existing", n, existing.get(n, "missing")) for n in expected]
if not units:
    sys.exit("no expected tests")

count = lambda *st: sum(s in st for _, _, s in units)
passed, total = count("passed"), len(units)
parts = {}
for kind in ("security", "functional", "existing", "other"):
    sel = [s for k, _, s in units if k == kind]
    if sel:
        parts[kind] = sum(s == "passed" for s in sel) / len(sel)
reward = passed / total
metrics = {"scoring_mode": "threshold", "status": "scored", "reward": reward, "passed": passed,
           "failed": count("failed", "missing"), "errors": count("error"), "skipped": count("skipped"), "total": total,
           "parts": parts, "missing": [n for _, n, s in units if s == "missing"][:200],
           "not_passed": [n for _, n, s in units if s != "passed"][:200]}
json.dump(metrics, open(f"{LOGS}/metrics.json", "w"), indent=1)
json.dump({"reward": reward}, open(f"{LOGS}/reward.json", "w"))
for name in ("hidden.xml", "ctrf_existing.json"):
    try:
        open(f"{LOGS}/{name}", "w").write(open(f"{OUT}/{name}").read())
    except OSError:
        pass
print("reward", reward, parts)
