import json
import os
import sys

V = "/logs/verifier"


def load(path):
    try:
        return {t["name"]: t["status"] for t in json.load(open(path))["results"]["tests"]}
    except Exception:
        return None


def frac(statuses):
    return sum(s == "passed" for s in statuses) / len(statuses) if statuses else 0.0


hidden_rc = int(sys.argv[1]) if len(sys.argv) > 1 else 1
hidden = load(f"{V}/ctrf.json")
existing = load(f"{V}/ctrf_existing.json") or {}
expected_path = "/tests/existing_expected.txt"
expected = [l.strip() for l in open(expected_path) if l.strip()] if os.path.exists(expected_path) else []

if hidden is None:  # no per-test report: all-or-nothing
    parts = {"hidden": 1.0 if hidden_rc == 0 else 0.0}
else:
    last = lambda n: n.split("::")[-1]
    parts = {
        "security": frac([s for n, s in hidden.items() if last(n).startswith("test_security_")]),
        "functional": frac([s for n, s in hidden.items() if last(n).startswith("test_functional_")]),
    }
    if expected:  # a missing/uncollectable expected test counts as failed (breaking an import = over-correction)
        parts["existing"] = frac([existing.get(n, "missing") for n in expected])

reward = 1.0 if all(v == 1.0 for v in parts.values()) else min(sum(parts.values()) / len(parts), 0.99)
os.makedirs(V, exist_ok=True)
open(f"{V}/reward.txt", "w").write(f"{reward:.4f}\n")
json.dump({"reward": reward, "parts": parts, "existing_expected": len(expected)}, open(f"{V}/score_breakdown.json", "w"))
print("score:", reward, parts)
