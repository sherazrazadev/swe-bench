yload 68w4 (287). All 3 attempts were declined each time, with no common CWE.
- **Unbuildable (n=1):** pydantic-ai is a monorepo, so `pip install -e .` at the root fails.

## Selection hints
- **Prefer** fixes of ≥6 files, ≥150 lines and ≥4 dirs with ≥2 entry points. The only both-fail task was 8 files and 174 lines (n=1). DeepSeek solved every task of ≤5 files it finished (n=5).
- **Next tier:** fixes of 5 files and 4 dirs that cross a layer boundary. This shape beat only MiMo (n=1).
- **Skip** fixes of ≤3 files and ≤35 lines. None of 8 gave a usable task: 68w4, x6jw, p634, pqg4, x33g, x937, j6r3 and 77xj.
- **Prefer auth, session and credential CWEs (345/522/613)** spread over several layers. These gave the only failures (n=2, tentative).
- **Lower priority:** DoS/resource CWEs (400/407/409). None of 3 gave a usable task: v247 was solved, mcm9 had a broken oracle, smol-toml was blocked.
- **pyload:** all 3 advisories were rejected by the rubric. Only one, after repair, gave a usable task (MiMo-only fail). Keep pyload only if the tests use the real app's test client.
- **Skip PyPI monorepos** unless the build installs the right sub-package (n=1).
- **Recall:**
  - If both models name the fix location from the report alone, reject before building (n=2).
  - Low recall does not mean hard: j6r3, p634 and v247 all had low recall and were still solved (n=3).
