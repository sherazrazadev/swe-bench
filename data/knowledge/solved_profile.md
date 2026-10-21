## Solved-task profile (deterministic, rebuilt after every evaluation)
38 evaluated tasks were solved by at least one model; 36 on the FIRST attempt. Median solve time 13 min. These are the shapes to avoid or to combine with the techniques that broke a model (see the technique scoreboard).
- Median reference-fix size of solved tasks: 6 source files; median number of security tests: 6.
- Solved by vulnerability family: auth / session / credentials x11, resource exhaustion (DoS) x8, path / file handling x6, other x5, injection (code / command / markup) x4, parsing / type confusion x4, information exposure x3, SSRF / redirect x2, deserialization / prototype pollution x1
- In 8 of 38 solves the agent changed every source file of the reference fix: the report led it to all affected places.

### Why solved tasks were too easy (measured; fix the most common first)
- **coverage gap** in 25 of 38 solved tasks -> list every place the reference fix hardens and reach EACH one from its own security test - a repair that skips one place must fail.
- **no hidden path** in 15 of 38 solved tasks -> put part of the root cause in a REAL place the report never leads to - a second implementation, a producer feeding the check, a defaults/merge route - and reach it with its own test (techniques 1, 2, 3, 7, 12-15).
- **small fix** in 12 of 38 solved tasks -> a one-place fix is solved whatever the report says; skip it unless the code has a real second place the fix must also reach (fix width alone does not help: 10-21-file fixes were solved on attempt 1).
- **few security tests** in 9 of 38 solved tasks -> write one security test per fix place, each through its own entry point (spelling and encoding variants of one input do not count: models always catch them).
- **report points at the code** in 8 of 38 solved tasks -> never name the file, function, option or parameter the fix changes, and never state how far the bug reaches ('every provider', 'on every route').

| Task | Family | Fix | Security tests | Techniques used | Solved by | Attempt | Minutes | Why it passed |
|---|---|---|---|---|---|---|---|---|
| 9router | auth / session / credentials | 13 files / 10 dirs / 257 lines | 6 | 1, 4, 5, 6, 8, 9 | DeepSeek | 1 | 2 | coverage gap (1/12 fix files changed) |
| @hono/oauth-providers | auth / session / credentials | 7 files / 7 dirs / 54 lines | 6 | 1, 4, 5, 6, 8, 10 | DeepSeek | 1 | 3 | - |
| msgpack5 | resource exhaustion (DoS) | 2 files / 2 dirs / 40 lines | 7 | 1, 4, 5, 6, 8 | DeepSeek | 1 | 4 | small fix |
| nltk | resource exhaustion (DoS) | 6 files / 2 dirs / 163 lines | 5 | 4, 5, 6, 8 | DeepSeek | 1 | 4 | coverage gap (1/7 fix files changed); report points at the code: grammar; no hidden path; few security tests |
| ip-address | parsing / type confusion | 3 files / 1 dir / 25 lines | 6 | 4, 5, 6, 8 | DeepSeek | 1 | 5 | small fix; report points at the code: Address4, Address6; no hidden path |
| @xmldom/xmldom | other | 3 files / 2 dirs / 37 lines | 10 | 1, 2, 4, 5, 6, 8, 9 | DeepSeek | 1 | 6 | small fix |
| vibe-trading-ai | auth / session / credentials + path / file handling + information exposure | 17 files / 5 dirs / 618 lines | 6 | 3, 4, 5, 6, 8 | DeepSeek | 1 | 6 | coverage gap (4/23 fix files changed); report points at the code: Settings, service |
| pyload-ng | auth / session / credentials | 2 files / 2 dirs / 9 lines | 4 | 4, 5, 6 | DeepSeek | 1 | 8 | coverage gap (1/2 fix files changed); small fix; no hidden path; few security tests |
| pyload-ng | auth / session / credentials | 4 files / 2 dirs / 58 lines | 7 | 4, 5, 6, 8 | DeepSeek | 1 | 8 | coverage gap (3/5 fix files changed); no hidden path |
| n8n | injection (code / command / markup) | 9 files / 7 dirs / 343 lines | 6 | 1, 4, 5, 8 | DeepSeek | 1 | 8 | coverage gap (5/9 fix files changed); report points at the code: execute |
| @vitest/browser | auth / session / credentials + path / file handling | 8 files / 4 dirs / 104 lines | 4 | 1, 2, 4, 5, 6, 8, 9 | DeepSeek | 1 | 9 | coverage gap (6/8 fix files changed); report points at the code: upload; few security tests |
| PYSEC-2026-3837-v2 | other | fix size unknown | 6 | 1, 2, 5, 7, 9, 12 | DeepSeek | 1 | 9 | coverage gap (4/21 fix files changed); report points at the code: commit |
| pymongo | other | 3 files / 3 dirs / 74 lines | 6 | 4, 5, 6, 7, 8 | DeepSeek | 1 | 10 | small fix |
| adm-zip | parsing / type confusion | 2 files / 2 dirs / 11 lines | 6 | 4, 5, 6, 8 | DeepSeek | 1 | 11 | small fix; no hidden path |
| react-router | other | 8 files / 7 dirs / 113 lines | 5 | 1, 3, 4, 5, 6, 7, 8 | DeepSeek | 1 | 12 | coverage gap (1/6 fix files changed); report points at the code: server; few security tests |
| pyload-ng | auth / session / credentials | 5 files / 4 dirs / 111 lines | 7 | 4, 5, 6 | DeepSeek | 1 | 12 | no hidden path |
| datamodel-code-generator | path / file handling | 1 files / 1 dir / 31 lines | 6 | 4, 5, 6, 9 | DeepSeek | 1 | 13 | small fix; no hidden path |
| @sync-in/server | other | 21 files / 8 dirs / 224 lines | 6 | 1, 4, 5, 6, 7, 8, 9 | DeepSeek | 1 | 13 | coverage gap (12/20 fix files changed) |
| hono | path / file handling | fix size unknown | 4 | 1, 4, 5, 6, 8, 9 | DeepSeek | 1 | 13 | coverage gap (1/2 fix files changed); small fix; few security tests |
| pydantic-ai | auth / session / credentials | 6 files / 3 dirs / 222 lines | 8 | 4, 5, 6, 8, 9 | DeepSeek | 1 | 13 | coverage gap (3/6 fix files changed); no hidden path |
| fast-uri | parsing / type confusion + SSRF / redirect | 2 files / 2 dirs / 238 lines | 8 | 1, 2, 4, 5, 6, 8, 9 | DeepSeek | 1 | 14 | small fix |
| pypdf | resource exhaustion (DoS) | 2 files / 2 dirs / 93 lines | 6 | 4, 6, 8, 9 | DeepSeek | 1 | 14 | small fix; no hidden path |
| crewai-tools | SSRF / redirect | 8 files / 4 dirs / 121 lines | 6 | 1, 4, 5, 6, 7, 8 | DeepSeek | 1 | 14 | coverage gap (7/8 fix files changed) |
| devalue | resource exhaustion (DoS) | 3 files / 3 dirs / 141 lines | 6 | 4, 5, 6, 8 | DeepSeek | 1 | 15 | coverage gap (1/3 fix files changed); small fix; no hidden path |
| changedetection-io | injection (code / command / markup) | 12 files / 8 dirs / 95 lines | 6 | 1, 4, 5, 6, 8 | DeepSeek | 1 | 17 | coverage gap (3/22 fix files changed) |
| @bytebase/dbhub | auth / session / credentials + injection (code / command / markup) | 7 files / 6 dirs / 189 lines | 8 | 1, 3, 4, 5, 6, 8 | DeepSeek | 1 | 20 | coverage gap (6/7 fix files changed) |
| stream-json | resource exhaustion (DoS) | 10 files / 4 dirs / 286 lines | 7 | 1, 4, 5, 6, 8 | DeepSeek | 1 | 21 | coverage gap (2/13 fix files changed) |
| pypdf | resource exhaustion (DoS) | 4 files / 2 dirs / 117 lines | 5 | 4, 5, 6, 8 | DeepSeek | 1 | 23 | coverage gap (1/4 fix files changed); no hidden path; few security tests |
| @typespec/openapi3 | path / file handling | 6 files / 5 dirs / 53 lines | 7 | 4, 5, 6, 7, 8 | DeepSeek | 1 | 26 | coverage gap (4/6 fix files changed) |
| httpx2 | resource exhaustion (DoS) | 4 files / 1 dir / 238 lines | 8 | 4, 5, 6, 8, 9 | DeepSeek | 1 | 26 | coverage gap (2/4 fix files changed); no hidden path |
| @payloadcms/plugin-import-export | deserialization / prototype pollution | 16 files / 10 dirs / 344 lines | 5 | 4, 5, 6 | DeepSeek | 1 | 26 | coverage gap (3/18 fix files changed); no hidden path; few security tests |
| banks | parsing / type confusion | 13 files / 3 dirs / 232 lines | 7 | 3, 4, 5, 6, 8, 9 | DeepSeek | 1 | 27 | coverage gap (10/14 fix files changed) |
| devalue | information exposure | 4 files / 1 dir / 40 lines | 6 | 4, 5, 6, 7, 8, 9 | DeepSeek | 1 | 27 | report points at the code: uneval |
| fast-jwt | auth / session / credentials | 1 files / 1 dir / 33 lines | 7 | 1, 4, 5, 6, 8, 9 | MiMo | 1 | 34 | small fix |
| GitPython | injection (code / command / markup) + information exposure | 5 files / 4 dirs / 55 lines | 5 | 1, 2, 4, 5, 6, 8 | DeepSeek | 1 | 42 | few security tests |
| undici | auth / session / credentials | 10 files / 5 dirs / 120 lines | 7 | 1, 4, 5, 6, 7, 8 | DeepSeek | 3 | 49 | coverage gap (9/10 fix files changed) |
| nltk | path / file handling | 10 files / 3 dirs / 236 lines | 5 | 4, 5, 6, 8 | MiMo | 2 | 61 | coverage gap (5/10 fix files changed); no hidden path; few security tests |
| nltk | resource exhaustion (DoS) | 7 files / 4 dirs / 289 lines | 6 | 4, 6, 8 | DeepSeek | 1 | 64 | coverage gap (5/8 fix files changed); no hidden path |
