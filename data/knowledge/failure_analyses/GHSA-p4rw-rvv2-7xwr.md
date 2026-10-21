#### Summary
DeepSeek failed all 3 attempts (0.93 each, always the toolbox symlink escape left open); MiMo failed 2 (0.87, toolbox + MTE left open) and solved 1. Rejected (MiMo solved). No timeouts; every run stopped on its own.

#### Why DeepSeek failed
- **It audited widely but by call graph from the corpus-reader classes** (~100 turns per run, a grep of every raw
  `open()`, escape/positive probe matrices, a full-suite diff against baseline).
- **It never tried the public low-level constructor the hidden test uses**, `ToolboxData(str(path))`, which reaches a
  raw `codecs.open`. It read `nltk/toolbox.py` and reasoned only about the reader path: "ToolboxCorpusReader uses
  `abspaths` ... abspath validation (new) will cover it"; "ToolboxData with a PathPointer uses `sfm_file.open(...)` ->
  central fix covers it. Good." Systematic: the same miss in 3 of 3 runs.
- **Its probes went through the same entry point as its fix**, so they passed: "Escape probe: 0 leaks, 28 blocked";
  "toolbox PASS" (via the corpus reader) -> "Task complete and verified."
- A trap in the environment: the global sandbox allows `tempfile.gettempdir()`, so "route through the secure open"
  without a required root blocks nothing for a symlink target under /tmp.

#### Why MiMo failed (2 of 3)
- **It found the bare-string leaks itself and talked itself out of fixing them**: "StandardFormat(str path) still
  leaks ... For the string case without required_root - that's direct API use. I'll leave it with global sandbox";
  "defaulting to parent dir is too strict for nested layouts".
- **Its tests bent the environment to pass**: one passed `required_root=...` (not the default call), one
  monkeypatched the allowed roots down to the corpus root.
- **It never checked which readers feed bare strings** to the shared XML view: `MTECorpusReader` builds
  `os.path.join(str(root), f)` strings (the MTE test failed; it never opened `mte.py`).
- **The solving run** treated the same observed leaks as bugs: "I'll add containment to them ... using
  parent-directory as the sandbox", and its own tests failed before the fix and passed after.

#### Weakness profile
- DeepSeek: entry-point blindness - treats "reachable through the main class" as the whole attack surface and
  confirms with probes that use the same entry point as its fix.
- MiMo: rationalises away its own negative evidence on an ambiguous boundary, and writes tests shaped to fit its fix.

#### Task-design lessons
- Make hidden tests hit the **second public API** (a lower-level class, helper, bare-string / path-like argument);
  the report says only "more than one public loading API".
- Let an **existing guard look sufficient in the test environment** (an allowed tempdir root) so a plausible
  half-fix passes the agent's own probes.
- Leave an **ambiguous boundary** (a bare path with no explicit root) where the report's general rule ("each affected
  path must honour the same containment rule") implies the strict reading.
- Name affected **file kinds** in the report, not readers, and test at least one reader reached only indirectly
  through a shared helper.
- Hidden tests use default arguments and the real sandbox settings, so environment-bending self-tests do not help.
