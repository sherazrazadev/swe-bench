PROJECT MASTER CONTEXT: CWE-Bench Automated Task Factory

1. Executive Summary & Mission
   Objective: Build an automated, scalable data engineering pipeline that produces 100–200 Harbor-formatted cybersecurity evaluation tasks within a 3-week sprint.
   Target Benchmark: CWE-Bench (a private, held-out cybersecurity benchmark for coding agents by Collinear AI).
   Core Quality Metric: Every accepted task must achieve pass@3 = 0 on both DeepSeek V4.1 Flash (max) and Xiaomi MiMo-V2.6-Pro.
   Attribution Rule: A task failure is only valid if attributed to a model capability limitation (not a task defect, bad environment, ambiguous instruction, or missing dependency).
2. Task Specifications (Harbor Format)
   Each task packages a real open-source repository in a historically vulnerable state with realistic reports and hidden tests.
   Component Specification
   Format Standard Harbor layout: instruction.md, task.toml, environment/, solution/ (oracle patch), tests/ (hidden test suite).
   Environment Real open-source repo pinned at the vulnerable commit; dependencies and backing services (DB, cache) fully installed and buildable.
   Instruction Realistic vulnerability report describing observed impact and trigger. Strict Rule: Zero hints, zero file names, zero function names, zero line numbers.
   Security Tests (fail → pass) Exploits vulnerability through realistic entry points. Must assert the hole is patched, including variants beyond any basic PoC in the report.
   Functional Tests (pass → pass) Existing regression test suites plus legitimate-use tests to ensure the model does not break features or over-block.
   Oracle Solution The actual historical human fix (clean git diff). Must pass 100% of security and functional tests.
   Metadata CWE ID, programming language, repo URL, vulnerability source, entry point.
   Out of Scope (Strictly Forbidden):
   Synthetic code snippets or toy math riddles.
   Dependency-only bumps (e.g., npm audit fix, version bumps in package.json).
   Config-only changes (e.g., tweaking a YAML setting).
   Contrived, unreachable, or dead-code vulnerabilities.
3. The Scientific Paradigm: Breaking Frontier Models
   Internal research demonstrates that modern frontier models (Opus 5.5, GPT-6 Astra, DeepSeek V4.1) easily solve standard coding obstacles. To reliably achieve pass@3 = 0, tasks must engineer "Silent Failures" (where the model confidently claims success but fails hidden verification).
   The 3 Prerequisites for Silent Failure:
   No Answer Key: The agent cannot access or reverse-engineer the hidden test suite during its run.
   Real-World Variety: Uses messy, complex, multi-file production codebases where data flows across multiple layers. The model defaults to an overly simplistic assumption.
   Undisputed Truth: Grounded in a real historical human CVE patch (the oracle).
   CWE-Bench Failure Taxonomy (Targeted Weaknesses):
   Localization Failure: Model gets lost in the repository structure and never locates the root-cause file.
   Missed Detection: Model inspects the vulnerable code but falsely classifies it as safe.
   Incomplete Remediation / Wrong Invariant: Model applies a band-aid fix to the specific trigger mentioned in the bug report, leaving sibling exploit paths and variants wide open.
   Over-Correction (The Over-Blocking Trap): Model neutralizes the security hole by disabling, over-restricting, or removing the affected feature entirely, failing the pass → pass functional tests.
   Vulnerability Heuristics to Target:
   Inter-Procedural Flows: Entry point in one file (e.g., routing/controller), flow through middleware/services, sink deep in the database/ORM layer.
   Business Logic & State Tracking: Race conditions, order-of-operation flaws, multi-step transaction bypasses.
4. The 8-Stage Pipeline Architecture
   code
   Text
   [1. Mine] -> [2. Screen] -> [3. Build] -> [4. Validate] -> [5. Rubric] -> [6. Run Models] -> [7. Trial Analysis] -> [8. Package]
   Mine: Query OSV.dev and GitHub Advisory Database (GHSA) for real-world Python (PyPI) and JavaScript (npm) vulnerabilities with fixed commit links. Target: 300–400 raw candidates.
   Screen: Filter out junk (dependency bumps, config changes) and run a "fail-fast" buildability check (verify pip install / npm install runs in Docker).
   Build: Isolate pre-patch state, extract the human patch (oracle_solution.patch), and use an LLM (Claude 3.5 Sonnet / Opus) to generate non-leaky instruction.md and variant-rich hidden_tests.py.
   Validate: Execute the oracle fix in a sandbox. The pre-patch code MUST fail security tests; the oracle patch MUST pass both security and functional tests.
   Rubric Check: Verify the task is fair, unambiguous, and solvable without undocumented assumptions.
   Model Run (Adversarial Gate): Execute 3 trials on DeepSeek V4.1 Flash and 3 trials on MiMo-V2.6-Pro. Accept only tasks where both models score 0/3 (pass@3 = 0).
   Trial Analysis: Verify via execution traces that failures stem from model capability gaps, not environment issues.
   Package: Output standard Harbor task directory with complete metadata.
5. Enterprise Directory Structure
   The repository is split into distinct modules following standard production data engineering patterns:
   code
   Text
   cwe-bench-factory/
   ├── config/
   │ ├── settings.yaml # Pipeline limits, timeouts, batch sizes
   │ └── models.yaml # Evaluator parameters and configurations
   ├── skills/
   │ └── adversarial_research.md # Knowledge base on silent failures & CWE traps
   ├── data/ # Assembly-line data stages
   │ ├── 01_mined/ # Raw OSV/GHSA JSON records
   │ ├── 02_screened/ # Filtered candidate metadata
   │ ├── 03_environments/ # Cloned repositories at pre-patch state
   │ ├── 04_eval_runs/ # Execution traces of DeepSeek & MiMo
   │ └── 05_accepted_harbor/ # Final 100–200 Harbor tasks
   ├── src/
   │ ├── common/ # Shared utilities (state_manager, git, logging)
   │ ├── stage1_mining/ # OSV and GHSA scrapers
   │ ├── stage2_screening/ # Diffs filter & Docker buildability check
   │ ├── stage3_task_builder/ # Harbor task generation via Anthropic API
   │ ├── stage4_oracle_validator/ # Sandbox runner for oracle & pre-patch tests
   │ ├── stage5_evaluator/ # Model trial runner (pass@3 = 0 verification)
   │ └── stage6_packager/ # Final Harbor formatter and metadata generator
   ├── .env # Secrets (ANTHROPIC_API_KEY, GITHUB_TOKEN, etc.)
   ├── requirements.txt
   └── run_pipeline.py # Master CLI controller
6. Current Implementation State & Immediate Instructions for Cursor
   Done: Initial data miner logic for the OSV API has been prototyped and validated. State management (deduplication) and rate-limiting concepts are defined.
   Next Immediate Steps:
   Initialize the directory structure and scaffolding as specified in Section 5.
   Implement skills/adversarial_research.md containing the heuristics and failure modes.
   Finalize src/common/state_manager.py for persistent deduplication across runs.
   Implement src/stage1_mining/osv_miner.py with batch controls (BATCH_SIZE=10, scalable to 400).
   Build src/stage2_screening/ to isolate vulnerable commits and discard non-code changes.
