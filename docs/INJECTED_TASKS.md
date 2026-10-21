# Injected "parallel path" tasks: design

**Why:** every task that broke a model had the same shape: one security rule enforced in **several places** (parallel
implementations, a lower-level API, a save/reload path), where the models fix the obvious place and miss the others.
Mined advisories with that shape are rare: only 4 of 28 evaluated tasks had it. Injection lets us build that shape on
purpose. The task spec allows it (`source = mined or injected`).

## How it works

1. **Pick a real repo at a recent commit:** a project we already screened (real code, real tests, builds here).
2. **Find a security control used in 2+ places:** escaping in two renderers, path containment in several readers, an
   origin or credential check in several entry points. At least one place must be in a module that doesn't look
   related.
3. **Inject by removal, not by writing exploits:** the vulnerability is created by **deleting** that control in
   every place, as a mechanical search/replace patch. The model writes no attack code; this is the same kind of edit
   as today's "removal" check patch, which has never been flagged.
4. **Ground truth = the original code:** the reference fix is the reverse of the injection, the project's own code.
5. **Same report, tests and validation as mined tasks:**
   - a behavioural report;
   - one security test per path and per input shape;
   - functional tests near the boundary;
   - the 10-criterion rubric, recall probe, leak scan, reference fix 1.0, existing tests, and the shallow / removal /
     alternative fix checks.
6. **Metadata:** `source = "injected"`, plus the repo commit used and the injection patch.

## Rules for a good injection

- The control must protect a **real entry point**, so the injected bug is exploitable the way a real one would be.
- **At least 2 paths, at least 1 in another module,** and the report names neither.
- The injected repo must still **build and pass its existing tests**, apart from the security behaviour.
- **No obvious tell:** the removal must leave clean code with no dangling helpers or comments.
- Prefer **recent commits** (after the models' training) and keep the recall probe on, since the "fix" is the
  project's current code.

## Risks and how we handle them

| Risk | Handling |
|---|---|
| The model remembers the upstream code | Recent commits only; recall probe; prefer less famous repos |
| The injected bug looks artificial | The rubric's "realistic" criterion is blocking; the removal must leave natural code |
| Safety flags on generation | Removal-only injection, no exploit writing; a flag retires the candidate as today |
| Existing tests start failing after injection | Existing tests that fail on the injected repo are dropped from the enforced set (pass before and after only) |

## Build plan

1. A stage 3 "inject" mode: Opus gets the repo map and candidate files and returns the control, its places of use
   (≥2), the removal edits, and the report, tests and check patches.
2. Apply the removal to create the vulnerable snapshot; store the reverse as `oracle_solution.patch`.
3. Reuse stages 4-6 unchanged. Mark `source = "injected"` in the metadata and the results.
4. Pilot on 5 repos, compare break rates with mined tasks, then scale.
5. Injected records are registered in `data/02_screened/injected.json`; stage 3 selection merges that file with
   `screened.json` and prioritises injected candidates, so the pilot is evaluated first. Repos that already produced a
   task are skipped by `injector.pick_repos`.
