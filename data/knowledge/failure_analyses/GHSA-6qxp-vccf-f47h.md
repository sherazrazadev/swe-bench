#### Summary
DeepSeek failed 3/3 (0.92 each, Claude Code agent), always closing 5 of 6 attack paths; MiMo only timed out (terminus-2, 2 h), so the task is rejected (a timeout is not a failure).

#### Why DeepSeek failed
- **Same diagnosis and fix in all 3 attempts:** only `auth()` enforced the issuer binding while the lower-level token
  entry points (`fetchToken`, `exchangeAuthorization`, `refreshAuthorization`, `executeTokenRequest`) did not; it put a
  guard in the shared token-request path, covering every *call path* (mostly `packages/client/src/client/auth.ts`).
- **The missed path is a data path, not a call path:** the SDK's own Zod schemas `.strip()` unknown keys, so a
  credential saved and reloaded through `OAuthClientInformationSchema` loses its `issuer` stamp and looks unbound. None
  of the attempts changed `packages/core/src/auth.ts`, where the schemas live.
- **It saw the gap and argued itself out of it:** it mentioned the schemas or `.strip()` in 12-18 turns per attempt -
  "maybe `.strip()` removes `issuer`..." then "The mention of the schemas probably just guards against an
  implementation that ... validates strictly". The report lists schema-parsed persistence under *legitimate use that
  must keep working*; it read that as a constraint, not as an attack surface. An in-code comment ("intentionally absent
  from the wire-response schema") reinforced it.
- **Stopped when its own tests passed** ("Fix complete and verified end-to-end"), 9-15 min, well inside the limit.

#### Why MiMo failed
- Not a counted failure: with the older terminus-2 harness it ran out of the 2-hour limit in all 3 attempts with 0 of
  6 attack paths closed. It was not re-run with Claude Code.

#### Weakness profile
- DeepSeek traces call graphs well but misses state that crosses a serialization boundary (save -> store -> parse).
- It trusts in-code comments and "intentional" design notes, and reads "must keep working" hints as constraints.
- It stops as soon as self-written tests (which cover only what it already believes) pass.

#### Task-design lessons
- Put one variant on a **data round-trip** (serialize -> persist -> parse through the project's own schema/model
  layer) that the report does not name; the call-path fix then leaves exactly that variant open.
- Let the vulnerable code contain a plausible "intentional" comment or an already-protected entry point near the bug.
- Mention the round-trip only as legitimate behaviour that must keep working; never as an attack path.
