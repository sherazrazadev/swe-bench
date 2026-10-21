#### Summary
DeepSeek failed attempt 1 (0.86, 5 of 7 attack paths) then solved attempt 2; MiMo failed its one graded attempt (0.93): it closed every attack path but broke a legitimate caching behaviour. Rejected (DeepSeek solved).

#### Why DeepSeek failed (attempt 1)
- **Right root cause:** cache / deduplicate keyed responses on the caller-supplied `opts.origin` label ("Client/Pool
  ignore `opts.origin`... BalancedPool ignores it entirely").
- **Fix (7 lib files):** `compose()` passes the dispatcher to interceptors; cache/dedupe key on `dispatcher[kUrl]`,
  skipping pool-like dispatchers without `kUrl`.
- **Missed the wrappers:** `RetryAgent(Client(A))` and `Dispatcher1Wrapper(Client(A))` have no `kUrl` and are not
  pool-like, so they fell back to the label (both wrapper tests failed). It opened `dispatcher1-wrapper.js` only to
  check it would not break - "Not relevant." - and read the report's "however the client object is wrapped" as
  chained `compose` calls.
- **Stopped on its own 9-scenario repro:** "All 9 pass ... The fix is complete and fully validated."
- **The solving attempt** did the same fix but then enumerated every dispatcher class asking "which ones set `kUrl`?",
  first dismissed the case ("very unlikely"), kept going, and confirmed it from the repo's own usage
  (`test/retry-agent.js`: `new RetryAgent(client, opts)`) - then propagated the real origin through the wrappers.

#### Why MiMo failed
- **Closed all 7 attack paths, broke 1 of 7 functional tests** (`storage_with_custom_lookup_same_host`): the widest
  fix (13 files) added a second, redundant safety layer - `CacheHandler.onRequestStart` re-keys a stored entry to the
  connection's origin "if that disagrees with the key we looked up with". With `compose(cache(), dns({lookup}))` the
  cache sees the resolved IP before dns rewrites it, so same-hostname responses are no longer reused.
- **It had the composition order right early** ("Call order: dns -> cache -> client"), then flipped it ("first
  interceptor in the list is outermost ... Either order should work") and re-added the re-keying it had dropped.
- **Tested only one order** (`compose([dns, cache])`), which passes; stopped after 1 h 40 min: "The origin-validation
  hole is fixed and covered by regression tests."

#### Weakness profile
- DeepSeek: does not enumerate every place the real destination can hide; reads a class-level requirement ("however
  wrapped") narrowly; treats "my own repro passes" as proof of completeness.
- MiMo: over-hardens with redundant defence-in-depth layers; confuses the order of composed layers; tests a legitimate
  configuration in one order only and generalises ("either order should work").

#### Task-design lessons
- Phrase requirements that imply a **class of cases** ("however it is wrapped / combined") and give each member its
  own hidden security test; the example in the report should be only one member.
- Test the same **legitimate behaviour in every supported composition order**: over-restricting fixes fail only in
  the order the agent did not try (this is what breaks MiMo).
- Pair each security test with a "must still work" twin sharing its setup (same host, custom lookup, wrapper).
- Prefer missed cases that appear in the repo's own usage/tests but not in the report's reproduction steps.
