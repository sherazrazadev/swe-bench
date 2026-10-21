#### Summary
ACCEPTED - both models failed all 3 attempts (DeepSeek 0.83/0.83/0.94, MiMo 0.89/0.94/0.89, Claude Code agent), every run stopped on its own (no timeout). All 6 fixed the three wrappers the report names (Suspense, ErrorBoundary, Context.Provider) and all 6 left `renderToString([unsafe, [unsafe]])` unescaped.

#### Why DeepSeek failed
- **The diagnosis was right in all 3 runs** and close to the report's own wording, so the failures are about **scope**,
  not understanding.
- **It found the second renderer every time and declined to fix it in 2 of 3 runs.** It read `src/jsx/dom/server.ts`
  and the existing test expecting `renderToString('Hono')` to return `'Hono'`, then: "top-level string = trusted HTML
  (like `c.html(str)`)... I'll leave top-level semantics unchanged." Run 3 confirmed the hole experimentally ("bare
  string: raw") and still left it: "Top-level entry, leave as is (like c.html)." It read the report's "a bare string
  must still be renderable" as "do not escape".
- **The run that did fix `renderToString` (0.94)** guarded it with `typeof element === 'string'` only, although it had
  already written an array-aware helper for the wrappers. Its own tests covered a bare string, not an array.
- Stopped after its own 9-15 wrapper-focused tests, lint and build: "The fix is complete." (25-35 min, 79-112 turns.)

#### Why MiMo failed
- **It explored narrowly.** It found `dom/server.ts` in only 1 of 3 runs: one run's first grep ended in
  `| grep -v "dom/"` and it then claimed "there's only `renderToReadableStream` and JSXNode.toString()" (false); another
  asked "is there a `renderToString`?" twice and never searched.
- **The run that found it (0.94)** fixed the two entry points unevenly: `renderToReadableStream` through its
  array-aware helper, `renderToString` with a string-only check - and reported full coverage.
- Stopped after ticking off the report's bullet points with 17-21 tests of its own (37-66 min).

#### Weakness profile
- Shared: both treat the report's examples as the complete list of sinks, and fix only the input shape they
  reproduced (a bare string) even when the same parameter accepts arrays, nested arrays and promises.
- DeepSeek: over-reasons about intent - finds the sink, then uses a "keep legitimate behaviour" clause or an existing
  passing test as permission to leave it vulnerable.
- MiMo: under-explores and asserts unverified facts ("that API doesn't exist") instead of searching.

#### Task-design lessons
- Put a **second entry point in a sibling module whose path sounds out of scope** (here `dom/` reads as "client") and
  describe it only vaguely ("a string handed to the renderer directly").
- Add a **"must keep working" clause that plausibly argues against the fix** ("a bare string must still be
  renderable"), backed by an existing test that passes either way (`'Hono'` has nothing to escape).
- **Test input-shape variants at each sink** (array, nested array, promise, number), not only each sink.
- Make **two entry points share the bug but need separate fixes**; agents fix them unevenly and claim full coverage.
- List some sinks "for example" and test more than you list: every agent stopped once the listed items were covered.
