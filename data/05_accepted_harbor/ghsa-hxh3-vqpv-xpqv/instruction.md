# Untrusted text is emitted as live HTML by the JSX server renderer

Fix the problem described below in the project in `/workspace`.

## Summary
We render HTML on the server using this framework's built-in JSX. Normally any string we interpolate as element content is automatically HTML-escaped, so visitor-supplied text appears as inert characters and never as markup. We found several common rendering situations where that automatic escaping silently does not happen and the raw string is written straight into the response. Any attacker-controlled value displayed through one of those paths becomes stored or reflected cross-site scripting.

## Impact
A visitor submits a value such as `<img src=x onerror=alert(1)>` as a comment, display name, search term, etc. When our page later renders that value, the browser receives the literal tag and runs the handler instead of showing the text. The script executes in the victim's session, on our origin, with access to their cookies and the page.

## How to reproduce (behaviour level)
Render a page where an untrusted string is interpolated as child content. In the simplest element tree the value is escaped as expected. The escaping is skipped — and the raw string reaches the browser — whenever that text, or a string handed to the server renderer directly, passes through the framework's higher-level rendering wrappers instead of a plain element: for example a wrapper that defers part of the subtree behind a temporary placeholder until asynchronous children resolve, a wrapper that shows a fallback when a child errors while an asynchronous child is also present, or the mechanism that carries a shared value down into a subtree. Sending `<img src=x onerror=alert(1)>` through any of these yields that literal tag in the HTML rather than the escaped `&lt;img src=x onerror=alert(1)&gt;`. The underlying cause is shared: in these modes a child value is re-stringified and treated as finished markup, bypassing the escaping that ordinary element children receive.

## Expected behaviour
Any plain string that ends up in the rendered output must be HTML-escaped in every rendering mode, so it can never introduce tags or attributes. Legitimate behaviour must keep working: ordinary text must still appear (as visible text), a bare string must still be renderable as the top-level element, and content that a developer has explicitly marked as trusted raw HTML must still be emitted as markup.

## What you have

- `/workspace`: the project's source at the affected revision, with its dependencies installed in `node_modules` and the package built (`bun run build`).
- Node.js 22, its package managers and git are installed. There is no network access.

## Requirements

- Fix the vulnerability described above in the project's source code under `/workspace`.
- Only changes under `/workspace` are kept. Changes to dependency manifests and lockfiles, to test-runner configuration (such as `conftest.py`, `pytest.ini`, `vitest.config.*`, `jest.config.*`) and to the project's existing test files are not kept, and no dependencies can be added or upgraded.
- The project must still build offline with `bun run build`.
- Do not look for existing fixes elsewhere.

## Time

You have 2 hours. Run `bash /app/timer.sh` to see how much time remains. Keep the project working after every change.
