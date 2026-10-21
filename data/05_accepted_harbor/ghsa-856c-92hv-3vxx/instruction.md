# Secret request headers are replayed to other hosts after a 3xx reply, and operators cannot turn redirect following off

Fix the problem described below in the project in `/workspace`.

## Summary

Apprise lets an operator add their own request headers to a target, for example `json://alerts.internal.example/hook?+X-Api-Key=s3cr3t`. Self-hosted receivers, API gateways and reverse proxies often authenticate callers with exactly this kind of header. Some services also use their own key header for the same purpose.

When the configured endpoint replies with a 3xx status, Apprise repeats the request against whatever host the `Location` header names, and it does so without telling anyone. For 307 and 308 replies it replays the method, the message body and every custom header.

The underlying client library removes only `Authorization` when the host changes. API-key headers, tokens and shared secrets go to the new host unchanged. Apprise gives operators no way to opt out of this.

## Impact

Some people can collect the operator's secret headers and the message contents on a host they choose:

- anyone who controls the configured endpoint
- anyone who controls a proxy in front of it
- anyone who can inject a redirect into its responses

Remote configuration sources and remote files that Apprise retrieves to attach to messages are affected in the same way, because those requests also carry operator-supplied credentials and headers.

## Reproduce

1. Run a small server that answers every request with `307` and a `Location` pointing to a different hostname that you also control. Record what that second host receives.
2. Point the JSON target above at the first server and trigger a notification.
3. The second host receives the replayed request, including `X-Api-Key: s3cr3t`.

## Expected behaviour

- Operators need a per-target boolean option, `redirect=` (`yes` / `no`). It should behave exactly like the existing common per-target option `verify=`.
- With `redirect=no`, Apprise must never contact the host named in a redirect, whatever kind of target is involved. A redirect reply counts as a failed delivery or a failed retrieval. Its body must never be used as content.
- With no option, or with `redirect=yes`, behaviour stays as it is today. Redirects are still followed and succeed, for example when an endpoint has moved to a new path on the same server.
- Custom headers must still reach the configured host itself.

## What you have

- `/workspace`: the project's source at the affected revision, installed in editable mode into the system Python with its dependencies.
- Python 3.11 and git are installed. There is no network access.

## Requirements

- Fix the vulnerability described above in the project's source code under `/workspace`.
- Only changes under `/workspace` are kept. Changes to dependency manifests and lockfiles, to test-runner configuration (such as `conftest.py`, `pytest.ini`, `vitest.config.*`, `jest.config.*`) and to the project's existing test files are not kept, and no dependencies can be added or upgraded.
- Do not look for existing fixes elsewhere.

## Time

You have 2 hours. Run `bash /app/timer.sh` to see how much time remains. Keep the project working after every change.
