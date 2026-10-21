# Forged forwarding header lets any client escape API throttling and falsify the audit trail

## Summary

pyLoad's web interface works out who is calling from the `X-Forwarded-For` request header whenever a request carries one. It does this even when no reverse proxy sits in front of the server. Whatever the caller puts in that header becomes its identity for two security jobs:

- **Throttling of the HTTP API (`/api/...`).** Each client gets 100 calls per minute. The budget is tracked against the claimed address, so a client gets a fresh budget just by changing the header.
- **Security log entries.** Failed sign-in attempts on the web form, and HTTP API requests rejected for bad credentials, are logged with the address from the header. The machine that actually connected is not recorded.

This happens on a stock installation where the web interface is reached directly.

## Steps to reproduce

1. Expose pyLoad directly, with no proxy, and create an API key.
2. From one host, call any `/api/` method in a loop, sending the key in the `X-API-Key` header. After 100 calls within a minute you get `429 Too Many Requests`.
3. Run the loop again, adding `X-Forwarded-For: 198.51.100.N` with a different N on each call. You are never throttled.
4. Submit the sign-in form with a wrong password and `X-Forwarded-For: 203.0.113.9`. The error line in the log names `203.0.113.9` instead of your host.

## Impact

- The per-client cap on API usage does nothing: one client can send as many calls as it likes.
- A client can name any other address in the header. That address then uses up its throttling budget, or shows up in the security log as the culprit. This hides the real source and can send incident response after an innocent host.

## Expected behaviour

- Unless an operator has explicitly said that pyLoad runs behind a reverse proxy they control, two things must use the real network peer: the address used for throttling, and the address written to authentication-related log entries. No request header may change either one.
- A client must not be able to escape its own budget, or use up someone else's, by editing headers.
- Normal traffic must keep working:
  - Requests that happen to carry proxy-style headers are still served normally.
  - Different hosts still have separate budgets.
  - Valid API keys and valid sign-ins still work.
  - Failed attempts are still logged with the real peer address.
