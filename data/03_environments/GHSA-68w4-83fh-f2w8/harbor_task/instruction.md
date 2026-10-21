# Low-privilege accounts can brute-force other users' passwords through the HTTP API

## Summary
Our pyLoad deployment exposes an HTTP API operation that takes a **username** and a **password** and, when the pair matches an existing account, returns that account's details (display name, role, permission flags, template, email). When the password is wrong it returns an empty record instead.

The problem is that this operation is reachable by **any** signed-in account, no matter how limited its rights. A user we created with the lowest role and no permission flags at all — someone who should only be able to watch the download queue — can call this operation over and over, each time supplying the administrator's username together with a guessed password, and tell from the reply whether the guess was right (a populated record) or wrong (an empty one). Nothing refuses, throttles, or flags these attempts.

In effect, a disposable low-privilege login becomes a password-checking oracle against every other account, including the administrator's. Once the admin password is recovered this way, the whole instance is compromised: settings, user management, the reconnect script, the storage location, and so on.

## Steps to reproduce
1. As the administrator, create a second account with the lowest role and no permission flags; note its credentials.
2. Authenticate to the API as that low-privilege account.
3. Invoke the account-details operation with `username` set to the administrator's name and an arbitrary `password`.
4. Observe that a wrong password returns an empty record while the correct password returns the administrator's full record — and that no authorization error is ever raised.

## Expected behaviour
- A caller who is not an administrator must not be able to use this account-details operation to learn whether a password is valid for an account, whatever permission flags that caller holds. The right-password and wrong-password replies must be indistinguishable to such a caller.
- Administrators must keep the ability to look up account details for valid credentials.
- Every other API operation must keep its existing permission behaviour: operations intentionally open to any signed-in user stay open, and operations gated behind a specific permission stay gated.
