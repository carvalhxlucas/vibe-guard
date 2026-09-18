# Auth flows that go wrong

Library-independent. Each section: what breaks, how to check it, what to do.

---

## Roles and admin checks

**The mistake:** a `role` or `is_admin` column on `profiles`, which the user can update
because the RLS policy lets them update their own row. They set it to `admin`.

**Check it:**
```bash
rg -n 'is_admin|role|is_pro|plan|subscription_status' --glob '*.sql'
rg -n "\.from\('profiles'\).*update|is_admin|role ===" --glob '!node_modules'
```
Then in SQL: does any policy allow `authenticated` to update that column?

**Fix, best to worst:**

1. Put the role in `auth.users.app_metadata`. The client cannot write it — only the
   service role or a dashboard admin can. Read it from the verified JWT server-side.
2. Keep a separate `user_roles` table with RLS that grants `select` to the owner and
   `update` to nobody.
3. If the role must live on `profiles`, revoke the column:
   ```sql
   revoke update (role) on public.profiles from authenticated;
   ```

Check the role **on the server, on every request that depends on it**. Hiding the admin
link in the UI while the admin API route stays open protects nothing.

Same rule for anything that represents money: `plan`, `credits`, `subscription_status`,
`is_pro`. If a user can write it, they will give themselves the paid tier.

---

## Password reset

**The mistakes:** a reset token that does not expire, a reset response that reveals
whether the email exists, a reset flow that logs the user in without checking the token,
and the reset link leaking through the `Referer` header.

**What to do:**

- Always respond "If that email has an account, we sent a link" — whether or not it
  does. Same message, same HTTP status, and ideally the same response time.
- Short expiry, one use. Supabase handles both; hand-rolled flows usually do neither.
- Invalidate all other sessions after a successful reset. If the account was taken
  over, the attacker's session must die with the password change.
- Require the current password to change the password while logged in.
- Rate limit reset requests per email and per IP. Without it, the endpoint is a free
  email cannon pointed at any address an attacker chooses.

---

## Email verification

An unverified email is not an identity. Before letting a new account do anything that
touches money, other users, or outbound email, require verification.

The specific hole: sign up as `victim@company.com`, never verify, and if the app later
links accounts by email address, you inherit whatever that email is trusted for. If the
app supports both password and OAuth login, make sure the link-by-email path requires a
verified address on both sides.

---

## OAuth

- Every redirect URL in an allowlist in the provider dashboard. No wildcards.
- PKCE for any public client. Supabase's JS client uses it by default; keep it.
- Validate the `state` parameter. It is what stops an attacker from completing a login
  flow in your user's browser with their own account attached.
- After the callback, **only redirect to paths you validated**:
  ```ts
  const safeNext = next.startsWith('/') && !next.startsWith('//') ? next : '/dashboard';
  ```
  `//evil.com` is a protocol-relative URL — it leaves your site. That single check is
  the difference between a login redirect and an open redirect used for phishing.

---

## Sessions and cookies

| Setting | Value | Why |
|---|---|---|
| `httpOnly` | `true` | JavaScript cannot read it, so an XSS cannot steal the session |
| `secure` | `true` in production | Never sent over plain HTTP |
| `sameSite` | `lax` | Blocks the cross-site request forgery case while keeping normal links working |
| `path` | `/` | |
| Access token lifetime | ~1 hour | Short window if a token does leak |
| Refresh token | rotating, revoked on reuse | A stolen refresh token gets one use before the whole family is revoked |

Never put a session token in `localStorage`. It converts any XSS — including one in a
third-party script you added for analytics — into full account takeover. Cookies with
`httpOnly` are not stealable that way.

Logout must invalidate the session **server-side**, not only delete the cookie. Deleting
the cookie on a shared computer leaves a valid token in whatever copied it.

---

## Rate limiting auth endpoints

Every one of these needs a limit, per IP and per account:

| Endpoint | Without a limit |
|---|---|
| Login | Credential stuffing against leaked password lists |
| Signup | Thousands of fake accounts, and your email domain on a blocklist |
| Password reset | Free email cannon aimed at any address |
| OTP / magic link | Same, plus SMS costs if phone auth is on |
| Any AI or paid API route | The four-figure bill |

Supabase applies its own limits to its auth endpoints — check the current values under
Authentication → Rate Limits and raise or lower them deliberately. Anything you built
yourself needs its own limiter.

Prefer a limiter with shared state (Upstash Redis, the hosting provider's firewall).
An in-memory counter resets on every cold start, which on serverless means it barely
counts at all.

---

## Account enumeration

Any place where the app answers "does this email exist" differently is a list of your
users waiting to be harvested. The usual leaks:

- Login: "No account with that email" vs "Wrong password"
- Signup: "Email already registered"
- Reset: "We sent a link" vs "Email not found"
- Response timing: a hash comparison that only runs for existing accounts

For signup, if you must tell the user the address is taken, send an email to the
existing account instead of answering in the UI.

---

## Multi-factor

Not needed for most early apps. It becomes worth the friction when the account controls
money, other people's data, or an admin surface. When you add it:

- TOTP over SMS. SIM swapping is a real and cheap attack.
- Recovery codes, shown once, stored hashed.
- Require MFA again for dangerous actions — changing the password, changing the payout
  account, deleting the workspace.

---

## Quick self-test

Run these against the app before launch. All five should hold.

1. Log in, then delete the session cookie in dev tools. Reload. You are logged out —
   and the API returns 401, not data.
2. Call a protected API route with `curl` and no cookie. Expect 401.
3. Log in as user A. Take a record id. Log in as user B, call the API with A's id.
   Expect 404/403.
4. In dev tools, edit any client-side `role`/`isAdmin`/`plan` value to `admin`/`true`.
   The server must not change behavior.
5. Request a password reset for an address with no account. The response must be
   identical to one that has an account.
