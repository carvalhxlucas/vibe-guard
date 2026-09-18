---
name: secure-auth-setup
description: Sets up or hardens authentication so sessions, protected routes, and role checks are right the first time — Supabase Auth on Next.js primarily, plus Auth.js and Clerk. Use when the user asks to add login, signup, auth, or protected pages; when they ask "is my login secure", "how do I protect this route", "how do I check if the user is an admin"; or when a security-audit finds routes with no auth check. Also use when session bugs appear: users logged out on refresh, stale sessions, or middleware that does not protect anything.
---

# Secure auth setup

Two jobs, and the first step is deciding which one you are doing:

- **Green field** — no auth yet. Scaffold it correctly.
- **Hardening** — auth exists and mostly works. Find the holes, fix them one at a
  time, keep the app running.

Ask which, if it is not obvious from the repo. Then read `references/` for the stack
you are on before writing any code.

## The rules that do not change

State these to the user as you go. They are the whole reason this skill exists:

1. **Never hand-roll authentication.** No custom password hashing, no home-made JWT
   signing, no "just store the user id in localStorage". Every auth library on this
   page has had more security review than anything either of us writes today.
2. **The browser cannot be trusted with any decision.** A logged-in flag in
   localStorage, a `role` field in a React context, a hidden admin button — all of
   these are suggestions the user can edit. Every check that matters happens on the
   server, on every request.
3. **Hiding a page is not protecting it.** If `/admin` renders a different UI but the
   data still comes from an API route with no check, the data is public. Protect the
   data, not the layout.
4. **On the server, verify the user — do not read the session.** With Supabase,
   `getSession()` reads the cookie and trusts it; `getUser()` revalidates with the auth
   server. In server code, always `getUser()`.
5. **Three layers, not one.** Middleware for redirects, a server-side check in every
   route handler and server action, and RLS in the database. Middleware alone is a
   convenience, not a boundary — it does not run for every data path.

## Step 1 — Read what is already there

```bash
cat package.json | rg -i 'supabase|next-auth|@auth/|clerk|lucia|passport|jsonwebtoken|bcrypt'
fd -H 'middleware\.(ts|js)$' --max-depth 2
fd -H 'supabase' lib utils app --max-depth 3 2>/dev/null
rg -ln "'use client'" | xargs rg -l 'createClient|auth\.' 2>/dev/null
rg -n 'getSession\(\)|getUser\(\)|auth\(\)|currentUser\(\)' --glob '!node_modules'
rg -n 'localStorage|sessionStorage' --glob '!node_modules' | rg -i 'token|session|user|auth|role'
```

Two findings to look for immediately, because they are both critical and common:

- `jsonwebtoken` or `bcrypt` in `package.json` alongside a hand-written login route —
  hand-rolled auth. Migrating is a bigger conversation; raise it, do not silently
  start.
- A token or user object in `localStorage` — readable by any script on the page, which
  means any XSS becomes full account takeover. Sessions belong in `httpOnly` cookies.

## Step 2 — Scaffold or harden

Follow the reference for the stack:

- **`references/supabase-nextjs.md`** — the full Supabase + Next.js App Router setup:
  browser client, server client, the middleware that refreshes the session, the OAuth
  callback route, protected layouts, server actions, and route handlers. Includes the
  `@supabase/ssr` cookie contract, where most broken Supabase auth comes from.
- **`references/hardening.md`** — the flows that go wrong regardless of library:
  password reset, email verification, OAuth redirects, role and admin checks, session
  lifetime, logout, rate limiting on auth endpoints, and account enumeration.

For Auth.js or Clerk, the library docs own the setup; your job is the checks in
`references/hardening.md` and the server-side verification in rule 4.

When writing files:

- **Never overwrite an existing auth file without showing the diff and asking.**
  Breaking a working login is worse than leaving a mediocre one in place.
- Match the project's existing conventions — its directory layout, its import style,
  whether it uses TypeScript.
- Write the smallest thing that works, then say what to test.

## Step 3 — Protect the routes, not just the pages

Walk every server entry point and add the check. This is the part that scaffolding
tutorials skip and that AI-generated apps almost always miss.

```ts
// Every route handler that reads or writes user data:
const supabase = await createClient();
const { data: { user } } = await supabase.auth.getUser();
if (!user) return new Response('Unauthorized', { status: 401 });
```

```ts
// Every server action — these are public HTTP endpoints, whatever the file looks like:
'use server';
export async function deleteNote(id: string) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) throw new Error('Unauthorized');

  // Authorize the specific row. Never trust an id from the client on its own.
  const { error } = await supabase
    .from('notes').delete().eq('id', id).eq('user_id', user.id);
  if (error) throw new Error('Not found');
}
```

The `.eq('user_id', user.id)` is not redundant with RLS — it is the second layer, and
it is what protects you the day someone disables a policy. Keep both.

## Step 4 — Say what to test, then stop

Give the user the list and let them run it:

1. Log in, refresh the page. Still logged in? (If not, the middleware cookie refresh is
   wrong — see `references/supabase-nextjs.md`.)
2. Log out. Press back. The protected page must not render from cache.
3. Copy a protected API URL. Open it in a private window. Must be 401, not data.
4. Log in as user A, note a record id. Log in as user B, call the API with A's id.
   Must be 404 or 403, never the record.
5. Edit the user id or role in any client-side state you can reach from dev tools.
   Nothing on the server should change behavior.

Test 4 is the one that catches the mistake that matters most. Do not skip it.

## Never do these

- Never put a `role`, `is_admin`, or `plan` field in a table the user can update, and
  then trust it. If a user can `update profiles set role = 'admin'`, they will. Keep
  role in `auth.users.app_metadata` (which the client cannot write), or in a table
  whose RLS grants no update to `authenticated`.
- Never use the service role key to "make auth work". It bypasses every check.
- Never redirect after login to a URL taken from a query parameter without validating
  it against an allowlist — that is an open redirect, and it is how phishing links get
  your domain in front of your users.
- Never return a different error for "no such account" and "wrong password". That tells
  an attacker which emails are registered.
