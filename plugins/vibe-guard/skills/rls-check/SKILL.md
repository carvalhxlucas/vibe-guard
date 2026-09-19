---
name: rls-check
description: Inspects the live Supabase/Postgres database for tables reachable with the public anon key that have Row Level Security off, no policies, or a policy allowing everything — then generates the RLS migration to fix it. Use when someone asks about RLS or Row Level Security, or describes the symptom without the term: "can other users see my data", "someone told me anyone can read my database", "my key is in the frontend, is that bad", "is my Supabase locked down", "my table suddenly returns empty results", "generate policies for my schema". Also use before a first launch on any Supabase project, and whenever a security audit flags RLS.
---

# RLS check

Find every table an anonymous or logged-in stranger can read or write, and generate the
policies that close it.

This skill **writes a migration file** but **never applies it**. Applying is the user's
call, and a wrong RLS policy takes an app offline just as effectively as a leak takes it
down. Generate, explain, let them apply.

## Why this matters, in one paragraph

Explain this to the user once, in the report — most people building on Supabase have
never had it put plainly:

> Your anon key is public. It ships inside the JavaScript every visitor downloads, and
> it is *supposed* to be public. The thing that makes that safe is Row Level Security:
> the database itself checking, on every single query, which rows this particular
> caller is allowed to see. With RLS off, the anon key is a master key to that table —
> anyone can open dev tools, copy the key, and run `select * from your_table`.

## Step 1 — Get the authoritative schema state

Migration files lie. Tables created in the Supabase dashboard never appear in
`supabase/migrations/`, and RLS toggled in the dashboard UI leaves no trace in the
repo. Always try to read the live database first.

Try these in order and use the first that works. Check what the user actually has
before picking — do not assume a tool is installed:

```bash
command -v psql supabase
```

```bash
# a. A connection string in the environment, with psql available
psql "$DATABASE_URL" -f "${CLAUDE_PLUGIN_ROOT}/skills/rls-check/scripts/introspect.sql"

# b. Local Supabase stack running — this prints the local DB URL
supabase status
# then: psql "<the DB URL it printed>" -f "${CLAUDE_PLUGIN_ROOT}/skills/rls-check/scripts/introspect.sql"

# c. Supabase CLI linked to a remote project. The subcommand for running SQL has
#    changed across CLI versions, so check before using it rather than guessing:
supabase db query --help 2>/dev/null || supabase db --help
```

**Paste mode is the path that always works, and there is no shame in going straight to
it.** Print the contents of `scripts/introspect.sql`, ask the user to run it in the
Supabase dashboard (SQL Editor → New query → paste → Run), and paste the results back.
Say why it is worth the 30 seconds: the repository cannot tell you what the live
database actually does.

Only if the user declines, fall back to reading `supabase/migrations/*.sql` and
`*.sql` anywhere in the repo — and label every finding in the report as
**unverified (read from migrations, not from the live database)**.

## Step 2 — Classify every table

For each table in the `public` schema, decide which pattern it is. This decision drives
the policy, and getting it wrong is how you either leak data or break the app. When a
table is ambiguous, **ask the user** — one question per ambiguous table, with your best
guess offered first.

| Pattern | How to recognize it | Policy shape |
|---|---|---|
| **Owned by a user** | Has `user_id`, `owner_id`, `author_id`, `created_by`, or `profile_id` referencing `auth.users` | Owner does everything; nobody else sees it |
| **The user's own profile** | Table is `profiles`/`users` with `id` referencing `auth.users(id)` | Read own row always; read others only if the app shows public profiles |
| **Tenant/team scoped** | Has `team_id`, `org_id`, `workspace_id`, plus a membership table | Membership lookup decides access |
| **Public read, admin write** | Pricing plans, blog posts, published content, feature flags | `select` open; writes closed to everyone but service role |
| **Join / membership table** | Two foreign keys, no obvious owner | Access follows the parent the user owns |
| **Fully private** | Webhook logs, audit trails, internal jobs | No policies at all; only the service role touches it |

Also inspect, because these are the RLS holes people miss:

- **Views** — before Postgres 15 and without `security_invoker`, a view runs as its
  creator and *bypasses* the RLS of its underlying tables. Check
  `pg_views` and the `security_invoker` reloption.
- **`security definer` functions** — these bypass RLS by design. Every one of them is
  a hole unless it filters by `auth.uid()` internally. They also need
  `set search_path = ''`.
- **Storage buckets** — `storage.objects` has its own policies. A public bucket with
  user uploads is the same leak as a table with RLS off.
- **Realtime** — a table published to `supabase_realtime` streams changes to
  subscribers; RLS applies, but only if it is on.

## Step 3 — Report before generating

Show the user a table of what you found, sorted by risk, before you write anything:

```
Table              RLS    Policies   Reachable by anon key   Risk
customers          OFF    0          yes                     CRITICAL — every row readable by anyone
messages           ON     1 (true)   yes                     CRITICAL — policy allows all rows
notes              ON     2          scoped to owner         ok
plans              OFF    0          yes                     ok if intentional — public pricing data?
webhook_logs       OFF    0          yes                     CRITICAL — internal data exposed
```

`Reachable by anon key` means: the `anon` or `authenticated` role has a `GRANT` on the
table. A table with no grant is not reachable regardless of RLS — do not report it as
Critical. Check `information_schema.role_table_grants`, which `introspect.sql` returns.

Confirm the classification of anything you guessed, then move on.

## Step 4 — Generate the migration

Write to `supabase/migrations/<timestamp>_enable_rls.sql` (timestamp format
`YYYYMMDDHHMMSS`). If the project has no `supabase/migrations/` directory, write
`rls-policies.sql` in the project root and tell the user to paste it into the SQL
editor.

`references/policy-patterns.md` has the exact SQL for each pattern above, plus the
three things that make generated policies actually correct in production:

1. Wrap `auth.uid()` as `(select auth.uid())` — Postgres then evaluates it once per
   query instead of once per row. On a 100k-row table this is the difference between
   30 ms and 30 seconds.
2. Add `to authenticated` (or `to anon, authenticated`) to every policy, so the policy
   is not even evaluated for roles it does not apply to.
3. Index every column a policy filters on. A policy on `user_id` with no index on
   `user_id` turns every query into a sequential scan.

Write one policy per command (`select`, `insert`, `update`, `delete`) rather than
`for all` — it keeps the intent readable and lets you open reads without opening
writes.

Always include the rollback at the bottom of the file, commented out:

```sql
-- Rollback (only if this migration breaks the app):
-- drop policy if exists "owners read their notes" on public.notes;
-- alter table public.notes disable row level security;
```

## Step 5 — Hand it over with a test plan

Never run `supabase db push` or `supabase migration up` yourself. Print the command and
let the user run it.

Give them the verification steps, because "the app still works" is not proof that RLS
is on, and "the app broke" is the normal first result:

1. **Apply to local or staging first** — `supabase db reset` locally, or push to a
   branch database.
2. **Prove the lock works.** In the SQL editor, run the queries in
   `scripts/verify-rls.sql`. They impersonate the `anon` role and should return zero
   rows for every protected table.
3. **Prove the app still works.** Log in and exercise each screen that reads or writes
   the affected tables.
4. **Expect empty results, not errors.** RLS does not throw — it filters. A list that
   went blank after this migration means the policy is too tight, usually because the
   ownership column is not what you assumed. Say this up front; it is the number one
   reason people disable RLS again and give up.

## Things to never do in this skill

- **Never apply a migration.** Generate it, explain it, stop.
- **Never recommend turning RLS off to fix an empty list.** The fix is the policy.
- **Never suggest the service role key as a workaround** for a policy that is too
  tight. Moving a query to the service role bypasses RLS for that query — if that query
  is reachable from the browser, the leak is now worse than before.
- **Never assume `user_id` is the owner column** without checking the foreign key.
  Some schemas use `user_id` for "the user this row is about", which is a different
  thing from "the user who may read it".
