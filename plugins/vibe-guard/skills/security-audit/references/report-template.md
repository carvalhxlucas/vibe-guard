# Report template

Write the report to `SECURITY-AUDIT.md` in the project root. Keep this shape.

Tone: direct, specific, and calm. No scare language, no "you must immediately", no
security theater. The reader should finish the report knowing exactly what to do next
and roughly how long it takes.

---

```markdown
# Security audit — <project name>

**Date:** <YYYY-MM-DD>
**Scope:** <what you actually looked at: source in this repo, migrations in supabase/, package.json>
**Stack detected:** <Next.js 15 App Router · Supabase · Vercel>

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High     | 0 |
| Medium   | 0 |
| Low      | 0 |

<One paragraph, five lines max: the overall state, and the single thing to fix first.
If it is clean, say that plainly.>

---

## Critical

### C1. <Short title in plain words — "Your Supabase admin key is in code the browser downloads">

**What it is**
<Two or three sentences. No security vocabulary. Describe the situation, not the
category name.>

**Why it matters**
<The concrete bad day. Who does what, and what you lose: money, data, accounts,
your domain's email reputation. Be specific to this app — "anyone who opens your
site can read every row of your `customers` table, including emails and Stripe IDs".>

**Where**
- `lib/supabase-admin.ts:7` — `eyJhbGci…9fQ4`
- `app/api/admin/route.ts:12`

**How to fix**
<Numbered steps for this codebase, with a snippet if a snippet helps. Include
rotation/cleanup when the secret has already leaked. End with how to confirm it
worked.>

**Effort:** <10 minutes / an hour / an afternoon>

---

## High
<Same four-field structure, numbered H1, H2, …>

## Medium
<M1, M2, … — these can be shorter, two or three lines per field>

## Low
<A compact list is fine here: one line each, with file:line.>

---

## Checked and clean

<List what you verified and found no problem with. This is not filler — it tells the
reader the scope of the audit and stops them re-auditing the same ground.>

- Secrets in git history — no `.env` file has ever been committed
- CORS — no CORS configuration present; the app is same-origin, which is correct here

## Not checked

<Everything you could not verify, and what it would take. Be honest here.>

- Live database RLS state — needs `supabase link` or dashboard access. Migrations in
  `supabase/migrations/` suggest RLS is on for 3 of 4 tables, but the live database is
  the authority.
- Deploy-time environment variables in Vercel — not visible from the repository.

---

## Fix these three first

1. <Highest impact per minute spent> — <effort>
2. <…>
3. <…>
```

---

## Notes on writing the findings

- **One finding per problem, not per occurrence.** Ten routes missing auth is one
  finding with ten locations, not ten findings.
- **Rank within severity.** The first Critical should be the worst Critical.
- **Never write "consider" or "you may want to".** Say what to do.
- **Quantify the loss when you can.** "An unauthenticated endpoint that calls GPT-4
  costs you roughly $0.03 per request; a scraper doing 10 requests/second costs
  $26/hour."
- **If a finding depends on something you could not see, say so in the finding**
  rather than dropping it: "If `notes` has RLS enabled in the live database, this is
  not exploitable. Verify before dismissing."
