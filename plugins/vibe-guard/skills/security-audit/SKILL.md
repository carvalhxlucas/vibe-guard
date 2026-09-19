---
name: security-audit
description: Audits a project for security and robustness problems before it meets real users — exposed secrets, missing Supabase/Postgres Row Level Security, API routes with no authorization, missing input validation and rate limiting, open CORS, missing security headers, and vulnerable dependencies. Produces a plain-language report with severities and fixes, and changes no code. Use whenever someone asks for any kind of pre-launch look over an app that will be public, however they phrase it: "is my app secure", "check my security", "did I leak any keys", "is my RLS set up", "am I ready to launch", "I want to put this online tomorrow", "real people are going to sign up", "can you look this over", "anything here going to bite me", "what am I missing before I ship". Also use after a burst of AI-generated code lands in an app that handles user data or money.
---

# Security audit

Scan the project and produce a report. **Report only — do not change any code.**

The reader is a solo founder or indie developer who ships fast with AI tools and does
not have a security background. They are smart. They just have not seen these failure
modes before. Write for that person.

## Non-negotiable rules

1. **Never edit, fix, or refactor anything during this skill.** Not even an obvious
   one-line fix. The value of an audit is that the user reads it and decides. If they
   ask for fixes afterwards, that is a separate request.
2. **Never print a secret you find.** Show at most the first 6 and last 4 characters,
   plus `file:line`. A report that quotes the key in full leaks it again into the
   transcript.
3. **Report what you verified, not what is typical.** If you could not check something
   (no database access, no deploy config in the repo), say so in "Not checked" instead
   of guessing. A fabricated finding destroys the user's trust in the real ones.
4. **No jargon without a translation.** "CSRF", "SSRF", "IDOR" mean nothing to this
   reader. Say what an attacker actually does and what the user actually loses.

## Step 1 — Map the stack (2 minutes, no deep reading)

Establish what you are auditing before you look for problems:

```bash
ls -a                          # project root: framework config, .env files, .gitignore
cat package.json 2>/dev/null   # framework, ORM, auth library, validation library
```

Record: framework (Next.js App Router / Pages Router, Vite+React, Remix, Express,
other), database layer (Supabase client, Prisma, Drizzle, raw `pg`), auth
(Supabase Auth, NextAuth/Auth.js, Clerk, hand-rolled), hosting (`vercel.json`,
`netlify.toml`, Dockerfile), and whether the repo is a git repository.

If the project is not one of the stacks above, still run every check — the checks are
described by what they look for, not by framework.

## Step 2 — Run the checks

Run all eight. `references/checks.md` has the detection recipes (exact grep patterns,
what a true positive looks like, what a false positive looks like) and the fix
guidance for each. Read that file before starting the checks.

| # | Check | Looking for |
|---|-------|-------------|
| 1 | Exposed secrets | Real credentials in tracked files, in git history, or behind a client-side env prefix |
| 2 | Row Level Security | Supabase/Postgres tables reachable by the anon key with RLS off or with a policy that allows everything |
| 3 | API route authorization | Route handlers and server actions that never check who is calling, or that trust a user-supplied ID |
| 4 | Input validation | Request bodies and query params used without a schema; string-concatenated SQL |
| 5 | Rate limiting and abuse | Expensive or costly endpoints (AI calls, email, signup, password reset) with no limit |
| 6 | CORS | `Access-Control-Allow-Origin: *` on authenticated endpoints, or reflected origins |
| 7 | Security headers and transport | Missing HSTS/CSP/frame protections, mixed content, cookies without `httpOnly`/`Secure`/`SameSite` |
| 8 | Dependencies and error hygiene | Known-vulnerable packages, stack traces returned to users, secrets written to logs |

Work breadth-first. Getting a shallow pass over all eight checks is worth more than an
exhaustive pass over check 1. Then go deep only on the areas that showed hits.

Useful global sweeps:

```bash
# Files the user thinks are private but git is tracking
git ls-files | grep -Ei '(^|/)\.env' || echo "no tracked .env files"
# Was a secret ever committed and then deleted? Deletion does not un-leak it.
git log --oneline --all -- '*.env*' 2>/dev/null | head
# Every server entry point worth reading
find . -path ./node_modules -prune -o \( -name 'route.ts' -o -name 'route.js' -o -name '*.server.ts' -o -name 'actions.ts' \) -print 2>/dev/null | head -50
```

## Step 3 — Assign severity

Severity is about consequence, not about how sophisticated the attack is. Most real
damage to small apps comes from embarrassingly simple things.

- **Critical** — Someone can take it today with no special skill: read or delete every
  user's data, spend your money, or log in as anyone. Examples: service_role key in
  client-side code, RLS off on a table with user data, payment webhook with no
  signature check, admin route with no auth check.
- **High** — Requires one extra step or a specific condition, but the loss is still
  severe. Examples: user-supplied ID trusted in a query (one user reads another's
  rows), no rate limit on an endpoint that costs you money per call, secret in git
  history that is still valid.
- **Medium** — Real but bounded, or needs an unlikely precondition. Examples: missing
  security headers, verbose error messages exposing stack traces, dependency
  vulnerability with no exploit path in your usage.
- **Low** — Hygiene. Worth fixing, nothing burns if you do it next week.

When you cannot tell whether a finding is Critical or High, say so in one line and
rank it as the higher of the two. Under-calling a real leak costs more than an
occasional over-call.

## Step 4 — Write the report

Use the structure in `references/report-template.md`. It is the required shape of the
output, including the four fields every finding must have:

- **What it is** — the problem in plain language, no security vocabulary.
- **Why it matters** — the concrete bad day: what an attacker does, what you lose.
- **Where** — `file:line` for each occurrence. Secrets redacted.
- **How to fix** — the specific change for *this* codebase, with a code snippet where a
  snippet helps. Not "implement proper authentication".

Deliver the report as a Markdown file at `SECURITY-AUDIT.md` in the project root
(this is the one file this skill writes) and summarize the headline numbers in chat:
count by severity plus the single most urgent item. Ask before overwriting an existing
`SECURITY-AUDIT.md`.

If the user asks for a shareable version, publishing the report as an artifact is fine
— but strip `file:line` detail and every redacted secret fragment first if it will
leave their machine.

## Step 5 — Close the loop

End with the three things that buy the most safety for the least work, in order, and
offer to fix them. Do not start fixing until they say yes. If the report is clean,
say so plainly and name what you checked — "no findings" is only useful when the
reader can see the scope behind it.
