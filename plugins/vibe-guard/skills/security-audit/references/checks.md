# Detection recipes

One section per check. Each gives: what to run, what a true positive looks like, what a
false positive looks like, and the fix to recommend. Adapt the commands to the stack —
they assume a JS/TS project with `rg` or `grep` available.

Throughout: exclude `node_modules`, `.next`, `dist`, `build`, and lockfiles. `rg`
respects `.gitignore` by default, which is usually what you want — except in check 1,
where ignored files still matter if they were ever committed.

**Every `rg` below names a path — usually `.`** Ripgrep with no path argument searches
standard input, not the project. Run from a tool with no terminal attached, it returns
nothing and exits cleanly, which reads exactly like a clean result. If you write your
own search, give it a path.

---

## Check 1 — Exposed secrets

### Detect

```bash
# a. Credentials in tracked source
rg -n --hidden -g '!.git' -g '!node_modules' \
  -e 'sk_live_[A-Za-z0-9]{16,}' -e 'sk_test_[A-Za-z0-9]{16,}' -e 'whsec_[A-Za-z0-9]{16,}' \
  -e 'sk-(proj-|svcacct-)?[A-Za-z0-9_-]{32,}' -e 'sk-ant-[A-Za-z0-9_-]{20,}' \
  -e 'AKIA[0-9A-Z]{16}' -e 'AIza[0-9A-Za-z_-]{35}' -e 'gh[pousr]_[A-Za-z0-9]{36,}' \
  -e 'sb_secret_[A-Za-z0-9_-]{20,}' -e 'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.' \
  -e 'BEGIN [A-Z ]*PRIVATE KEY' \
  -e '(postgres|postgresql|mysql|mongodb\+srv)://[^:]+:[^@]+@' .

# b. Secrets behind a public (client-bundled) prefix — the classic vibecoder mistake
rg -n '(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|NUXT_PUBLIC|GATSBY)_[A-Z0-9_]*(SERVICE_ROLE|SECRET|PRIVATE|PASSWORD)' .

# c. Server-only env vars read from a file that runs in the browser
rg -ln "'use client'|\"use client\"" . | xargs rg -n 'process\.env\.[A-Z_]+' 2>/dev/null \
  | rg -v 'NEXT_PUBLIC_'

# d. Is .env actually ignored, and was it ever committed?
cat .gitignore 2>/dev/null | rg -n 'env'
git ls-files | rg '(^|/)\.env'
git log --oneline --all -- '*.env*' | head

# e. Secrets baked into a built bundle or a Dockerfile
rg -n 'ENV [A-Z_]*(KEY|SECRET|TOKEN|PASSWORD)' Dockerfile* 2>/dev/null
```

### True positive
A high-entropy value matching a known provider prefix, assigned in a tracked file; or
any secret-shaped value under a public env prefix; or `.env.local` appearing in
`git ls-files`.

### False positive
`.env.example` / `.env.sample` with placeholder values. Publishable keys
(`pk_live_`, `pk_test_`), the Supabase `anon` key, and `NEXT_PUBLIC_SUPABASE_URL` are
public by design — these are **not** findings on their own. The anon key is only a
finding in combination with check 2 (RLS off), and then the finding is the RLS, not
the key.

### Fix to recommend
Move the value to `.env.local`, confirm `.env*` (except `.env.example`) is in
`.gitignore`, read it server-side only via `process.env`, and add it to the hosting
provider's environment variables. **Rotate the credential in the provider's dashboard**
if it ever reached a commit — removing the line does not remove it from git history,
and public-repo scrapers find keys within minutes. Severity for a committed-and-still-
valid key is Critical.

---

## Check 2 — Row Level Security (Supabase / Postgres)

### Detect

```bash
# Which tables exist and how are they created?
fd -e sql . supabase migrations 2>/dev/null || find . -name '*.sql' -not -path '*/node_modules/*'
rg -n -i 'create table|enable row level security|create policy|force row level security' --glob '*.sql' .

# Is the client created with the anon key or the service key, and where?
rg -n 'createClient\(' --glob '!node_modules' .
rg -n 'SERVICE_ROLE|service_role|serviceRole' .
```

For each table found in migrations, check that a matching
`ALTER TABLE <t> ENABLE ROW LEVEL SECURITY;` exists **and** that at least one policy
exists per operation the app performs (select/insert/update/delete).

If the user has the Supabase CLI linked, this is worth asking them to run — it is the
authoritative answer and a migration file can lie about the live database:

```sql
select relname,
       relrowsecurity  as rls_enabled,
       relforcerowsecurity as rls_forced
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r';

select schemaname, tablename, policyname, cmd, qual, with_check
from pg_policies where schemaname = 'public';
```

### True positive
A table holding user data with no `ENABLE ROW LEVEL SECURITY`, or RLS enabled with a
policy whose `USING` clause is `true` (allows every row to every caller), or a table
with RLS enabled and **zero** policies while the app reads it with the anon key —
that last one silently returns empty results and usually gets "fixed" by the user
disabling RLS.

Also a true positive, and commonly missed: `service_role` client created in a file that
is not clearly server-only. The service role key bypasses RLS entirely.

### False positive
Tables that are intentionally public read (a `posts` table for a blog, a `plans`
pricing table). A policy of `using (true)` for `select` on genuinely public data is
correct. Ask what the table holds before calling it.

### Fix to recommend
```sql
alter table public.notes enable row level security;

create policy "owners read their notes"
  on public.notes for select
  using (auth.uid() = user_id);

create policy "owners write their notes"
  on public.notes for insert
  with check (auth.uid() = user_id);
```
Explain the one-sentence version: "RLS is the database itself checking who is asking.
Without it, anyone who opens your site's JavaScript can read the whole table, because
the anon key is public — it is supposed to be public. RLS is what makes that safe."

---

## Check 3 — API route authorization

### Detect

```bash
# Every server entry point
fd 'route\.(ts|js)$' app 2>/dev/null
fd . pages/api 2>/dev/null
rg -ln "'use server'" .
# Which of them never check identity? That list is the finding.
# --files-without-match, spelled out: in ripgrep `-L` means --follow, not
# --files-without-match as it does in grep, so `rg -L -l` returns the opposite set.
rg --files-without-match 'getUser|getSession|auth\(\)|currentUser|verifyToken|requireUser' \
  --glob 'route.{ts,js}' --glob 'pages/api/**' --glob '!node_modules' .
```

Read every handler that performs a write, a delete, a payment, an email send, or an
admin action. For each, answer two questions:

1. **Authentication** — does it establish *who* is calling, before doing the work?
2. **Authorization** — does it check that this caller owns *the specific record* being
   touched? A handler that takes `userId` or `orderId` from the request body and
   queries with it, without comparing to the session, lets any logged-in user act on
   anyone's data by changing a number.

Also check webhook handlers (`/api/webhooks/stripe`, etc.) for signature verification —
`stripe.webhooks.constructEvent(body, sig, secret)`. A webhook without signature
verification lets anyone POST "payment succeeded" to your app.

### True positive
A mutating handler with no session lookup. A handler that reads an identifier from
`req.body`/`params` and uses it directly in a query. A `'use server'` action with no
auth check — server actions are public HTTP endpoints, which surprises most people.
A webhook route with no signature check.

### False positive
Genuinely public endpoints: health checks, public content feeds, the login route
itself. Handlers where an auth middleware covers the whole path — verify the
middleware actually matches the path via its `matcher` config before dismissing.

### Fix to recommend
```ts
const { data: { user } } = await supabase.auth.getUser();
if (!user) return new Response('Unauthorized', { status: 401 });

// Authorize the specific record, do not trust an ID from the client:
const { data: note } = await supabase
  .from('notes').select().eq('id', params.id).eq('user_id', user.id).single();
if (!note) return new Response('Not found', { status: 404 });
```
Note that `middleware.ts` in Next.js is a convenience, not a security boundary for
data access — each route that touches data should still confirm ownership.

---

## Check 4 — Input validation

### Detect

```bash
rg -n 'await req\.json\(\)|request\.json\(\)|req\.body|searchParams\.get' --glob '!node_modules' .
rg -n 'zod|valibot|yup|joi|@sinclair/typebox|ajv' package.json
# Raw SQL built by concatenation or interpolation
rg -n '(query|execute|raw|sql)\s*\(\s*[`"\x27][^`"\x27]*\$\{' --glob '!node_modules' .
rg -n 'dangerouslySetInnerHTML|innerHTML\s*=' --glob '!node_modules' .
```

### True positive
`const body = await req.json()` followed by using `body.x` directly in a query, a
price calculation, or a database write. String-interpolated SQL. A TypeScript
interface used as if it validated anything — types vanish at runtime and are not
validation; this is worth stating explicitly, it is a very common misunderstanding.
User-controlled HTML rendered via `dangerouslySetInnerHTML` without sanitization.

### False positive
Supabase/Prisma/Drizzle query builders with parameter binding are not SQL injection
even with user input — flag those under authorization (check 3) instead, if at all.
Validation applied one layer up (a shared `validateBody` helper) counts as validated.

### Fix to recommend
```ts
import { z } from 'zod';
const Body = z.object({ title: z.string().min(1).max(200), amountCents: z.number().int().positive() });

const parsed = Body.safeParse(await req.json());
if (!parsed.success) return Response.json({ error: 'Invalid request' }, { status: 400 });
```
Emphasize: never trust a price, quantity, role, or user ID that arrived from the
browser. Recompute prices server-side from your own database.

---

## Check 5 — Rate limiting and abuse

### Detect

```bash
rg -n 'ratelimit|rate-limit|@upstash/ratelimit|express-rate-limit|limiter|arcjet' --glob '!node_modules' .
# Endpoints that cost money or send things
rg -ln 'openai|anthropic|resend|sendgrid|nodemailer|twilio|stripe' --glob '!node_modules' .
```

Cross-reference: any route calling a paid API, sending email/SMS, creating accounts,
or resetting passwords, with no limiter in the path.

### True positive
An AI-calling endpoint reachable without authentication and without a limit — this is
the single most common way a solo founder wakes up to a four-figure bill. Also: signup
and password-reset endpoints with no limit (spam and user enumeration), and file
uploads with no size cap.

### False positive
Routes already behind a provider-level limit (Vercel Firewall rules, Cloudflare), or a
limiter applied in middleware covering the path. Verify before dismissing.

### Fix to recommend
Per-user limit when authenticated, per-IP when not. Upstash Ratelimit is the usual
low-friction choice on Vercel:
```ts
const { success } = await ratelimit.limit(user?.id ?? ip);
if (!success) return new Response('Too many requests', { status: 429 });
```
Also recommend a hard spending cap in the provider dashboard (OpenAI, Anthropic, and
Twilio all support one). A cap is the only control that works when the code is wrong.

---

## Check 6 — CORS

### Detect

```bash
rg -n -i 'access-control-allow-origin|cors\(|Access-Control-Allow-Credentials' --glob '!node_modules' .
rg -n 'origin:\s*[\x27"`]?(\*|true|req\.headers)' --glob '!node_modules' .
cat vercel.json next.config.* 2>/dev/null | rg -n -A3 -i 'headers|cors'
```

### True positive
`Access-Control-Allow-Origin: *` on an endpoint that reads cookies or an auth header.
Reflecting `req.headers.origin` back into the allow header (this permits every site).
`Access-Control-Allow-Credentials: true` combined with a wildcard or reflected origin —
this is the combination that lets another website make authenticated requests as your
logged-in user.

### False positive
Wildcard CORS on a genuinely public, unauthenticated, read-only endpoint is fine —
say so rather than padding the report. Same-origin apps (the typical Next.js app
calling its own `/api`) need no CORS config at all; absence of CORS is not a finding.

### Fix to recommend
An explicit allowlist of your own origins, and credentials only alongside an exact
origin match.

---

## Check 7 — Security headers, transport, cookies

### Detect

```bash
rg -n -A10 'async headers\(\)' next.config.* 2>/dev/null
rg -n 'headers' vercel.json netlify.toml 2>/dev/null
rg -n 'helmet' package.json
rg -n 'cookies\(\)\.set|res\.cookie|setHeader\(.Set-Cookie' --glob '!node_modules' .
rg -n 'http://' --glob '!node_modules' --glob '!*.md' . | rg -v 'localhost|127\.0\.0\.1|schema|w3\.org|example'
```

### True positive
No `Strict-Transport-Security`, `X-Frame-Options`/`frame-ancestors`,
`X-Content-Type-Options`, or `Referrer-Policy`. Hand-set session cookies missing
`httpOnly`, `secure`, or `sameSite`. Production requests to `http://` URLs.

### False positive
Vercel and Netlify terminate TLS and redirect HTTP to HTTPS by default, so "no HTTPS"
is not a finding on those platforms — the finding is the missing HSTS header.
Auth libraries (Supabase Auth, Auth.js, Clerk) set their own cookie flags correctly;
only hand-rolled cookies are in scope here. A missing CSP on a small app is Medium at
most, and a badly configured CSP breaks the site, so recommend it in report-only mode
with a note to test in `Content-Security-Policy-Report-Only` first.

### Fix to recommend
```js
// next.config.js
async headers() {
  return [{ source: '/:path*', headers: [
    { key: 'Strict-Transport-Security', value: 'max-age=63072000; includeSubDomains; preload' },
    { key: 'X-Content-Type-Options', value: 'nosniff' },
    { key: 'X-Frame-Options', value: 'DENY' },
    { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' },
  ]}];
}
```

---

## Check 8 — Dependencies and error hygiene

### Detect

```bash
npm audit --omit=dev 2>/dev/null | tail -20   # or: pnpm audit / yarn npm audit
rg -n 'console\.(log|error)\((.*)(token|secret|key|password|session|user)' --glob '!node_modules' .
rg -n 'stack|error\.message' --glob '!node_modules' . | rg -i 'json|res\.send|return Response'
rg -n 'NODE_ENV' next.config.* 2>/dev/null
```

### True positive
Critical/high advisories on runtime (non-dev) dependencies. `console.log` of a token,
session, or full user object — on Vercel these land in logs that anyone on the team,
and any log drain, can read. Error handlers returning `error.message` or `error.stack`
to the client: stack traces disclose file paths, library versions, and sometimes query
contents.

### False positive
Dev-only advisories (build tooling) are Low unless the build is public-facing.
Transitive advisories with no reachable path from your code are Low — say why.

### Fix to recommend
`npm audit fix`, then a manual upgrade for what remains. Log an error ID, not the
error: return `{ error: 'Something went wrong', id }` to the client and keep the detail
server-side.

---

## Check 9 — Resource exhaustion and resilience

The other eight checks ask "can someone take something". This one asks "can someone
make it stop working". The attacker needs no credentials and no skill: they send a
normal request, or the same normal request a few thousand times, and the app falls
over for everybody.

Rate limiting (check 5) is the traffic-volume half of this and is covered there. This
check is about the requests that are expensive *one at a time* — where one caller with
a laptop is enough.

### Detect

```bash
# a. Database connections: a new client per request, or the direct port on serverless
rg -n 'postgres(ql)?://[^ ]*:5432' --glob '!node_modules' --glob '!*.md' .
rg -n 'new (Pool|Client)\(|new PrismaClient\(' --glob '!node_modules' .
rg -n 'max:\s*[0-9]+|connection_limit=|pool_timeout=' --glob '!node_modules' .

# b. Reads with no ceiling on how many rows come back
rg -n '\.select\(' --glob '!node_modules' -A3 . | rg -v '\.(limit|range|single|maybeSingle)\('
rg -n 'findMany\(' -A4 --glob '!node_modules' . | rg -v 'take:'
rg -n -i 'select \*' --glob '!node_modules' --glob '!*.md' .

# c. A query inside a loop — one request becomes N queries
rg -n -A6 '\b(for|while)\b|\.(forEach|map)\(' --glob '!node_modules' . \
  | rg 'await .*(\.from\(|findMany|findUnique|findFirst|\.query\()'

# d. Request bodies read with no size ceiling
rg -n 'await (req|request)\.(json|text|formData|arrayBuffer)\(\)' --glob '!node_modules' .
rg -n 'bodyParser|sizeLimit|maxFileSize|multer|formidable|express\.json\(' --glob '!node_modules' .

# e. Outbound calls with no timeout, retries with no ceiling
rg -n 'fetch\(|axios\.(get|post|put|delete)|got\(' --glob '!node_modules' . \
  | rg -v 'signal|timeout|AbortController|AbortSignal'
rg -n -i 'retry|retries|maxAttempts|backoff' --glob '!node_modules' .

# f. Regexes built from user input, or nested quantifiers
rg -n 'new RegExp\(' --glob '!node_modules' .
rg -n '\([^)]*[+*]\)[+*]' --glob '!node_modules' --glob '!*.md' .

# g. Heavy work sitting directly in a request path
rg -n 'maxDuration' vercel.json next.config.* 2>/dev/null
rg -ln 'sharp|jimp|puppeteer|playwright|pdf-lib|pdfkit|archiver|xlsx|csv-parse|ffmpeg' \
  --glob '!node_modules' .
```

### True positive

- **A new database client per request on serverless.** `new PrismaClient()` or
  `new Pool()` at the top of a route handler instead of a shared module-level
  singleton, or the direct Postgres URL (port `5432`) used by the app. Each
  invocation opens its own connection; Supabase's free tier allows about 60. A
  traffic spike exhausts the pool and every request — including the ones already
  paid for — fails with a connection error. Nothing is hacked; the app is simply down.
- **A read with no row ceiling on a table that grows.** `.select('*')` on `messages`,
  `events`, or `logs` with no `.limit()` or `.range()`, and no `where` narrowing it to
  one owner. Fine on day one with 40 rows. At 400,000 rows the same endpoint pulls the
  table into memory on every call.
- **A query inside a loop.** Fetching a list, then querying once per item. Twenty
  items is 21 round trips; the endpoint gets slower as the data grows, and each slow
  request holds a connection the whole time.
- **A body read with no size check.** `await req.json()` where the caller controls the
  length, with no `Content-Length` gate — a 50MB JSON body is parsed in full before any
  validation runs. Same for uploads accepted without a byte cap, and for deeply nested
  JSON, which costs far more to parse than its size suggests.
- **An outbound call with no timeout.** `fetch()` to a payment provider, an AI API, or
  a webhook target with no `signal`. When that service hangs, your function hangs with
  it until the platform kills it — billed for the full duration, holding a connection,
  and returning nothing.
- **Retries with no ceiling or no backoff.** A handler that retries a failing
  dependency in a tight loop turns one outage into your own outage, and multiplies the
  load on whatever already broke.
- **A regex built from user input, or one with a nested quantifier** like
  `(a+)+$` or `(\s*\w+)*@`, applied to a user-supplied string. Some short inputs make
  these run effectively forever — one request pins a CPU. Email and URL validators
  written by hand are the usual place this appears.
- **Image, PDF, video, or spreadsheet processing directly in a request handler**, sized
  by whatever the caller uploads. One 8000×8000 PNG is a memory spike; ten concurrent
  ones take the instance out.

### False positive

- A pooled connection string (Supabase pooler on port `6543`, Neon/PgBouncer, Prisma
  Accelerate, Drizzle over an HTTP driver) is the fix already applied — not a finding.
  The direct URL used only by migrations or seed scripts is correct.
- An unbounded `select` on a table that is bounded by design (settings, plans,
  countries, feature flags) is fine. Say why you dismissed it.
- Framework defaults that already cap things: `express.json()` defaults to 100kb,
  Vercel caps a serverless request body at 4.5MB and function duration at
  `maxDuration`. These bound the damage, so the finding is at most Medium — but a cap
  that exists only because of a platform default disappears the day the app moves, so
  it is worth one line.
- A retry with exponential backoff and a maximum attempt count is correct engineering.
- Regexes over a string the app itself produced, or with no nested quantifier, are not
  in scope.
- Work already moved off the request path — a queue, a cron job, a background
  function, a webhook that acknowledges first and processes after — is the fix.

### Severity note

Whether these are High or Medium depends almost entirely on one question: **can an
unauthenticated caller reach it?** An expensive endpoint behind a login, with a rate
limit, used by 200 known customers, is Medium — it will hurt one day, on a Tuesday.
The same endpoint public is High: anyone who finds the URL can take the app down for
everyone, repeatedly, from a phone, and there is nothing to revoke afterwards.

State that reasoning in the finding. It is what tells the reader which of these to fix
tonight and which to put in next week's list.

### Fix to recommend

```ts
// a. One client for the whole process, and the pooled port on serverless
// lib/db.ts — imported everywhere, never constructed inside a handler
export const prisma = globalThis.__prisma ?? (globalThis.__prisma = new PrismaClient());
// DATABASE_URL  → the pooler (…pooler.supabase.com:6543) for the app
// DIRECT_URL    → port 5432, migrations only

// b. Every list read gets a ceiling, and the ceiling is yours, not the client's
const perPage = Math.min(Number(searchParams.get('perPage') ?? 20), 100);
const { data } = await supabase
  .from('messages').select('id, body, created_at')   // named columns, not *
  .eq('user_id', user.id)
  .order('created_at', { ascending: false })
  .range(page * perPage, page * perPage + perPage - 1);

// c. One query instead of N — collect the ids, then fetch once
const authors = await supabase.from('profiles').select().in('id', post.authorIds);

// d. Refuse an oversized body before parsing it
const len = Number(req.headers.get('content-length') ?? 0);
if (len > 100_000) return new Response('Payload too large', { status: 413 });

// e. Every outbound call gets a deadline
const res = await fetch(url, { signal: AbortSignal.timeout(10_000) });
```

Alongside the code:

- **Cap the function, not just the request.** `maxDuration` in `vercel.json` set to
  what the endpoint actually needs — 10 seconds, not the 300 the platform allows.
- **Move heavy work off the request path.** Accept the upload, return `202`, process in
  a background function, queue, or cron. The user gets an answer immediately and one
  slow job cannot take the endpoint down.
- **Validate before you do work, not after.** Check the schema and the size limits
  first, so a malformed 10MB payload costs a `400` rather than a parse.
- **Put a provider-level limit in front of it.** Vercel Firewall or Cloudflare rate
  rules stop the flood before it reaches a function you are billed for. Application
  code cannot shed load it has already been handed.
- **Index the columns your policies and filters use.** An RLS policy on `user_id` with
  no index sequential-scans the table on every query, which turns ordinary traffic into
  a load problem.
