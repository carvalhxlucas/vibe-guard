# The full pre-launch list

Seven sections. Each item: what to check, how to check it, and whether it blocks a
launch. "Blocking" means real user data, real money, or the app's reputation is at
stake on day one.

Each `rg` command names a path. Ripgrep with no path searches standard input rather
than the project, and returns nothing without an error — indistinguishable from a
clean result.

---

## 1. Secrets and environment variables

| Item | Blocking | How to check |
|---|---|---|
| No secret in the client bundle | **Yes** | `npm run build`, then grep `.next/static` for `sk_live`, `sk-proj`, `SERVICE_ROLE`, and a JWT prefix |
| Every `.env` file is gitignored | **Yes** | `git ls-files \| rg '\.env'` returns nothing but `.env.example` |
| No secret in git history | **Yes** if found | `git log --all --oneline -- '*.env*'`; also grep history for provider prefixes. A key that was ever committed must be rotated, not deleted |
| Production env vars set in the host | **Yes** | Ask. Every key in `.env.local` must exist in Vercel → Settings → Environment Variables, scoped to Production |
| Server secrets have no public prefix | **Yes** | `rg 'NEXT_PUBLIC_[A-Z_]*(SECRET\|SERVICE_ROLE\|PRIVATE)' .` |
| Different keys for preview and production | No | Ask. Preview deployments are public URLs — they should not hold production credentials |
| `.env.example` documents every variable | No | Compare its keys against `rg -o 'process\.env\.[A-Z_]+' . \| sort -u` |

Preview deployments deserve their own line: on Vercel they are publicly reachable by
URL. If preview points at the production database, every preview URL is a door into
real user data. Ask.

---

## 2. Database

| Item | Blocking | How to check |
|---|---|---|
| RLS on for every table with user data | **Yes** | Run the `rls-check` skill. Do not take migrations as proof |
| Backups on, and recent | **Yes** | Ask: Supabase → Database → Backups. Free tier retention is short — know the number |
| Restore tested once | No | Ask. An untested backup is a hope, not a plan |
| Destructive migrations reviewed | **Yes** if present | `rg -n 'drop (table\|column)\|alter column.*type' supabase/migrations` — these are not undone by a code rollback |
| Connection pooling for serverless | No | Serverless functions open a connection each. Use the Supabase pooler URL (port 6543) for the app, the direct URL (5432) for migrations |
| Indexes on RLS filter columns | No | A policy on `user_id` with no index sequential-scans every query |
| Seed and test data removed | No | `rg -in 'test@\|dummy\|lorem ipsum\|foo@bar' supabase prisma db 2>/dev/null` — migrations and seeds |

---

## 3. Errors, logging, monitoring

| Item | Blocking | How to check |
|---|---|---|
| No stack traces returned to users | **Yes** | `rg -n 'error\.stack\|error\.message' --glob '!node_modules' .` inside response bodies |
| No secrets or tokens in logs | **Yes** | `rg -n 'console\.(log\|error)\(' . \| rg -i 'token\|session\|password\|key\|user\b'` — Vercel logs are readable by everyone on the team and by any log drain |
| Error tracking installed | No, but close | `rg -n 'sentry\|bugsnag\|highlight\|posthog' package.json`. Without it, you find out from a user, days later |
| Custom 404 and 500 pages | No | `fd 'not-found|error|global-error' app` |
| Uptime check on the main URL | No | Ask. Free options exist; a down app nobody knows is down is the worst case |
| `console.log` cleanup | No | Debug logging in production is noise that hides the real error |

An error boundary that swallows the error and shows "Something went wrong" with no
logging is worse than a crash — it fails silently and you never hear about it. Check
that `global-error.tsx` reports somewhere.

---

## 4. Transport, headers, cookies

| Item | Blocking | How to check |
|---|---|---|
| HTTPS enforced | **Yes** | Automatic on Vercel/Netlify. On a custom server, verify the redirect |
| HSTS header | No | `rg -n 'Strict-Transport-Security' next.config.* vercel.json` |
| `X-Content-Type-Options: nosniff` | No | Same files |
| Frame protection | No | `X-Frame-Options: DENY` or a CSP `frame-ancestors`. Stops clickjacking |
| `Referrer-Policy` | No | `strict-origin-when-cross-origin` |
| CSP | No | Valuable, and it breaks sites. Ship `Content-Security-Policy-Report-Only` first |
| Session cookie flags | **Yes** if hand-rolled | `httpOnly`, `secure`, `sameSite=lax`. Auth libraries set these correctly; hand-written `res.cookie` calls usually do not |
| No mixed content | No | `rg -n "http://" --glob '!*.md' .` minus localhost |
| Custom domain + certificate | No | Ask. Also check the `www`/apex redirect resolves one way |

---

## 5. Cost, abuse, and staying up

This section is where solo founders actually get hurt. A security hole might never be
found; an unlimited AI endpoint gets found in hours.

Two different failures live here. **Cost**: someone spends your money. **Availability**:
someone makes the app stop working for everybody, which needs no volume at all when a
single request is expensive enough. The first rows cover cost, the last rows cover
availability.

| Item | Blocking | How to check |
|---|---|---|
| Hard spending cap at every paid provider | **Yes** | Ask: OpenAI, Anthropic, Twilio, and the hosting plan all support one. This is the only control that still works when the code is wrong |
| Rate limits on expensive endpoints | **Yes** | `rg -n 'ratelimit\|arcjet\|express-rate-limit' .`, cross-referenced against routes calling paid APIs |
| Auth required on AI endpoints | **Yes** | An unauthenticated AI route is a free API for everyone who finds it |
| Upload size and type limits | No | `rg -n 'maxFileSize\|bodyParser\|sizeLimit\|multer' .` |
| Billing alerts | No | Ask. An alert at 2× expected spend, sent to an address you actually read |
| Serverless function timeouts | No | `vercel.json` → `maxDuration`. A hung function billed for 300 seconds, repeatedly, adds up |
| Bot protection on signup | No | Vercel Firewall, Cloudflare Turnstile, or the host's built-in option |
| Shared database client, pooled port | **Yes** on serverless | `rg -n 'new PrismaClient\|new Pool\|new Client' .` inside route handlers — one per request exhausts the pool. App on the pooler (6543), migrations on 5432 |
| Every list query has a row ceiling | **Yes** | `rg -n '\.select\(' .` and `rg -n 'findMany' .` without `limit`/`range`/`take`. Fine at 40 rows, fatal at 400,000 |
| Request body size capped | No | `rg -n 'content-length\|sizeLimit\|bodyParser' .`. Vercel caps at 4.5MB; a cap you own survives moving host |
| Outbound calls have a timeout | No | `rg -n 'fetch\(' . \| rg -v 'signal'`. A hung provider hangs your function for the full `maxDuration`, billed |
| Retries bounded, with backoff | No | `rg -n -i 'retry\|backoff' .`. A tight retry loop turns their outage into yours |
| Heavy work off the request path | No | Image, PDF, video, spreadsheet work in a handler, sized by the caller's upload. Queue it, return `202` |

---

## 6. Payments

Skip entirely if the app takes no money. If it does, all of these block.

| Item | How to check |
|---|---|
| Live keys are live, test keys are gone | `rg -n 'sk_test_\|pk_test_' .` — shipping test keys means no payment ever arrives |
| Webhook signature verified | `rg -n 'constructEvent\|webhooks\.verify' .`. Without it, anyone can POST "payment succeeded" and get the product free |
| Webhook endpoint is idempotent | Stripe retries. Charging or provisioning twice on a retry is a support ticket at best |
| Prices computed server-side | `rg -n 'amount\|price' app/api` — a price that arrives from the browser is a price the customer chose |
| Entitlement checked server-side on every use | Not just at checkout. A `is_pro` flag the user can write is not an entitlement |
| Refund and failed-payment paths handled | `checkout.session.completed` alone is not enough — handle `invoice.payment_failed` and subscription cancellation |
| Webhook endpoint registered for production | Ask. The test-mode endpoint does not fire for live payments |

---

## 7. Data, privacy, the legal minimum

Scaled to a small app — not legal advice, just the parts that are cheap now and
expensive later.

| Item | Blocking | Notes |
|---|---|---|
| Privacy policy and terms exist | No | Required by Stripe, the app stores, and most ad platforms. A generator is fine to start |
| Cookie/analytics consent where required | No | GDPR (EU), LGPD (Brazil). Privacy-first analytics without cookies avoids most of the requirement |
| Account deletion actually deletes | No | Both laws give users this right. A `deleted_at` column that keeps everything is not deletion |
| Only collect what you use | No | Data you never collected cannot leak |
| Third-party scripts audited | No | Every analytics or chat widget script runs with full access to your page, including your users' input |
| Contact address for security reports | No | An email in the README or a `/.well-known/security.txt`. Without one, someone who finds a hole has no way to tell you — so they post it publicly |

---

## The five-minute version

If the user has no patience for the full list, these five cover most of the real risk:

1. Build, and grep the output for your secrets.
2. Confirm RLS is on for every table holding user data.
3. Set a hard spending cap at every paid API provider.
4. Confirm a database backup exists, and that you know how to restore it.
5. Confirm you can roll back the deploy, and that you would find out it needed rolling
   back from something other than an angry user.
