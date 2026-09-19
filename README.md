# VibeGuard

**Security guardrails for people who ship fast with AI.**

You built the thing in a weekend. It works. Real people are about to put their email
addresses, their data, and maybe their credit cards into it. VibeGuard is the part
nobody taught you: the checks that happen before that goes wrong.

It is a [Claude Code](https://claude.com/claude-code) plugin — four skills, a reviewer
agent, and a hook that never sleeps.

```shell
/plugin marketplace add carvalhxlucas/vibe-guard
/plugin install vibe-guard@vibe-guard
```

---

## Why this exists

AI coding tools are very good at making things work and completely indifferent to
whether they are safe. The same six problems show up in almost every app built this
way:

| The problem | What actually happens |
|---|---|
| API keys hardcoded, or behind `NEXT_PUBLIC_` | Anyone who opens your site's JavaScript reads your keys. Bots scrape public repos for them within minutes of a push. |
| Row Level Security off in Supabase | The anon key is public by design. With RLS off, "public" means every row of every table is readable by anyone. |
| API routes with no auth check | Server actions and route handlers are public HTTP endpoints. Without a check, `POST /api/delete-account` works for anybody. |
| No input validation, no rate limits | A TypeScript type is not validation — types disappear at runtime. An unauthenticated endpoint that calls an AI API is a bill waiting to happen. |
| CORS wide open | `Access-Control-Allow-Origin: *` plus credentials lets any website make requests as your logged-in users. |
| No deploy hygiene | Stack traces shown to users, secrets in logs, missing HTTPS headers, `.env` committed months ago and still valid. |

None of these require a skilled attacker. They require someone curious with browser
dev tools open.

**Who it is for:** indie developers and solo founders shipping with Cursor, Lovable,
bolt.new, v0, or Claude Code — typically Next.js/React + Supabase or Postgres +
Vercel. The checks are written by what they look for, not by framework, so most of it
works anywhere. No security background assumed.

---

## What is in the box

### 🔍 `/vibe-guard:security-audit` — find out what is wrong

Scans the project across eight areas and writes `SECURITY-AUDIT.md`: exposed secrets,
RLS, API route authorization, input validation, rate limiting, CORS, security headers,
dependencies and error hygiene.

Every finding gets a severity and four fields — **what it is** in plain language,
**why it matters** in terms of your app, **where** (`file:line`, secrets redacted), and
**how to fix it** for this codebase. It reports what it verified and lists what it
could not check, so you know the edges.

It never edits your code. When you have read it and decided, ask for the fixes.

### 🔒 `/vibe-guard:rls-check` — lock down the database

Reads the **live** Supabase schema, not your migration files — tables and RLS toggles
made in the dashboard never show up in the repo. Reports which tables the public anon
key can reach, classifies each table by ownership pattern, then generates the RLS
migration.

It writes the migration; you apply it. Ships with `verify-rls.sql`, which impersonates
the `anon` role to prove the lock actually holds, because "the app still works" is not
proof.

### 🔑 `/vibe-guard:secure-auth-setup` — login that holds

Scaffolds Supabase Auth on Next.js correctly — the `@supabase/ssr` cookie contract, the
middleware shape that does not randomly log people out, protected layouts, server
actions — or hardens the auth you already have.

Covers the parts tutorials skip: verifying the user server-side instead of trusting the
session, roles that live somewhere the user cannot edit, password reset that does not
leak which emails are registered, and OAuth redirects that are not open redirects.

### 🚀 `/vibe-guard:deploy-checklist` — the pre-launch pass

Most launch risk is not in your code — it is in the Vercel dashboard, the Supabase
settings, and your Stripe account. This walks seven sections (secrets, database,
errors and monitoring, transport, cost controls, payments, privacy), clearly separating
**what it verified in the code** from **what only you can confirm in a dashboard**.

Ends with the rollback plan, because knowing how to undo the deploy matters more at 2am
than any checklist item.

### 🤖 `security-reviewer` agent — review a diff

A read-only reviewer for a branch or PR. Only security, only what changed, no style
notes and no padding. A diff with nothing security-relevant gets "No security findings"
and a one-line scope statement.

```shell
> use the security-reviewer agent on my current branch
```

### 🛡️ The secret-blocking hook — always on

Nothing to run. Every `Write` and `Edit` Claude makes is checked first. If it contains
something that looks like a real credential, the write is blocked:

```
VibeGuard blocked this write: it contains what looks like a real credential.

• Line 12 — Stripe secret key: sk_live_…xYzB
  A Stripe secret key can create charges, issue refunds, and read every
  customer record on your account.

Do this instead:
  1. Move the value into an environment variable…
```

17 credential patterns: AWS, Stripe, OpenAI, Anthropic, Supabase, GitHub, Google,
Slack, SendGrid, Twilio, private keys, database URLs with passwords, and JWTs.

It knows the difference between a secret and a public key — Stripe publishable keys,
the Supabase anon key, and `NEXT_PUBLIC_SUPABASE_URL` pass through untouched, as do
writes to `.env*` files, which is where secrets belong. It also catches the inverse
mistake: a real secret placed behind a `NEXT_PUBLIC_` prefix.

High-confidence matches are blocked outright. Lower-confidence ones ask you first.

**Escape hatches:** add `vibeguard-ignore` in a comment on the same line, or set
`VIBEGUARD_DISABLE=1` for the session.

---

## Install

```shell
/plugin marketplace add carvalhxlucas/vibe-guard
/plugin install vibe-guard@vibe-guard
```

Then restart Claude Code, or run `/reload-plugins`.

To try it without installing:

```bash
git clone https://github.com/carvalhxlucas/vibe-guard
claude --plugin-dir ./vibe-guard/plugins/vibe-guard
```

## Use it

Run a skill by name, or just describe the situation — the skills trigger on what you
say:

| You say | What runs |
|---|---|
| "is this safe to launch?" · "did I leak any keys?" | `security-audit` |
| "can other users see my data?" · "is my Supabase locked down?" | `rls-check` |
| "add login to my app" · "how do I protect this route?" | `secure-auth-setup` |
| "I'm deploying tonight, anything I should check?" | `deploy-checklist` |

A reasonable first pass on an app that already exists:

```shell
/vibe-guard:security-audit      # what is wrong
/vibe-guard:rls-check           # close the database
/vibe-guard:deploy-checklist    # everything outside the repo
```

---

## What it is not

VibeGuard is a fast, opinionated pass at the mistakes that sink small apps. It is not a
penetration test, not a compliance audit, and not a guarantee. The skills read your
code and, for `rls-check`, your database — they cannot see your hosting configuration,
your DNS, or your traffic. Business logic flaws, race conditions, and anything specific
to your domain need a human. Every report says what it could not check.

## Development

```bash
git clone https://github.com/carvalhxlucas/vibe-guard
cd vibe-guard

# Load it into a session without installing
claude --plugin-dir ./plugins/vibe-guard

# Check the manifests and components
claude plugin validate .
claude plugin validate ./plugins/vibe-guard --strict
```

### Tests

```bash
cd tests
npm install
npm test
```

37 checks, no network and no Postgres to install — PGlite runs Postgres 18 in wasm:

- **The hook**, driven exactly as Claude Code drives it: 16 payloads covering each
  credential family, the ask path, and the cases that must pass through untouched
  (publishable keys, `.env` writes, placeholders, `vibeguard-ignore`).
- **`rls-check`'s SQL**, against a real database seeded with a Supabase-shaped schema
  that has deliberate mistakes: every statement in `introspect.sql` runs, leaking
  tables rank above locked ones, a `using (true)` policy is counted as open, and the
  `verify-rls.sql` pattern reports a leak as a leak while the owner still sees their
  own row.
- **Every SQL block in `policy-patterns.md`**, compiled against a bare schema, because
  they are documented as copy-ready.

Behavior of the skills — whether each one fires on the phrasing a real user types — is
measured by six cases under `plugins/vibe-guard/evals/`. The tool for running them is
[`claude plugin eval`](https://code.claude.com/docs/en/plugin-evals), which needs early
access on your account:

```bash
cd plugins/vibe-guard
claude plugin eval . --scaffold --allow-tools Bash Write Edit
```

Without that, `tests/run-cases.mjs` runs the same case files through `claude -p` and
applies the graders that cost nothing to compute — `tool_used`, `regex`, `file_exists`.
The `llm` graders are reported as skipped rather than guessed at. It calls the Claude
CLI, so it costs about \$2.50 for a full pass:

```bash
cd tests
node run-cases.mjs                # every case, plugin loaded
node run-cases.mjs --case rls     # one case
node run-cases.mjs --baseline     # also run with no plugin, for the comparison
```

Current result: all four skills fire on colloquial phrasing as their first tool call,
and the unrelated request invokes none of them.

## Roadmap

- [x] `security-audit` — the report
- [x] `rls-check` — live RLS state and generated policies
- [x] `secure-auth-setup` — auth scaffolding and hardening
- [x] `deploy-checklist` — the pre-launch pass
- [x] `security-reviewer` — diff review agent
- [ ] Framework coverage beyond Next.js: Remix, SvelteKit, Expo
- [ ] Dependency and supply-chain checks with real advisory data
- [ ] A GitHub Action wrapping the reviewer agent

## Contributing

Issues and pull requests welcome — especially new secret patterns and false positives.
If the hook blocked something it should not have, that is a bug worth reporting: paste
the redacted line and the rule name from the message. New checks are most useful with
an eval case attached.

## License

MIT — see [LICENSE](LICENSE).
