# VibeGuard

**Security guardrails for people who ship fast with AI.**

You built the thing in a weekend. It works. Real people are about to put their email
addresses, their data, and maybe their credit cards into it. VibeGuard is the part
nobody taught you: the check that happens before that goes wrong.

It is a [Claude Code](https://claude.com/claude-code) plugin. Two pieces:

- **`/vibe-guard:security-audit`** — scans your project and writes a plain-language
  report: what is wrong, why it matters, exactly how to fix it. It never changes your
  code.
- **A secret-blocking hook** — watches every file Claude writes and stops a hardcoded
  API key before it reaches your disk, not after.

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

## Who it is for

Indie developers and solo founders shipping with Cursor, Lovable, bolt.new, v0, or
Claude Code — typically Next.js/React + Supabase or Postgres + Vercel. The checks are
written by what they look for, not by framework, so most of it works anywhere. No
security background assumed: the report explains every finding in normal words.

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

### Run an audit

```shell
/vibe-guard:security-audit
```

Or just ask — Claude runs it on its own when you say things like "is this safe to
launch?", "did I leak any keys?", or "check my security before I deploy".

You get a `SECURITY-AUDIT.md` in your project root with every finding rated
**Critical / High / Medium / Low**, and for each one:

- **What it is** — in plain language, no jargon
- **Why it matters** — the concrete bad day, in terms of your app
- **Where** — `file:line`, with any secret redacted
- **How to fix** — the actual change for your codebase, with code

It reports. It does not fix. When you have read it and decided, ask for the fixes.

<details>
<summary>What the audit covers</summary>

1. **Exposed secrets** — credentials in source, in git history, or behind a
   client-side env prefix
2. **Row Level Security** — tables reachable with the anon key and RLS off, or a
   policy that allows everything
3. **API route authorization** — handlers with no auth check, or that trust a
   user-supplied ID; webhooks with no signature verification
4. **Input validation** — request bodies used unvalidated, string-concatenated SQL,
   unsanitized HTML
5. **Rate limiting** — expensive or costly endpoints with no limit
6. **CORS** — wildcard or reflected origins on authenticated endpoints
7. **Security headers, transport, cookies** — HSTS, frame protection, cookie flags
8. **Dependencies and error hygiene** — known vulnerabilities, stack traces returned
   to users, secrets in logs

</details>

### The secret-blocking hook

Nothing to run. Once the plugin is installed, every `Write` and `Edit` Claude makes is
checked first. If it contains something that looks like a real credential, the write
is blocked and you see why:

```
VibeGuard blocked this write: it contains what looks like a real credential.

• Line 12 — Stripe secret key: sk_live_…xYzB
  A Stripe secret key can create charges, issue refunds, and read every
  customer record on your account.

Do this instead:
  1. Move the value into an environment variable…
```

It knows the difference between a secret and a public key: Stripe publishable keys,
the Supabase anon key, and `NEXT_PUBLIC_SUPABASE_URL` pass through untouched. Writes
to `.env*` files pass through too — that is where secrets belong.

High-confidence matches (known provider key formats, private keys, database URLs with
passwords, server secrets behind a public env prefix) are blocked outright.
Lower-confidence matches ask you first.

**Escape hatches**, for when it is wrong:

- Add `vibeguard-ignore` in a comment on the same line
- Set `VIBEGUARD_DISABLE=1` to turn the hook off for a session

## What it is not

VibeGuard is a fast, opinionated pass at the mistakes that sink small apps. It is not
a penetration test, not a compliance audit, and not a guarantee. It reads your code —
it cannot see your live database, your hosting configuration, or your DNS. The report
says explicitly what it could not check, so you know where the edges are.

## Roadmap

- `secure-auth-setup` — scaffold authentication that is right the first time
- `rls-check` — generate Row Level Security policies for your Supabase schema
- `deploy-checklist` — the pre-launch pass: env vars, HTTPS, error handling, logging
- A security-review subagent for pull requests

## Contributing

Issues and pull requests welcome — especially new secret patterns and false positives.
If the hook blocked something it should not have, that is a bug worth reporting: paste
the redacted line and the rule name from the message.

## License

MIT — see [LICENSE](LICENSE).
