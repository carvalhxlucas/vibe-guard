---
name: deploy-checklist
description: Runs the pre-launch pass before an app goes live or gets shared publicly — environment variables set correctly in the host, secrets kept out of the client bundle, HTTPS and security headers, error handling that does not leak stack traces, logs without sensitive data, database backups, spending caps on paid APIs, and the provider settings that exist only outside the repo. Use when someone says they are about to deploy, launch, go live, ship it, share the link, post it on Reddit or Product Hunt or Hacker News, or asks "anything I should do first", "am I ready to ship this", "what do I need to check before this goes out".
---

# Deploy checklist

The last pass before real people arrive. Different from `security-audit` in two ways:
it covers operational risk as well as security, and **most of what matters is not in
the repository** — it is in the Vercel dashboard, the Supabase settings, and the
Stripe account.

So this skill does two things, and must keep them clearly apart:

- **Verified** — things you checked yourself in the code.
- **Confirm in the dashboard** — things only the user can see. Ask them directly, one
  batch at a time. Never mark these as passing on assumption.

## Step 1 — Establish what "launch" means here

Ask, unless the repo makes it obvious:

- Is this the first public launch, or a deploy of an app already live?
- Does it handle payments? Real user accounts? File uploads? Anything regulated
  (health, financial, minors)?
- Expected traffic: a few friends, or a launch post?

The answers change which items are blocking. An app with no accounts and no payments
can skip half the list. Say which items you are skipping and why.

## Step 2 — Work the list

`references/checklist.md` holds the full list, grouped in seven sections with the
detection command for each item. Work through them in order:

1. Secrets and environment variables
2. Database (backups, RLS, connection limits)
3. Errors, logging, and monitoring
4. Transport, headers, and cookies
5. Cost and abuse controls
6. Payments (skip if none)
7. Data, privacy, and the legal minimum

Mark every item as **pass**, **fail**, **needs the user to confirm**, or **skipped
(and why)**.

The single most valuable check, and the one nobody runs:

```bash
npm run build
# Then look for your secrets in what shipped to the browser:
rg -l 'sk_live|sk-proj|SERVICE_ROLE|eyJ[A-Za-z0-9_-]{20,}\.' .next/static dist build 2>/dev/null \
  && echo "FOUND A SECRET IN THE CLIENT BUNDLE" || echo "clean"
```

A secret in the bundle is always blocking. Everything else is a judgment call; that
one is not.

## Step 3 — Write the checklist file

Output `DEPLOY-CHECKLIST.md` in the project root:

```markdown
# Pre-launch checklist — <project>
**Date:** <YYYY-MM-DD> · **Target:** <Vercel production>

## Blocking — do not launch with these open
- [ ] **Service role key is in the client bundle** — `lib/db.ts:4`. <what to do>

## Should fix before real traffic
- [ ] ...

## Do it soon after launch
- [ ] ...

## Confirm in the dashboard (I cannot see these)
- [ ] Vercel → Settings → Environment Variables: every variable in `.env.local` also
      set for Production, and no server secret duplicated under a `NEXT_PUBLIC_` name
- [ ] Supabase → Database → Backups: point-in-time recovery on, or daily backups at
      minimum — what is your plan's retention?
- [ ] OpenAI → Limits: a hard monthly spending cap set

## Verified clean
- Security headers configured in `next.config.js`
- No `console.log` of tokens or user objects
```

Keep the blocking list short and real. A checklist with 40 blocking items gets ignored,
and then a genuinely blocking item goes out with it.

## Step 4 — The rollback plan

Before they deploy, make sure they can undo it. Three questions, and write the answers
into the checklist file:

1. **How do you roll back?** On Vercel: Deployments → the previous one → Promote to
   Production. Confirm they know where that is *before* they need it at 2am.
2. **How do you restore the database?** A rollback of the code does not undo a
   migration. If the deploy includes a destructive migration (dropped column, changed
   type), the restore path is a backup — confirm one exists and is recent.
3. **How will you know something is wrong?** If the answer is "a user will email me",
   set up error alerting first. Sentry's free tier takes ten minutes.

## Step 5 — Hand over

Summarize in chat: blocking count, the first three things to do, and the dashboard
items you need answers on. Then stop. Do not deploy anything, do not run
`vercel --prod`, do not apply migrations. Launching is the user's decision and their
finger on the button.

## Tone

This skill runs at the most stressful moment of the project. Be concrete and calm. No
"critical security vulnerability!!" framing on a missing `Referrer-Policy` header. Rank
honestly, say what is genuinely blocking, and let them ship.
