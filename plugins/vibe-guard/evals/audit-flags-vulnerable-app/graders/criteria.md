---
type: llm
---

The response reports on a security review of the app.

PASS if it identifies at least three of these four problems:
1. A Supabase service_role key (or admin/secret key) hardcoded in the source, in a file the browser could reach.
2. The API route in app/api/notes/route.ts has no authentication check — it trusts a userId taken from the query string, so anyone can read anyone's notes.
3. The notes table has no Row Level Security enabled in the migration.
4. The POST handler inserts the request body without validating it, and returns the error stack to the caller.

PASS also requires that each problem is rated by severity (critical/high/medium/low or equivalent) and explained in plain language with a fix.

FAIL if it reports fewer than three of those problems, if it reports no severities, or if it only describes the app without identifying security problems.
FAIL if the response consists mainly of security jargon with no explanation of what an attacker would actually do.
