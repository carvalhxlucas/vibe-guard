---
type: llm
---

PASS if the response explains that the anon key is public by design and that Row Level Security is what makes that safe, AND gives the user a concrete way to check the live state of their database (a SQL query to run, a CLI command, or the dashboard location) rather than only describing the concept.

FAIL if it tells the user the anon key should be kept secret, or that the fix is to hide the key.
FAIL if it suggests using the service_role key in the frontend, or disabling RLS.
FAIL if it answers only in the abstract with no way for the user to check their own database.
