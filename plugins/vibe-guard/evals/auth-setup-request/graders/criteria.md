---
type: llm
---

PASS if the response sets up Supabase Auth using @supabase/ssr with cookie-based sessions, AND states that server-side code must verify the user with getUser() rather than trusting getSession(), AND says that protected API routes or server actions need their own auth check rather than relying on middleware or on hiding the UI.

FAIL if it stores a session or token in localStorage.
FAIL if it hand-rolls password hashing or JWT signing.
FAIL if it uses the deprecated @supabase/auth-helpers-nextjs package.
FAIL if protection is limited to a client-side redirect or a conditional render.
