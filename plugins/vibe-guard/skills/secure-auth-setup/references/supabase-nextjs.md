# Supabase Auth on Next.js (App Router)

Use `@supabase/ssr`. The older `@supabase/auth-helpers-nextjs` package is deprecated —
if you find it in `package.json`, migrating is the first fix.

```bash
npm install @supabase/supabase-js @supabase/ssr
```

Environment (`.env.local`, and `.gitignore` must cover `.env*`):

```
NEXT_PUBLIC_SUPABASE_URL=https://xxxx.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJ...
```

Both of those are public by design and belong under `NEXT_PUBLIC_`. The service role
key does **not** — it never gets a `NEXT_PUBLIC_` prefix and never appears in a file
that the browser can load.

---

## 1. Browser client

`lib/supabase/client.ts`

```ts
import { createBrowserClient } from '@supabase/ssr';

export function createClient() {
  return createBrowserClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
  );
}
```

---

## 2. Server client

`lib/supabase/server.ts`

```ts
import { createServerClient } from '@supabase/ssr';
import { cookies } from 'next/headers';

export async function createClient() {
  const cookieStore = await cookies();

  return createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return cookieStore.getAll();
        },
        setAll(cookiesToSet) {
          try {
            cookiesToSet.forEach(({ name, value, options }) =>
              cookieStore.set(name, value, options),
            );
          } catch {
            // Called from a Server Component, where cookies are read-only.
            // Safe to ignore when middleware is refreshing the session.
          }
        },
      },
    },
  );
}
```

Use the `getAll`/`setAll` pair. The older `get`/`set`/`remove` cookie methods are
removed, and code using them produces sessions that silently fail to refresh.

---

## 3. Middleware — the session refresh

`middleware.ts` at the project root, exporting `middleware`.

**Next.js 16 renamed this file to `proxy.ts`, exporting `proxy`.** Same behaviour, same
body, same `config.matcher` — only the file name and the exported function name change.
Check the installed version before writing it:

```bash
node -p "require('./package.json').dependencies.next"
```

Version 16 or later gets `proxy.ts` with `export async function proxy(request: NextRequest)`.
Version 15 and earlier gets `middleware.ts` with `export async function middleware(...)`.
The example below shows the 15-and-earlier form.

```ts
import { createServerClient } from '@supabase/ssr';
import { NextResponse, type NextRequest } from 'next/server';

export async function middleware(request: NextRequest) {
  let supabaseResponse = NextResponse.next({ request });

  const supabase = createServerClient(
    process.env.NEXT_PUBLIC_SUPABASE_URL!,
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          cookiesToSet.forEach(({ name, value }) => request.cookies.set(name, value));
          supabaseResponse = NextResponse.next({ request });
          cookiesToSet.forEach(({ name, value, options }) =>
            supabaseResponse.cookies.set(name, value, options),
          );
        },
      },
    },
  );

  // Do not put any code between createServerClient and getUser(). Anything that
  // returns early here skips the cookie refresh, and users get logged out at random.
  const { data: { user } } = await supabase.auth.getUser();

  const isProtected =
    request.nextUrl.pathname.startsWith('/dashboard') ||
    request.nextUrl.pathname.startsWith('/settings');

  if (!user && isProtected) {
    const url = request.nextUrl.clone();
    url.pathname = '/login';
    url.searchParams.set('next', request.nextUrl.pathname); // validated on the way back
    return NextResponse.redirect(url);
  }

  // Return supabaseResponse itself. Building a fresh NextResponse here drops the
  // refreshed auth cookies, which is the most common cause of "logged out on refresh".
  return supabaseResponse;
}

export const config = {
  matcher: [
    '/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)',
  ],
};
```

Middleware — `proxy.ts` on Next.js 16 — redirects. It does not authorize. Every route
handler and server action still does its own `getUser()` check — middleware does not run for every data path, and
a matcher gap silently disables it.

---

## 4. OAuth / magic link callback

`app/auth/callback/route.ts`

```ts
import { createClient } from '@/lib/supabase/server';
import { NextResponse } from 'next/server';

export async function GET(request: Request) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get('code');
  const next = searchParams.get('next') ?? '/dashboard';

  // Open-redirect guard: only same-origin, path-only destinations.
  const safeNext = next.startsWith('/') && !next.startsWith('//') ? next : '/dashboard';

  if (code) {
    const supabase = await createClient();
    const { error } = await supabase.auth.exchangeCodeForSession(code);
    if (!error) return NextResponse.redirect(`${origin}${safeNext}`);
  }

  return NextResponse.redirect(`${origin}/login?error=auth`);
}
```

In the Supabase dashboard (Authentication → URL Configuration), set the Site URL and
add every valid redirect URL to the allowlist. An unlisted redirect fails; a wildcard
entry defeats the purpose.

---

## 5. Protected layout

`app/dashboard/layout.tsx`

```tsx
import { createClient } from '@/lib/supabase/server';
import { redirect } from 'next/navigation';

export default async function DashboardLayout({ children }: { children: React.ReactNode }) {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect('/login');

  return <>{children}</>;
}
```

`getUser()`, never `getSession()`, in server code. `getSession()` returns whatever is
in the cookie without revalidating it, so it can be forged. `getUser()` calls the auth
server and verifies. In the browser, `getSession()` is fine — nothing there is trusted
anyway.

---

## 6. Login and signup server actions

`app/login/actions.ts`

```ts
'use server';

import { createClient } from '@/lib/supabase/server';
import { revalidatePath } from 'next/cache';
import { redirect } from 'next/navigation';
import { z } from 'zod';

const Credentials = z.object({
  email: z.string().email(),
  password: z.string().min(8).max(72), // bcrypt truncates past 72 bytes
});

export async function login(formData: FormData) {
  const parsed = Credentials.safeParse({
    email: formData.get('email'),
    password: formData.get('password'),
  });
  if (!parsed.success) return { error: 'Invalid email or password' };

  const supabase = await createClient();
  const { error } = await supabase.auth.signInWithPassword(parsed.data);

  // One generic message for every failure. A specific one ("no such user")
  // tells an attacker which email addresses have accounts here.
  if (error) return { error: 'Invalid email or password' };

  revalidatePath('/', 'layout');
  redirect('/dashboard');
}

export async function signOut() {
  const supabase = await createClient();
  await supabase.auth.signOut();
  revalidatePath('/', 'layout');
  redirect('/login');
}
```

---

## 7. Server-only admin client

Only when a task genuinely requires bypassing RLS — a webhook writing to a log table,
an admin backfill. Put it in its own file, and mark the file so nobody imports it from
a client component by accident.

`lib/supabase/admin.ts`

```ts
import 'server-only'; // build fails if a client component imports this
import { createClient } from '@supabase/supabase-js';

export const supabaseAdmin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  process.env.SUPABASE_SERVICE_ROLE_KEY!, // no NEXT_PUBLIC_ prefix, ever
  { auth: { persistSession: false, autoRefreshToken: false } },
);
```

`npm install server-only` for that import. It turns "a secret leaked into the bundle"
into a build error, which is where you want to find out.

---

## Checks after setup

```bash
# No server secret behind a public prefix
rg -n 'NEXT_PUBLIC_[A-Z_]*(SERVICE_ROLE|SECRET)'
# No service key imported from client code
rg -ln "'use client'" | xargs rg -l 'SERVICE_ROLE|supabaseAdmin' 2>/dev/null
# Deprecated auth helpers still installed
rg -n '@supabase/auth-helpers' package.json
# Server code reading the session instead of verifying the user
rg -n 'getSession\(\)' --glob '!node_modules' --glob '!**/*client*'
```

Then build once — `next build` — and grep the output bundle for the first 12 characters
of your service role key. Finding nothing is the only proof that matters.
