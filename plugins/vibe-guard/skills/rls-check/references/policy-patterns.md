# RLS policy patterns

Copy-ready SQL per table pattern. Every example follows the same three rules:

1. `(select auth.uid())` instead of bare `auth.uid()` — Postgres caches it as an
   InitPlan and evaluates it once per query instead of once per row.
2. `to authenticated` (or `to anon, authenticated`) on every policy, so it is skipped
   for roles it does not concern.
3. An index on every column the policy filters by.

Multiple permissive policies on the same command are combined with `OR`. That means
**adding a policy can only widen access, never narrow it**. If a table already has a
policy of `using (true)`, adding a scoped policy changes nothing — drop the open one.

---

## Pattern 1 — Rows owned by one user

The common case: notes, orders, uploads, anything with a `user_id`.

```sql
alter table public.notes enable row level security;

create index if not exists notes_user_id_idx on public.notes (user_id);

create policy "notes: owner reads"
  on public.notes for select to authenticated
  using ( (select auth.uid()) = user_id );

create policy "notes: owner inserts"
  on public.notes for insert to authenticated
  with check ( (select auth.uid()) = user_id );

create policy "notes: owner updates"
  on public.notes for update to authenticated
  using ( (select auth.uid()) = user_id )
  with check ( (select auth.uid()) = user_id );

create policy "notes: owner deletes"
  on public.notes for delete to authenticated
  using ( (select auth.uid()) = user_id );
```

`using` decides which existing rows the statement can see or touch. `with check`
decides what the new row is allowed to look like. `update` needs both — without
`with check`, a user can update their own row and set `user_id` to someone else's,
handing the row away.

Set the owner server-side rather than trusting the client:
`alter table public.notes alter column user_id set default auth.uid();`

---

## Pattern 2 — The user's own profile row

```sql
alter table public.profiles enable row level security;

create policy "profiles: read own"
  on public.profiles for select to authenticated
  using ( (select auth.uid()) = id );

create policy "profiles: update own"
  on public.profiles for update to authenticated
  using ( (select auth.uid()) = id )
  with check ( (select auth.uid()) = id );
```

If the app shows public profiles, open reads deliberately and **narrow the columns**,
because a profiles table usually holds an email address:

```sql
-- Public read of a restricted view, not of the table.
create view public.public_profiles with (security_invoker = on) as
  select id, username, avatar_url from public.profiles;

create policy "profiles: public read of safe columns"
  on public.profiles for select to anon, authenticated
  using ( true );
```

Only pair that open policy with a view when the underlying table has no sensitive
column — RLS filters rows, never columns. To restrict columns, use
`grant select (id, username, avatar_url) on public.profiles to anon;` and revoke the
rest.

Insert on `profiles` is usually a trigger on `auth.users`, not a client insert:

```sql
create function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.profiles (id, username) values (new.id, new.email);
  return new;
end; $$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();
```

---

## Pattern 3 — Team / tenant scoped

Never inline the membership lookup as a subquery in the policy — on a table with a
self-referencing membership check it causes infinite recursion, and Supabase returns
`infinite recursion detected in policy for relation "members"`. Wrap it in a
`security definer` function:

```sql
create function public.is_team_member(team uuid)
returns boolean
language sql
security definer
set search_path = ''
stable
as $$
  select exists (
    select 1 from public.team_members
    where team_id = team and user_id = auth.uid()
  );
$$;

alter table public.projects enable row level security;
create index if not exists projects_team_id_idx on public.projects (team_id);

create policy "projects: members read"
  on public.projects for select to authenticated
  using ( public.is_team_member(team_id) );

create policy "projects: members write"
  on public.projects for insert to authenticated
  with check ( public.is_team_member(team_id) );
```

The function is `security definer`, so it bypasses RLS on `team_members` — that is
deliberate and safe here because it only ever returns a boolean about the caller.
`set search_path = ''` is not optional: without it, a `security definer` function can
be hijacked by a caller who puts a malicious table earlier in their search path.

For role-based writes inside a team, add the role to the function:
`public.has_team_role(team uuid, required text)`.

---

## Pattern 4 — Public read, protected write

Pricing plans, published blog posts, public catalog data.

```sql
alter table public.plans enable row level security;

create policy "plans: anyone reads"
  on public.plans for select to anon, authenticated
  using ( true );
-- No insert/update/delete policies at all: writes are denied for everyone
-- except the service role, which bypasses RLS.
```

For content with a draft state, never rely on the client to filter:

```sql
create policy "posts: anyone reads published"
  on public.posts for select to anon, authenticated
  using ( status = 'published' and published_at <= now() );

create policy "posts: author reads own drafts"
  on public.posts for select to authenticated
  using ( (select auth.uid()) = author_id );
```

---

## Pattern 5 — Join / membership tables

Access follows the parent row the user owns:

```sql
alter table public.note_tags enable row level security;

create policy "note_tags: follows note ownership"
  on public.note_tags for select to authenticated
  using (
    exists (
      select 1 from public.notes n
      where n.id = note_tags.note_id
        and n.user_id = (select auth.uid())
    )
  );
```

Index both foreign keys. This policy runs a subquery per row; without
`notes (id, user_id)` being indexed it is slow on any real table.

---

## Pattern 6 — Fully private tables

Webhook logs, audit trails, background job queues, anything only your server touches.
The strongest configuration is RLS on with **zero policies**, plus the grants revoked:

```sql
alter table public.webhook_events enable row level security;
revoke all on public.webhook_events from anon, authenticated;
```

RLS with no policies denies everything to normal roles. The service role still reaches
it, because service_role has `BYPASSRLS`. Revoking the grant is belt and braces: it
means a future policy added by mistake still cannot open the table up.

---

## Storage buckets

Storage policies live on `storage.objects`. The usual pattern is one folder per user,
with the user id as the first path segment:

```sql
create policy "avatars: users manage their own folder"
  on storage.objects for all to authenticated
  using ( bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text )
  with check ( bucket_id = 'avatars' and (storage.foldername(name))[1] = (select auth.uid())::text );
```

A bucket marked `public` serves every object to anyone with the URL, regardless of
policies. Public is right for avatars and wrong for invoices. Check
`storage.buckets.public` against what the bucket actually holds.

---

## Things that silently bypass RLS

| What | Why | What to do |
|---|---|---|
| `service_role` key | Has `BYPASSRLS`. Every query with it sees everything. | Server-only, never in a client bundle, never in a file without `'use server'` or an equivalent server boundary |
| Views without `security_invoker` | Run as the view's creator, not the caller | `create view … with (security_invoker = on)` — Postgres 15+, which is every current Supabase project |
| `security definer` functions | Run as their creator by design | Filter by `auth.uid()` inside, and always `set search_path = ''` |
| Postgres superuser / table owner | Owners are exempt unless RLS is forced | `alter table … force row level security` if the app connects as the owner |
| Database webhooks and triggers | Run outside the caller's context | Treat them as trusted server code |

---

## Verifying, not hoping

After applying, run `scripts/verify-rls.sql`. The one test that matters:
`set local role anon; select count(*) from public.<table>;` must return 0 for every
protected table.

The Supabase dashboard also flags "RLS disabled in public" under
Advisors → Security. An empty advisor list is a good second opinion, not a substitute
for the anon-role test.
