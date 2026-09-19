-- Supabase-shaped fixture: the roles, schemas, and mistakes a vibecoded project has.
create role anon nologin;
create role authenticated nologin;
create role service_role nologin bypassrls;

create schema if not exists auth;
create table auth.users (id uuid primary key, email text);

-- auth.uid() stub so the policies parse the way they do on Supabase
create function auth.uid() returns uuid language sql stable as $$
  select nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid
$$;

create schema if not exists storage;
create table storage.buckets (id text primary key, public boolean default false);
create table storage.objects (id uuid primary key default gen_random_uuid(), bucket_id text, name text);
insert into storage.buckets (id, public) values ('avatars', true), ('invoices', false);

-- 1. RLS off, granted to anon: critical
create table public.customers (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id),
  email text, stripe_customer_id text
);

-- 2. RLS on with a policy that allows everything: critical
create table public.messages (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id),
  body text
);
alter table public.messages enable row level security;
create policy "messages open" on public.messages for select using (true);

-- 3. Correctly scoped
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id),
  title text
);
alter table public.notes enable row level security;
create policy "notes owner reads" on public.notes for select to authenticated
  using ((select auth.uid()) = user_id);
create policy "notes owner writes" on public.notes for insert to authenticated
  with check ((select auth.uid()) = user_id);

-- 4. Intentionally public reference data
create table public.plans (id text primary key, price_cents int);

-- 5. Internal table, no grants
create table public.webhook_logs (id bigserial primary key, payload jsonb);

-- 6. Team scoped
create table public.team_members (team_id uuid, user_id uuid references auth.users(id));
create table public.projects (id uuid primary key default gen_random_uuid(), team_id uuid, name text);

-- A view that bypasses RLS, and one that does not
create view public.customer_emails as select id, email from public.customers;
create view public.safe_notes with (security_invoker = on) as select id, title from public.notes;

-- security definer function with no search_path pin
create function public.is_team_member(team uuid) returns boolean
language sql security definer stable as $$
  select exists (select 1 from public.team_members where team_id = team);
$$;

grant select, insert, update, delete on public.customers, public.messages, public.notes to anon, authenticated;
grant select on public.plans to anon, authenticated;
grant select on public.projects to authenticated;
grant select on public.customer_emails to anon;
