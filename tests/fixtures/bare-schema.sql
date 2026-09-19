create role anon nologin;
create role authenticated nologin;
create schema auth;
create table auth.users (id uuid primary key, email text);
create function auth.uid() returns uuid language sql stable as $$
  select nullif(current_setting('request.jwt.claims', true)::json->>'sub', '')::uuid
$$;
create schema storage;
create table storage.objects (id uuid primary key default gen_random_uuid(), bucket_id text, name text);
create function storage.foldername(name text) returns text[] language sql immutable as $$
  select string_to_array(name, '/')
$$;

create table public.notes (id uuid primary key default gen_random_uuid(), user_id uuid, title text);
create table public.profiles (id uuid primary key, username text, avatar_url text, email text);
create table public.team_members (team_id uuid, user_id uuid);
create table public.projects (id uuid primary key default gen_random_uuid(), team_id uuid, name text);
create table public.plans (id text primary key, price_cents int);
create table public.posts (id uuid primary key default gen_random_uuid(), author_id uuid, status text, published_at timestamptz);
create table public.note_tags (note_id uuid, tag text);
create table public.webhook_events (id bigserial primary key, payload jsonb);
grant select, insert, update, delete on all tables in schema public to anon, authenticated;
