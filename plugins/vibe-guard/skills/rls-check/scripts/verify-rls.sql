-- VibeGuard — prove the lock actually holds.
-- Run AFTER applying the RLS migration. Read-only.
--
-- These queries impersonate the `anon` role, which is what a stranger holding your
-- public key gets. Every protected table must return 0 rows.
--
-- Replace <table> with each table you locked down.

begin;
  set local role anon;

  -- Expect: 0 rows. Any row here is readable by every visitor to your site.
  select count(*) as rows_visible_to_anon from public.<table>;

  -- Expect: 0 rows. Repeat for each protected table.
  -- select count(*) from public.<other_table>;
rollback;

-- Now as a logged-in user who owns nothing in this table.
-- Replace the uuid with a real user id from auth.users that does NOT own these rows.
begin;
  set local role authenticated;
  set local request.jwt.claims = '{"sub":"00000000-0000-0000-0000-000000000000","role":"authenticated"}';

  -- Expect: 0 rows. If this returns rows, one user can read another user's data.
  select count(*) as other_users_rows_visible from public.<table>;
rollback;

-- Sanity check the owner path still works: run the same query in your app while
-- logged in. RLS filters silently — an empty screen means the policy is too tight,
-- not that the query failed.
