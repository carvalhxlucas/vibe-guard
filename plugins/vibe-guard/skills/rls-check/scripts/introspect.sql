-- VibeGuard — RLS introspection.
-- Read-only. Run in the Supabase SQL editor, or with psql "$DATABASE_URL" -f this file.
-- Returns five result sets. Paste all of them back.

-- 1. Every table: is RLS on, how many policies, and can the public roles reach it?
--    `open_policies` counts policies whose USING clause is literally `true`, which
--    grants every row and is the same as having no RLS at all.
--    `approx_rows` is null when the table has never been analyzed.
select
  c.relname                                   as table_name,
  c.relrowsecurity                            as rls_enabled,
  c.relforcerowsecurity                       as rls_forced,
  (select count(*) from pg_policies p
     where p.schemaname = 'public' and p.tablename = c.relname) as policy_count,
  (select count(*) from pg_policies p
     where p.schemaname = 'public' and p.tablename = c.relname
       and (p.qual = 'true' or p.with_check = 'true'))          as open_policies,
  coalesce(string_agg(distinct g.grantee, ', ')
    filter (where g.grantee in ('anon', 'authenticated', 'PUBLIC')), '(none)') as granted_to,
  nullif(c.reltuples, -1)::bigint             as approx_rows
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
left join information_schema.role_table_grants g
  on g.table_schema = 'public' and g.table_name = c.relname
where n.nspname = 'public' and c.relkind = 'r'
group by c.oid, c.relname, c.relrowsecurity, c.relforcerowsecurity, c.reltuples
order by
  -- Worst first: reachable by a public role, and nothing stopping the read.
  (count(*) filter (where g.grantee in ('anon', 'authenticated', 'PUBLIC')) > 0
     and (c.relrowsecurity is false
          or (select count(*) from pg_policies p
                where p.schemaname = 'public' and p.tablename = c.relname
                  and (p.qual = 'true' or p.with_check = 'true')) > 0)) desc,
  c.relrowsecurity asc,
  c.relname;

-- 2. Every policy, with its actual condition.
--    A `using_expression` of `true` means "every row", which is the same as no RLS.
--    `roles` of {public} means the policy applies to anon as well as logged-in users.
select
  tablename,
  policyname,
  cmd,
  roles,
  permissive,
  qual        as using_expression,
  with_check  as with_check_expression
from pg_policies
where schemaname = 'public'
order by tablename, cmd, policyname;

-- 3. Candidate ownership columns on base tables, so policies target the right column.
select
  c.table_name,
  c.column_name,
  c.data_type,
  tc.constraint_type is not null as is_foreign_key,
  ccu.table_schema || '.' || ccu.table_name as references_table
from information_schema.columns c
join information_schema.tables t
  on t.table_schema = c.table_schema
 and t.table_name = c.table_name
 and t.table_type = 'BASE TABLE'
left join information_schema.key_column_usage kcu
  on kcu.table_schema = c.table_schema
 and kcu.table_name = c.table_name
 and kcu.column_name = c.column_name
left join information_schema.table_constraints tc
  on tc.constraint_name = kcu.constraint_name
 and tc.constraint_type = 'FOREIGN KEY'
left join information_schema.constraint_column_usage ccu
  on ccu.constraint_name = tc.constraint_name
where c.table_schema = 'public'
  and (c.column_name ~ '(user|owner|author|profile|account|member|created_by)_?id$'
       or c.column_name ~ '(team|org|organization|workspace|tenant|company)_?id$'
       or c.column_name = 'id')
order by c.table_name, c.column_name;

-- 4. Things that bypass RLS: views running as their creator, and security definer
--    functions. For a view, `detail` is its security_invoker setting — `off` means it
--    ignores the RLS of the tables underneath it. For a function, `detail` is its
--    configuration, which must pin search_path.
select
  'view' as kind,
  c.relname as name,
  coalesce((select option_value from pg_options_to_table(c.reloptions)
            where option_name = 'security_invoker'), 'off') as detail
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'v'
union all
select
  'security definer function',
  p.proname,
  coalesce(array_to_string(p.proconfig, ', '), '(no search_path set)')
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public' and p.prosecdef
order by 1, 2;

-- 5. Storage buckets and whether they are public, plus their policy count.
--    A public bucket serves every object to anyone with the URL, policies or not.
select
  b.id as bucket,
  b.public as is_public,
  (select count(*) from pg_policies p
     where p.schemaname = 'storage' and p.tablename = 'objects') as storage_policy_count
from storage.buckets b
order by b.public desc, b.id;
