#!/bin/bash
# Builds a small Next.js-shaped app carrying the four mistakes the audit must find:
# a service role key in client-reachable code, a route with no auth check, a table
# with RLS off, and an unvalidated request body.
set -e
mkdir -p app/api/notes supabase/migrations lib

cat > package.json <<'JSON'
{
  "name": "notes-app",
  "dependencies": { "next": "15.0.0", "@supabase/supabase-js": "^2.45.0" }
}
JSON

cat > lib/supabase.ts <<'TS'
import { createClient } from '@supabase/supabase-js';

export const supabase = createClient(
  'https://abcdefghijklm.supabase.co',
  'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UiLCJpYXQiOjE3MDAwMDAwMDB9.Qk9ndXNTaWduYXR1cmVGb3JUZXN0aW5nT25seQ'
);
TS

cat > app/api/notes/route.ts <<'TS'
import { supabase } from '@/lib/supabase';

export async function GET(request: Request) {
  const userId = new URL(request.url).searchParams.get('userId');
  const { data } = await supabase.from('notes').select('*').eq('user_id', userId);
  return Response.json(data);
}

export async function POST(request: Request) {
  const body = await request.json();
  const { data, error } = await supabase.from('notes').insert(body).select();
  if (error) return Response.json({ error: error.message, stack: error.stack }, { status: 500 });
  return Response.json(data);
}
TS

cat > supabase/migrations/20240101000000_init.sql <<'SQL'
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id),
  title text,
  body text
);
SQL

echo "node_modules" > .gitignore
