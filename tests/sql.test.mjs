// Runs the rls-check SQL against a real Postgres (PGlite, Postgres 18 compiled to
// wasm) seeded with a Supabase-shaped schema carrying deliberate mistakes.
//
// Three things are checked:
//   1. Every statement in introspect.sql executes.
//   2. The verify-rls.sql pattern reports a leak as a leak and a locked table as 0.
//   3. Every SQL block in policy-patterns.md compiles, since they are copy-ready.
import { PGlite } from '@electric-sql/pglite';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const skill = join(here, '../plugins/vibe-guard/skills/rls-check');
const read = (p) => readFileSync(p, 'utf8');

const OWNER = '11111111-1111-1111-1111-111111111111';
const STRANGER = '22222222-2222-2222-2222-222222222222';

// Statements in introspect.sql are separated by a blank line before the next comment.
function statements(sql) {
  return sql
    .split(/;\s*(?=\n(?:--|\s*$)|\n\n)/)
    .map((s) => s.trim())
    .filter((s) => s.replace(/--.*$/gm, '').trim().length)
    .map((s) => (s.endsWith(';') ? s : s + ';'));
}

async function countAs(db, table, { role, sub }) {
  await db.exec('begin;');
  await db.exec(`set local role ${role};`);
  if (sub) await db.exec(`set local request.jwt.claims = '{"sub":"${sub}","role":"authenticated"}';`);
  const r = await db.query(`select count(*)::int as n from public.${table}`);
  await db.exec('rollback;');
  return r.rows[0].n;
}

export async function run() {
  let failed = 0;
  const check = (ok, label) => {
    if (!ok) failed++;
    console.log(`${ok ? 'PASS' : 'FAIL'}  ${label}`);
  };

  // 1. introspect.sql
  const db = await PGlite.create();
  await db.exec(read(join(here, 'fixtures/supabase-app.sql')));
  const introspect = statements(read(join(skill, 'scripts/introspect.sql')));
  for (const [i, stmt] of introspect.entries()) {
    const label = (stmt.match(/^--\s*(\d\..*)/m) || [, `statement ${i + 1}`])[1];
    try {
      const res = await db.query(stmt);
      check(res.rows.length > 0, `introspect: ${label.slice(0, 58)} (${res.rows.length} rows)`);
    } catch (e) {
      check(false, `introspect: ${label.slice(0, 58)} — ${e.message}`);
    }
  }

  // The first result set must rank the two leaking tables above the safe ones.
  const ranked = await db.query(introspect[0]);
  const order = ranked.rows.map((r) => r.table_name);
  check(
    order.indexOf('customers') < order.indexOf('notes') &&
      order.indexOf('messages') < order.indexOf('notes'),
    `introspect: leaking tables rank above locked ones (${order.slice(0, 4).join(', ')}…)`,
  );
  const messages = ranked.rows.find((r) => r.table_name === 'messages');
  check(Number(messages.open_policies) === 1, 'introspect: a `using (true)` policy is counted as open');

  // 2. The verify-rls.sql pattern
  await db.exec(`
    insert into auth.users values ('${OWNER}','a@x.com'), ('${STRANGER}','b@x.com');
    insert into public.notes (user_id, title) values ('${OWNER}','owner note');
    insert into public.customers (user_id, email) values ('${OWNER}','a@x.com');
  `);
  check(await countAs(db, 'notes', { role: 'anon' }) === 0, 'verify: anon sees 0 rows in a locked table');
  check(await countAs(db, 'notes', { role: 'authenticated', sub: OWNER }) === 1, 'verify: the owner still sees their row');
  check(await countAs(db, 'notes', { role: 'authenticated', sub: STRANGER }) === 0, 'verify: another logged-in user sees 0 rows');
  check(await countAs(db, 'customers', { role: 'anon' }) === 1, 'verify: a table with RLS off is reported as leaking');

  // 3. policy-patterns.md
  const fresh = await PGlite.create();
  await fresh.exec(read(join(here, 'fixtures/bare-schema.sql')));
  const blocks = [...read(join(skill, 'references/policy-patterns.md')).matchAll(/```sql\n([\s\S]*?)```/g)].map((m) => m[1]);
  for (const [i, block] of blocks.entries()) {
    const first = (block.split('\n').find((l) => l.trim() && !l.trim().startsWith('--')) || '').trim();
    try {
      await fresh.exec(block);
      check(true, `policy-patterns block ${i + 1}: ${first.slice(0, 52)}`);
    } catch (e) {
      check(false, `policy-patterns block ${i + 1}: ${first.slice(0, 52)} — ${e.message}`);
    }
  }

  return { total: introspect.length + 6 + blocks.length, failed };
}
