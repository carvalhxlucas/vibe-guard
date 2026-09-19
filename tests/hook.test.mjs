// Drives hooks/scripts/detect-secrets.mjs the way Claude Code does: one JSON payload
// on stdin per case, checking the exit code and the permission decision it returns.
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const HOOK = join(
  dirname(fileURLToPath(import.meta.url)),
  '../plugins/vibe-guard/hooks/scripts/detect-secrets.mjs',
);

// A key that looks real enough for the rule to fire, short enough that GitHub's own
// push protection does not flag this repository.
const STRIPE = 'sk_live_9fKq2LmZ7pRt4XwD';

const write = (file_path, content) => ({ tool_name: 'Write', tool_input: { file_path, content } });
const edit = (file_path, new_string) => ({ tool_name: 'Edit', tool_input: { file_path, new_string } });

const cases = [
  // Blocked: high-confidence credentials
  ['stripe secret key', write('lib/pay.ts', `const s = new Stripe("${STRIPE}")`), 'deny'],
  ['openai key', write('a.ts', 'const c = { apiKey: "sk-proj-Ab3dEf7hIj9kLm2nOp4qRs6tUv8wXy0zAb3dEf7h" }'), 'deny'],
  ['aws access key id', write('a.ts', 'const id = "AKIA4T2QZ7WBK3JHDLM9"'), 'deny'],
  ['github token', write('a.ts', 'const t = "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"'), 'deny'],
  ['private key block', write('key.pem', '-----BEGIN RSA PRIVATE KEY-----\nMIIEow==\n'), 'deny'],
  ['database url with password', write('lib/db.ts', 'const u = "postgresql://postgres:Sup3rS3cret@db.abc.supabase.co:5432/postgres"'), 'deny'],
  ['supabase service_role jwt', write('lib/sb.ts', 'const k = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlIjoic2VydmljZV9yb2xlIiwiaXNzIjoic3VwYWJhc2UifQ.abcdef123456"'), 'deny'],
  ['secret behind a public prefix', edit('lib/db.ts', 'process.env.NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY'), 'deny'],

  // Asked: plausible but unproven
  ['generic high-entropy assignment', edit('lib/x.ts', 'const apiKey = "a9Fk2Lq8ZvB3nX7wQ1sT"'), 'ask'],

  // Allowed: public by design, placeholders, or the right place for a secret
  ['stripe publishable key', write('lib/s.ts', 'const k = "pk_live_51H8xQ2KlmNoPqRsTuVwXyZaB"'), 'allow'],
  ['public supabase url', write('a.ts', 'const u = process.env.NEXT_PUBLIC_SUPABASE_URL'), 'allow'],
  ['secret written to .env.local', write('.env.local', `STRIPE_SECRET_KEY=${STRIPE}`), 'allow'],
  ['documented placeholder', write('README.md', 'OPENAI_API_KEY=your-api-key-here'), 'allow'],
  ['aws example key from the docs', write('a.ts', 'const id = "AKIAIOSFODNN7EXAMPLE1"'), 'allow'],
  ['line marked vibeguard-ignore', write('t.ts', `const k = "${STRIPE}" // vibeguard-ignore`), 'allow'],
  ['ordinary code', write('app/page.tsx', 'export default function Page() { return null }'), 'allow'],
];

export function run() {
  let failed = 0;
  for (const [label, payload, expected] of cases) {
    const proc = spawnSync('node', [HOOK], { input: JSON.stringify(payload), encoding: 'utf8' });
    const out = proc.stdout.trim();
    const decision = out
      ? JSON.parse(out).hookSpecificOutput.permissionDecision
      : 'allow';
    const exitOk = expected === 'deny' ? proc.status === 2 : proc.status === 0;
    const ok = decision === expected && exitOk;
    if (!ok) failed++;
    console.log(`${ok ? 'PASS' : 'FAIL'}  hook: ${label} → ${decision} (exit ${proc.status})`);
  }
  return { total: cases.length, failed };
}
