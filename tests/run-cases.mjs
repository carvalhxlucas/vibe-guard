// Headless runner for the eval cases in plugins/vibe-guard/evals/.
//
// `claude plugin eval` is the real tool for this and needs early access on the
// account. Until that is on, this runs the same case files through `claude -p` and
// applies the graders that cost nothing to compute: tool_used, regex, and
// file_exists. The llm graders are listed as skipped rather than guessed at.
//
//   node run-cases.mjs                 # every case, with the plugin loaded
//   node run-cases.mjs --case rls      # cases whose name matches
//   node run-cases.mjs --baseline      # also run without the plugin, and show the delta
import { execFileSync } from 'node:child_process';
import { readFileSync, readdirSync, existsSync, mkdtempSync, rmSync, statSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { tmpdir, homedir } from 'node:os';

const here = dirname(fileURLToPath(import.meta.url));
const PLUGIN = join(here, '../plugins/vibe-guard');
const EVALS = join(PLUGIN, 'evals');

const args = process.argv.slice(2);
const filter = args.includes('--case') ? args[args.indexOf('--case') + 1] : null;
const withBaseline = args.includes('--baseline');

function frontmatter(text) {
  const m = text.match(/^---\n([\s\S]*?)\n---\n?([\s\S]*)$/);
  if (!m) return { meta: {}, body: text.trim() };
  const meta = {};
  for (const line of m[1].split('\n')) {
    const kv = line.match(/^([\w-]+):\s*(.*)$/);
    if (!kv) continue;
    const [, k, raw] = kv;
    meta[k] = raw.startsWith('[')
      ? raw.slice(1, -1).split(',').map((s) => s.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean)
      : raw.replace(/^['"]|['"]$/g, '');
  }
  return { meta, body: m[2].trim() };
}

function loadCases() {
  return readdirSync(EVALS, { withFileTypes: true })
    .filter((d) => d.isDirectory() && d.name !== 'results' && existsSync(join(EVALS, d.name, 'prompt.md')))
    .filter((d) => !filter || d.name.includes(filter))
    .map((d) => {
      const dir = join(EVALS, d.name);
      const { meta, body } = frontmatter(readFileSync(join(dir, 'prompt.md'), 'utf8'));
      const graders = existsSync(join(dir, 'graders'))
        ? readdirSync(join(dir, 'graders')).map((f) => ({
            name: f.replace(/\.md$/, ''),
            ...frontmatter(readFileSync(join(dir, 'graders', f), 'utf8')),
          }))
        : [];
      return { name: d.name, dir, meta, prompt: body, graders };
    });
}

// Each run gets a scratch working directory, seeded by the case's fixture if it has one.
function workspace(c) {
  const dir = mkdtempSync(join(tmpdir(), `vg-${c.name}-`));
  if (existsSync(join(c.dir, 'fixture.sh'))) {
    execFileSync('bash', [join(c.dir, 'fixture.sh')], { cwd: dir, stdio: 'pipe' });
  }
  return dir;
}

function runClaude(c, cwd, { plugin }) {
  const tools = c.meta.allowed_tools || ['Read', 'Glob', 'Grep', 'Skill'];
  const argv = ['-p', c.prompt, '--max-turns', String(c.meta.max_turns || 20),
                '--allowedTools', ...tools, '--output-format', 'json'];
  if (plugin) argv.push('--plugin-dir', PLUGIN);
  let out;
  try {
    out = execFileSync('claude', argv, { cwd, encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  } catch (e) {
    out = e.stdout || '{}'; // a run that hits max_turns exits non-zero but still reports
  }
  let result = {};
  try { result = JSON.parse(out); } catch {}
  return { result, transcript: findTranscript(cwd, result.session_id) };
}

// Claude Code writes one .jsonl per session under ~/.claude/projects/<slug of cwd>/.
// The slug is built from the resolved path with every non-alphanumeric character
// turned into a dash, so /var/... becomes -private-var-... and underscores become
// dashes too. Rather than reproduce that exactly, find the directory that holds this
// run's session file, and fall back to the slug only when there is no session id.
function findTranscript(cwd, sessionId) {
  const root = join(homedir(), '.claude', 'projects');
  if (!existsSync(root)) return [];
  const dirs = readdirSync(root).map((d) => join(root, d)).filter((d) => statSync(d).isDirectory());

  let file = null;
  if (sessionId) {
    const hit = dirs.find((d) => existsSync(join(d, `${sessionId}.jsonl`)));
    if (hit) file = join(hit, `${sessionId}.jsonl`);
  }
  if (!file) {
    const slug = realpathSync(cwd).replace(/[^a-zA-Z0-9]/g, '-');
    const hit = dirs.find((d) => d.endsWith(slug));
    if (!hit) return [];
    file = readdirSync(hit)
      .filter((f) => f.endsWith('.jsonl'))
      .map((f) => join(hit, f))
      .sort((a, b) => statSync(b).mtimeMs - statSync(a).mtimeMs)[0];
  }
  if (!file) return [];
  return readFileSync(file, 'utf8')
    .split('\n')
    .filter(Boolean)
    .map((l) => { try { return JSON.parse(l); } catch { return null; } })
    .filter(Boolean);
}

function toolCalls(transcript) {
  const calls = [];
  for (const entry of transcript) {
    const content = entry.message?.content;
    if (!Array.isArray(content)) continue;
    for (const block of content) {
      if (block?.type === 'tool_use') calls.push({ name: block.name, input: JSON.stringify(block.input ?? {}) });
    }
  }
  return calls;
}

function grade(g, { result, transcript, cwd }) {
  const type = g.meta.type;
  if (type === 'llm' || type === 'baseline') return { skipped: true };

  if (type === 'tool_used') {
    const re = g.meta.input_match ? new RegExp(g.meta.input_match) : null;
    const n = toolCalls(transcript).filter((c) => c.name === g.meta.tool && (!re || re.test(c.input))).length;
    const min = g.meta.min !== undefined ? Number(g.meta.min) : 1;
    const max = g.meta.max !== undefined ? Number(g.meta.max) : Infinity;
    return { pass: n >= min && n <= max, detail: `${n} call(s)` };
  }

  if (type === 'regex') {
    const target = g.meta.target || 'last_message';
    let text = result.result || '';
    const fileTarget = typeof target === 'string' && target.includes('path:');
    if (fileTarget) {
      const path = target.match(/path:\s*([^\s}]+)/)[1];
      text = existsSync(join(cwd, path)) ? readFileSync(join(cwd, path), 'utf8') : '';
    } else if (target === 'trace') {
      text = JSON.stringify(transcript);
    }
    const found = new RegExp(g.meta.pattern, g.meta.flags || '').test(text);
    const pass = g.meta.match === 'not_contains' ? !found : found;
    return { pass, detail: found ? 'matched' : 'no match' };
  }

  if (type === 'file_exists') {
    const exists = existsSync(join(cwd, g.meta.path));
    return { pass: g.meta.exists === 'false' ? !exists : exists, detail: exists ? 'present' : 'absent' };
  }

  return { skipped: true, detail: `unsupported type: ${type}` };
}

const cases = loadCases();
console.log(`${cases.length} case(s)${withBaseline ? ', with a no-plugin baseline arm' : ''}\n`);

let cost = 0;
let failed = 0;

for (const c of cases) {
  const arms = withBaseline ? [true, false] : [true];
  for (const plugin of arms) {
    const cwd = workspace(c);
    const run = runClaude(c, cwd, { plugin });
    cost += run.result.total_cost_usd || 0;

    const label = `${c.name}${withBaseline ? (plugin ? ' [with plugin]' : ' [no plugin]') : ''}`;
    console.log(`── ${label}  (${run.result.num_turns ?? '?'} turns, $${(run.result.total_cost_usd || 0).toFixed(3)})`);

    for (const g of c.graders) {
      const r = grade(g, { ...run, cwd });
      if (r.skipped) {
        console.log(`   SKIP  ${g.name} — ${g.meta.type} grader needs a judge model`);
        continue;
      }
      // A no-plugin arm cannot invoke a plugin skill, so that grader is an
      // indicator there rather than a failure — the same rule claude plugin eval uses.
      const indicator = !plugin && g.meta.type === 'tool_used' && g.meta.tool === 'Skill' && g.meta.arm !== 'both';
      if (!r.pass && !indicator) failed++;
      console.log(`   ${indicator ? 'INFO' : r.pass ? 'PASS' : 'FAIL'}  ${g.name} — ${r.detail}`);
    }
    rmSync(cwd, { recursive: true, force: true });
  }
  console.log();
}

console.log(`${failed} grader failure(s) · $${cost.toFixed(2)} spent`);
process.exit(failed ? 1 : 0);
