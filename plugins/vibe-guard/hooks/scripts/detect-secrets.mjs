#!/usr/bin/env node
/**
 * VibeGuard — hardcoded secret detector.
 *
 * Runs as a PreToolUse hook on Write/Edit/MultiEdit/NotebookEdit. It reads the
 * hook payload from stdin, looks at the text Claude is about to write, and
 * blocks the write when it finds something that looks like a real credential.
 *
 * Exit codes:
 *   0 + no output      -> nothing found, tool call proceeds
 *   0 + decision JSON  -> "ask" (low-confidence match, user decides)
 *   2 + decision JSON  -> "deny" (high-confidence match, write blocked)
 *
 * Escape hatches:
 *   - VIBEGUARD_DISABLE=1 in the environment turns the hook off entirely.
 *   - A `vibeguard-ignore` comment on the same line skips that line.
 */

const DISABLED = ['1', 'true', 'yes'].includes(
  String(process.env.VIBEGUARD_DISABLE || '').toLowerCase(),
);

/** Files where storing a real secret is the correct thing to do. */
const EXEMPT_FILE = [
  /(^|[/\\])\.env(\.[a-z0-9_.-]+)?$/i,
  /(^|[/\\])\.git[/\\]/,
  /(^|[/\\])node_modules[/\\]/,
  /(^|[/\\])(package-lock\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?)$/i,
];

/** Never flag these: they are public by design. */
const PUBLIC_BY_DESIGN = [
  /^pk_(test|live)_/,          // Stripe publishable key
  /^pk_/,                      // other publishable keys
];

/** Values that are obviously fake. */
const PLACEHOLDER =
  /\byour[-_ ]?|\bmy[-_ ](api|secret|key|token)|example|placeholder|dummy|sample|redacted|changeme|change[-_ ]me|replace[-_ ]?(me|this|with)|insert[-_ ]|\btodo\b|fixme|x{5,}|\.{3,}|\*{4,}|<[^>]+>|\$\{|^test$|^fake|[-_ ]here$/i;

/**
 * Each rule: id, severity, human explanation, and a regex.
 * `confidence: "high"` denies the write. `"low"` asks the user instead.
 */
const RULES = [
  {
    id: 'aws-access-key-id',
    label: 'AWS access key ID',
    confidence: 'high',
    re: /\bAKIA[0-9A-Z]{16}\b/g,
    why: 'An AWS access key ID lets anyone who reads it call AWS as you — spin up servers, read your S3 buckets, run up your bill.',
  },
  {
    id: 'aws-secret-access-key',
    label: 'AWS secret access key',
    confidence: 'high',
    re: /aws[_-]?(secret|private)[_-]?(access[_-]?)?key\s*[:=]\s*["'`]([A-Za-z0-9/+=]{40})["'`]/gi,
    why: 'This is the half of the AWS credential pair that acts as the password. Paired with the key ID it is full account access.',
  },
  {
    id: 'stripe-secret-key',
    label: 'Stripe secret key',
    confidence: 'high',
    re: /\b(sk|rk)_(live|test)_[A-Za-z0-9]{16,}\b/g,
    why: 'A Stripe secret key can create charges, issue refunds, and read every customer record on your account.',
  },
  {
    id: 'stripe-webhook-secret',
    label: 'Stripe webhook signing secret',
    confidence: 'high',
    re: /\bwhsec_[A-Za-z0-9]{16,}\b/g,
    why: 'Anyone with this secret can forge webhook events, so they can tell your app "this payment succeeded" without paying.',
  },
  {
    id: 'openai-api-key',
    label: 'OpenAI API key',
    confidence: 'high',
    re: /\bsk-(proj-|svcacct-|admin-)?[A-Za-z0-9_-]{32,}\b/g,
    why: 'Anyone with this key spends your OpenAI credits. Leaked keys are scraped from public repos within minutes.',
  },
  {
    id: 'anthropic-api-key',
    label: 'Anthropic API key',
    confidence: 'high',
    re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g,
    why: 'Anyone with this key spends your Anthropic credits and can read nothing of yours, but the bill is yours.',
  },
  {
    id: 'supabase-secret-key',
    label: 'Supabase secret key',
    confidence: 'high',
    re: /\bsb_secret_[A-Za-z0-9_-]{20,}\b/g,
    why: 'A Supabase secret key bypasses Row Level Security. It reads and writes every row in every table, for every user.',
  },
  {
    id: 'github-token',
    label: 'GitHub token',
    confidence: 'high',
    re: /\b(gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b/g,
    why: 'A GitHub token can read and push to your repositories, including private ones.',
  },
  {
    id: 'google-api-key',
    label: 'Google API key',
    confidence: 'high',
    re: /\bAIza[0-9A-Za-z_-]{35}\b/g,
    why: 'Google API keys are billed per call. An unrestricted leaked key gets abused for Maps or AI quota until the bill lands.',
  },
  {
    id: 'slack-token',
    label: 'Slack token',
    confidence: 'high',
    re: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g,
    why: 'A Slack token can read and post messages in your workspace as the app or as you.',
  },
  {
    id: 'sendgrid-api-key',
    label: 'SendGrid API key',
    confidence: 'high',
    re: /\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b/g,
    why: 'A SendGrid key lets anyone send email from your domain. That is how your domain ends up on spam blocklists.',
  },
  {
    id: 'twilio-credentials',
    label: 'Twilio account SID or API key',
    confidence: 'high',
    re: /\b(AC|SK)[0-9a-f]{32}\b/g,
    why: 'Twilio credentials send SMS and make calls on your account, billed per message.',
  },
  {
    id: 'private-key-block',
    label: 'Private key file contents',
    confidence: 'high',
    re: /-----BEGIN (RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----/g,
    why: 'This is the private half of a key pair. Whoever holds it can impersonate your server, sign tokens, or SSH into your machines.',
  },
  {
    id: 'database-url-with-password',
    label: 'Database connection string with password',
    confidence: 'high',
    re: /\b(postgres(ql)?|mysql|mongodb(\+srv)?|redis|rediss):\/\/[^\s:'"`/]+:[^\s@'"`]{6,}@[^\s'"`/]+/gi,
    why: 'This string contains your database username and password. Anyone who reads it can connect directly and dump or delete your data.',
  },
  {
    id: 'jwt-token',
    label: 'JSON Web Token (possibly a Supabase service_role key)',
    confidence: 'high',
    re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{10,}\b/g,
    why: 'Legacy Supabase service_role keys are JWTs, and they bypass Row Level Security completely — every row of every table, readable and writable.',
  },
  {
    id: 'public-env-var-holding-secret',
    label: 'Server-only secret exposed through a client-side environment variable',
    confidence: 'high',
    re: /\b(NEXT_PUBLIC|VITE|REACT_APP|EXPO_PUBLIC|PUBLIC|NUXT_PUBLIC|GATSBY)_[A-Z0-9_]*(SERVICE_ROLE|SECRET|PRIVATE_KEY|PASSWORD|API_KEY_SECRET)[A-Z0-9_]*\b/g,
    why: 'Any variable with a public prefix is compiled into the JavaScript your users download. A secret placed there is readable by everyone who opens your site — no hacking required.',
  },
  {
    id: 'generic-assigned-secret',
    label: 'Credential assigned inline',
    confidence: 'low',
    re: /\b([A-Za-z0-9_]*(api[_-]?key|secret|token|password|passwd|auth[_-]?key|access[_-]?key|client[_-]?secret)[A-Za-z0-9_]*)\s*[:=]\s*["'`]([^"'`\s]{12,})["'`]/gi,
    valueGroup: 3,
    why: 'This looks like a credential written straight into the code. If it is real, it belongs in an environment variable instead.',
  },
];

function readStdin() {
  return new Promise((resolve) => {
    let buf = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => (buf += c));
    process.stdin.on('end', () => resolve(buf));
    // If stdin never arrives, do not hang the tool call.
    setTimeout(() => resolve(buf), 5000).unref?.();
  });
}

/** Shannon entropy in bits per character. Real keys sit well above 3. */
function entropy(s) {
  const counts = new Map();
  for (const ch of s) counts.set(ch, (counts.get(ch) || 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function isExemptFile(filePath) {
  return EXEMPT_FILE.some((re) => re.test(filePath || ''));
}

/** Pull every chunk of text this tool call would write into the file. */
function extractText(toolName, input) {
  const parts = [];
  const push = (v) => {
    if (typeof v === 'string' && v.length) parts.push(v);
  };
  push(input?.content);
  push(input?.new_string);
  push(input?.new_text);
  push(input?.new_source);
  if (Array.isArray(input?.edits)) {
    for (const e of input.edits) {
      push(e?.new_string);
      push(e?.new_text);
    }
  }
  return parts.join('\n');
}

function looksFake(value) {
  if (!value) return false;
  if (PLACEHOLDER.test(value)) return true;
  if (PUBLIC_BY_DESIGN.some((re) => re.test(value))) return true;
  // A value made of one repeated character, or with almost no variety, is filler.
  if (/^(.)\1+$/.test(value)) return true;
  return false;
}

function scan(text) {
  const findings = [];
  const seen = new Set();
  const lines = text.split(/\r?\n/);

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/vibeguard-ignore/i.test(line)) continue;
    if (line.length > 4000) continue; // minified bundle or data blob

    for (const rule of RULES) {
      rule.re.lastIndex = 0;
      let m;
      while ((m = rule.re.exec(line)) !== null) {
        const whole = m[0];
        const value = rule.valueGroup ? m[rule.valueGroup] : whole;
        if (looksFake(value)) continue;
        if (rule.confidence === 'low' && entropy(value) < 3.2) continue;

        const key = rule.id + ':' + whole;
        if (seen.has(key)) continue;
        seen.add(key);

        findings.push({
          rule,
          line: i + 1,
          preview: redact(whole),
        });
      }
    }
  }
  return findings;
}

/** Show enough of the match to be recognizable, never the whole secret. */
function redact(s) {
  const flat = s.replace(/\s+/g, ' ').trim();
  if (flat.length <= 12) return flat;
  return flat.slice(0, 8) + '…' + flat.slice(-4);
}

function buildReason(filePath, findings) {
  const lines = [];
  lines.push('VibeGuard blocked this write: it contains what looks like a real credential.');
  lines.push('');
  for (const f of findings) {
    lines.push(`• Line ${f.line} — ${f.rule.label}: ${f.preview}`);
    lines.push(`  ${f.rule.why}`);
  }
  lines.push('');
  lines.push('Do this instead:');
  lines.push(`  1. Move the value into an environment variable, for example SERVICE_API_KEY, and put the real value in .env.local (which must be listed in .gitignore).`);
  lines.push(`  2. In code, read it with process.env.SERVICE_API_KEY on the server only. Never in a file that runs in the browser, and never behind a NEXT_PUBLIC_ / VITE_ / REACT_APP_ prefix.`);
  lines.push(`  3. Add the same variable to your hosting provider's environment settings (Vercel: Project Settings → Environment Variables).`);
  lines.push(`  4. If this value was ever committed, rotate it in the provider's dashboard. Deleting the line does not un-leak it — git keeps history.`);
  lines.push('');
  lines.push('If this is a fake or example value, add a `vibeguard-ignore` comment on that line, or set VIBEGUARD_DISABLE=1 for this session.');
  return lines.join('\n');
}

function emit(decision, reason) {
  process.stdout.write(
    JSON.stringify({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: decision,
        permissionDecisionReason: reason,
      },
    }),
  );
}

async function main() {
  if (DISABLED) process.exit(0);

  let payload;
  try {
    payload = JSON.parse(await readStdin());
  } catch {
    process.exit(0); // never break a tool call over a parsing problem
  }

  const toolName = payload?.tool_name || '';
  const input = payload?.tool_input || {};
  const filePath = input.file_path || input.notebook_path || '';

  if (isExemptFile(filePath)) process.exit(0);

  const text = extractText(toolName, input);
  if (!text) process.exit(0);

  const findings = scan(text);
  if (findings.length === 0) process.exit(0);

  const reason = buildReason(filePath, findings);
  const highConfidence = findings.some((f) => f.rule.confidence === 'high');

  if (highConfidence) {
    emit('deny', reason);
    process.exit(2);
  }

  emit('ask', reason.replace('VibeGuard blocked this write', 'VibeGuard paused this write'));
  process.exit(0);
}

main();
