import { run as hook } from './hook.test.mjs';
import { run as sql } from './sql.test.mjs';

console.log('# hook — hardcoded secret detection\n');
const h = hook();
console.log('\n# rls-check — SQL against a real Postgres\n');
const s = await sql();

const total = h.total + s.total;
const failed = h.failed + s.failed;
console.log(`\n${total - failed}/${total} checks passed`);
process.exit(failed ? 1 : 0);
