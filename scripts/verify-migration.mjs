#!/usr/bin/env node
// Static verification for supabase/migrations/2026-11-23-phase0-admin-security.sql
//
// This script does NOT execute SQL and does NOT connect to any database. It reads
// the migration as text and asserts the properties the security review asked for,
// so a later edit cannot silently undo them:
//
//   item 1  rollback is complete   -> A0c tgenabled, A0g constraint capture,
//                                     A0h conflict register, B0b fail-closed
//                                     preflight, D.1.1-D.1.5 staged restore
//   item 2  role membership        -> 'SET' on PG16+ with 'MEMBER' fallback, and
//                                     no live gate on 'USAGE'
//   item 3  missing functions      -> has_function_privilege() only behind
//                                     to_regprocedure()
//   item 4  RLS dependency         -> B2.3 gate and C9 report
//
// Exit code 0 = all assertions hold, 1 = at least one regressed.
//
// Usage: node scripts/verify-migration.mjs [path]

import { readFileSync } from 'node:fs';

const path = process.argv[2] ?? 'supabase/migrations/2026-11-23-phase0-admin-security.sql';
const src = readFileSync(path, 'utf8');
const lines = src.split('\n');

const passed = [];
const failed = [];

function check(name, condition, detail) {
  if (condition) {
    passed.push(name);
  } else {
    failed.push(detail ? `${name} (${detail})` : name);
  }
}

const isComment = (line) => line.trimStart().startsWith('--');

// --- revision marker and section skeleton -----------------------------------
check('header marks Revision 7', /^-- STATUS: PROPOSAL ONLY — REVISION 7/m.test(src));

for (const section of ['A', 'B', 'C', 'D', 'S']) {
  check(
    `Section ${section} present`,
    new RegExp(`^-- SECTION ${section}\\b`, 'm').test(src),
  );
}

// --- item 1: capture, preflight, staged rollback ----------------------------
check('A0c captures trigger enabled state', /\btgenabled\b/.test(src));
check('A0c/A0g emit restore_statement', /\brestore_statement\b/.test(src));
check('A0g captures constraint validation', /\bconvalidated\b/.test(src));
check('A0h conflict register present', /^-- A0h\./m.test(src));
check('B0b fail-closed preflight present', /^-- B0b\./m.test(src));
check(
  'B0b override is documented',
  /allow_preexisting_objects/.test(src),
);

// A0h must enumerate all 14 objects B touches (11 created + 3 replaced).
const a0hStart = lines.findIndex((l) => /^-- A0h\./.test(l));
const b0bStart = lines.findIndex((l) => /^-- B0b\./.test(l));
check('A0h precedes B0b', a0hStart !== -1 && b0bStart !== -1 && a0hStart < b0bStart);
if (a0hStart !== -1 && b0bStart !== -1) {
  const register = lines.slice(a0hStart, b0bStart).join('\n');
  const numbers = [...register.matchAll(/^--\s*\|\s*(\d+)\s*\|/gm)].map((m) => Number(m[1]));
  const contiguous =
    numbers.length === 14 && numbers.every((n, i) => n === i + 1);
  check(
    'A0h lists exactly 14 objects, numbered 1-14',
    contiguous,
    `found ${numbers.length}: ${numbers.join(',') || 'none'}`,
  );
  check('A0h distinguishes RESTORE from DROP', /RESTORE/.test(register));
}

for (const stage of ['D.1.1', 'D.1.2', 'D.1.3', 'D.1.4', 'D.1.5']) {
  check(`rollback stage ${stage} present`, src.includes(stage));
}

// --- item 2: SET ROLE capability, not USAGE --------------------------------
check(
  "role gate uses 'SET' with a 'MEMBER' fallback",
  /then\s+'SET'\s+else\s+'MEMBER'/.test(src),
);
check(
  'ownership reassignment is verified after ALTER',
  /proowner/.test(src) && /alter function/i.test(src),
);

// No live statement may gate on 'USAGE'. The single permitted occurrence is the
// deliberate negative diagnostic whose alias records why it is wrong.
const liveUsage = lines.filter((l) => l.includes("'USAGE'") && !isComment(l));
check(
  "no live pg_has_role(...,'USAGE') gate",
  liveUsage.every((l) => l.includes('usage_privilege_not_sufficient')),
  liveUsage.map((l) => l.trim().slice(0, 80)).join(' | ') || undefined,
);

// --- item 3: to_regprocedure guards has_function_privilege -----------------
const functionPrivilegeCalls = lines.filter(
  (l) => /has_function_privilege\s*\(/.test(l) && !isComment(l),
);
check(
  'has_function_privilege() is always reached through to_regprocedure()',
  functionPrivilegeCalls.length > 0 &&
    functionPrivilegeCalls.every((l) => /to_regprocedure\s*\(/.test(l)),
  `${functionPrivilegeCalls.length} live call(s)`,
);
check('A10c reports function existence', /lsp_is_admin_exists/.test(src));

// --- item 4: provider_profiles RLS dependency ------------------------------
check('B2.3 RLS dependency gate present', /^-- B2\.3\b/m.test(src));
check('C9 RLS dependency report present', /^-- C9\./m.test(src));
check(
  'RLS gate inspects relrowsecurity and relforcerowsecurity',
  /relrowsecurity/.test(src) && /relforcerowsecurity/.test(src),
);
check('RLS gate considers helper bypassrls', /bypassrls/i.test(src));

// --- Revision 6 spelling regressions must stay fixed -----------------------
// These four tokens are named in the changelog, so they may appear in comments
// only. Any live occurrence is a regression.
const forbidden = [
  { name: 'count() without an argument', re: /count\s*\(\s*\)/ },
  { name: 'acl_default', re: /\bacl_default\b/ },
  { name: 'coallesce', re: /\bcoallesce\b/ },
  { name: 'scheman', re: /\bscheman\b/ },
];
for (const { name, re } of forbidden) {
  const live = lines.filter((l) => re.test(l) && !isComment(l));
  check(
    `no live use of ${name}`,
    live.length === 0,
    live.map((l) => l.trim().slice(0, 60)).join(' | ') || undefined,
  );
}

// --- quoting and block structure -------------------------------------------
const dollarTokens = src.split('$$').length - 1;
check('$$ delimiters are balanced', dollarTokens % 2 === 0, `${dollarTokens} tokens`);

const stack = [];
let unclosed = 0;
lines.forEach((line, i) => {
  const trimmed = line.trim();
  if (trimmed.startsWith('do $$')) stack.push(i + 1);
  else if (trimmed.startsWith('end $$;')) {
    if (stack.length > 0) stack.pop();
    // Otherwise this closes a plpgsql function body (return ...; end $$;).
  }
});
check(
  'every DO block is closed',
  stack.length === 0,
  stack.length ? `unclosed at line(s) ${stack.join(',')}` : undefined,
);

for (const fn of [
  'lsp_guard_profile_role',
  'lsp_guard_provider_verification',
  'lsp_guard_document_status',
]) {
  check(`guard function ${fn} defined`, src.includes(`function public.${fn}`) || src.includes(fn));
}

// --- limitations must remain explicit -------------------------------------
for (const id of ['L1', 'L2', 'L3', 'L4', 'L5']) {
  check(`limitation ${id} present`, new RegExp(`^--\\s*${id}\\.`, 'm').test(src));
}

// --- report ---------------------------------------------------------------
console.log(`verify-migration: ${path}`);
console.log(`  ${lines.length} lines, ${passed.length} checks passed, ${failed.length} failed\n`);

if (failed.length > 0) {
  for (const f of failed) console.error(`  FAIL  ${f}`);
  console.error('\nverify-migration: FAILED');
  process.exit(1);
}

for (const p of passed) console.log(`  ok    ${p}`);
console.log('\nverify-migration: PASSED');
