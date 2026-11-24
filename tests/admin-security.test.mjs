// Security regression tests for the 2026-11-24 hardening.
//
// Two layers are covered:
//   1. The pure authorization model in src/lib/adminValidation.js, which mirrors
//      the database rules and is what the Admin module consults before acting.
//   2. The shipped SQL itself: the migration and the two schema scripts are read
//      from disk and asserted to keep the guard trigger and the scoped services
//      policy, and to contain no permissive `using (true) with check (true)`
//      services write.
//
// These tests do not connect to Supabase. Live RLS behaviour is listed as a
// remaining manual check in the migration's section 4.

import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';

import {
  canMintDocumentLink,
  canWriteServiceRow,
  isTrustedAdminSession,
  resolveProfileRoleChange,
  roleWriteDecision,
} from '../src/lib/adminValidation.js';

const read = (relative) => readFileSync(new URL(relative, import.meta.url), 'utf8');

const migration = read('../supabase/migrations/2026-11-24-role-guard-and-services-scope.sql');
// The 2026-11-25 migration supersedes the guard from the file above.
const guardMigration = read('../supabase/migrations/2026-11-25-role-guard-trusted-session.sql');
const schemaSql = read('../supabase/schema.sql');
const permissiveScript = read('../supabase/allow-authorized-writes.sql');

/* --------------------------------------------------- role escalation (model) */

test('a customer cannot promote themselves to admin', () => {
  const result = resolveProfileRoleChange({
    actorId: 'customer-1',
    targetId: 'customer-1',
    currentRole: 'customer',
    nextRole: 'admin',
  });

  assert.equal(result.allowed, false);
  assert.equal(result.persistedRole, 'customer');
  assert.match(result.reason, /own role/i);
});

test('a provider cannot promote themselves to admin', () => {
  const result = resolveProfileRoleChange({
    actorId: 'provider-1',
    targetId: 'provider-1',
    currentRole: 'provider',
    nextRole: 'admin',
  });

  assert.equal(result.allowed, false);
  assert.equal(result.persistedRole, 'provider');
});

test('an authenticated user cannot change another user\'s role', () => {
  const result = resolveProfileRoleChange({
    actorId: 'customer-1',
    targetId: 'customer-2',
    currentRole: 'customer',
    nextRole: 'provider',
  });

  assert.equal(result.allowed, false);
  assert.equal(result.persistedRole, 'customer');
  assert.match(result.reason, /trusted administrative process/i);
});

test('an admin role cannot be changed through an ordinary profile update', () => {
  const demote = resolveProfileRoleChange({
    actorId: 'admin-1',
    targetId: 'admin-1',
    currentRole: 'admin',
    nextRole: 'customer',
  });
  assert.equal(demote.allowed, false);
  assert.equal(demote.persistedRole, 'admin');

  const otherAdmin = resolveProfileRoleChange({
    actorId: 'admin-1',
    targetId: 'customer-3',
    currentRole: 'customer',
    nextRole: 'admin',
  });
  assert.equal(otherAdmin.allowed, false);
  assert.equal(otherAdmin.persistedRole, 'customer');
});

test('legitimate profile saves that echo the current role still succeed', () => {
  const unchanged = resolveProfileRoleChange({
    actorId: 'customer-1',
    targetId: 'customer-1',
    currentRole: 'customer',
    nextRole: 'customer',
  });
  assert.equal(unchanged.allowed, true);
  assert.equal(unchanged.persistedRole, 'customer');

  const omitted = resolveProfileRoleChange({
    actorId: 'provider-1',
    targetId: 'provider-1',
    currentRole: 'provider',
  });
  assert.equal(omitted.allowed, true);
  assert.equal(omitted.persistedRole, 'provider');
});

test('only the trusted administrative process may change a role', () => {
  const result = resolveProfileRoleChange({
    actorId: 'operator',
    targetId: 'customer-1',
    currentRole: 'customer',
    nextRole: 'admin',
    trustedProcess: true,
  });

  assert.equal(result.allowed, true);
  assert.equal(result.persistedRole, 'admin');
});

test('an unknown role value is rejected rather than stored', () => {
  const result = resolveProfileRoleChange({
    actorId: 'operator',
    targetId: 'customer-1',
    currentRole: 'customer',
    nextRole: 'superuser',
    trustedProcess: true,
  });

  assert.equal(result.allowed, false);
  assert.equal(result.persistedRole, 'customer');
});

/* --------------------------------------- trusted-session guard (model) */
// Reproduces, without a database, the identity pairs PostgreSQL actually
// presents. The SECURITY DEFINER rows are the reported bypass: current_user is
// the function owner while session_user is still the caller's login role.

const CUSTOMER_SESSION = { sessionUser: 'authenticator', currentUser: 'authenticated', apiRequest: true };
const DEFINER_OWNED_BY_POSTGRES = { sessionUser: 'authenticator', currentUser: 'postgres', apiRequest: true };
const SQL_EDITOR = { sessionUser: 'postgres', currentUser: 'postgres', apiRequest: false, isSuperuser: true };

test('a customer cannot self-promote by direct profile update', () => {
  const result = roleWriteDecision({
    ...CUSTOMER_SESSION,
    operation: 'update',
    oldRole: 'customer',
    newRole: 'admin',
  });

  assert.equal(result.action, 'pin');
  assert.equal(result.persistedRole, 'customer');
});

test('a provider cannot self-promote by direct profile update', () => {
  const result = roleWriteDecision({
    ...CUSTOMER_SESSION,
    operation: 'update',
    oldRole: 'provider',
    newRole: 'admin',
  });

  assert.equal(result.action, 'pin');
  assert.equal(result.persistedRole, 'provider');
});

test('self-promotion through an upsert is refused before conflict resolution', () => {
  const result = roleWriteDecision({
    ...CUSTOMER_SESSION,
    operation: 'insert',
    oldRole: null,
    newRole: 'admin',
  });

  assert.equal(result.action, 'deny');
  assert.equal(result.code, '42501');
});

test('self-promotion through a SECURITY DEFINER RPC owned by postgres is pinned', () => {
  // Inside the function current_user is postgres; session_user is still the
  // caller's login role, so no administration session is in effect.
  assert.equal(isTrustedAdminSession({ ...DEFINER_OWNED_BY_POSTGRES, isSuperuser: true }), false);

  const update = roleWriteDecision({
    ...DEFINER_OWNED_BY_POSTGRES,
    isSuperuser: true,
    operation: 'update',
    oldRole: 'customer',
    newRole: 'admin',
  });
  assert.equal(update.action, 'pin');
  assert.equal(update.persistedRole, 'customer');

  const insert = roleWriteDecision({
    ...DEFINER_OWNED_BY_POSTGRES,
    isSuperuser: true,
    operation: 'insert',
    newRole: 'admin',
  });
  assert.equal(insert.action, 'deny');
  assert.equal(insert.code, '42501');
});

test('an ordinary profile update that echoes the role still succeeds', () => {
  const echoed = roleWriteDecision({
    ...CUSTOMER_SESSION,
    operation: 'update',
    oldRole: 'customer',
    newRole: 'customer',
  });
  assert.equal(echoed.action, 'allow');
  assert.equal(echoed.persistedRole, 'customer');

  const omitted = roleWriteDecision({
    ...CUSTOMER_SESSION,
    operation: 'update',
    oldRole: 'provider',
    newRole: null,
  });
  assert.equal(omitted.action, 'allow');
  assert.equal(omitted.persistedRole, 'provider');
});

test('a trusted SQL Editor session may provision an administrator', () => {
  assert.equal(isTrustedAdminSession(SQL_EDITOR), true);

  const result = roleWriteDecision({
    ...SQL_EDITOR,
    operation: 'update',
    oldRole: 'customer',
    newRole: 'admin',
  });
  assert.equal(result.action, 'allow');
  assert.equal(result.persistedRole, 'admin');
});

test('a service_role API request cannot change a role', () => {
  const result = roleWriteDecision({
    sessionUser: 'authenticator',
    currentUser: 'service_role',
    apiRequest: true,
    isProvisioner: true,
    operation: 'update',
    oldRole: 'customer',
    newRole: 'admin',
  });

  assert.equal(result.action, 'pin');
  assert.equal(result.persistedRole, 'customer');
});

test('provisioner membership cannot survive an elevation', () => {
  // An API role with membership is still an API role.
  assert.equal(
    isTrustedAdminSession({
      sessionUser: 'authenticator',
      currentUser: 'authenticated',
      apiRequest: true,
      isProvisioner: true,
    }),
    false,
  );

  // A definer function that switched identity no longer matches session_user.
  assert.equal(
    isTrustedAdminSession({
      sessionUser: 'postgres',
      currentUser: 'authenticated',
      apiRequest: false,
      isProvisioner: true,
    }),
    false,
  );
});

test('an explicit provisioner session on a direct connection is trusted', () => {
  assert.equal(
    isTrustedAdminSession({
      sessionUser: 'lsp_provisioner_ops',
      currentUser: 'lsp_provisioner_ops',
      apiRequest: false,
      isProvisioner: true,
    }),
    true,
  );

  const result = roleWriteDecision({
    sessionUser: 'lsp_provisioner_ops',
    currentUser: 'lsp_provisioner_ops',
    isProvisioner: true,
    operation: 'update',
    oldRole: 'provider',
    newRole: 'admin',
  });
  assert.equal(result.persistedRole, 'admin');
});

test('the API login role is refused rather than guessed at', () => {
  const result = roleWriteDecision({
    sessionUser: 'authenticator',
    currentUser: 'authenticator',
    apiRequest: true,
    operation: 'update',
    oldRole: 'customer',
    newRole: 'admin',
  });

  assert.equal(result.action, 'deny');
  assert.equal(result.code, '42501');
});

/* ------------------------------------------------------ services (model) */

test('a customer cannot create, modify or delete services', () => {
  const create = canWriteServiceRow({ role: 'customer', row: {} });
  const modify = canWriteServiceRow({ role: 'customer', row: { providerId: 'provider-1' } });
  const remove = canWriteServiceRow({ role: 'customer', row: { providerId: 'customer-1' } });

  assert.equal(create, false);
  assert.equal(modify, false);
  assert.equal(remove, false);
});

test('a provider may manage only their own services', () => {
  const own = canWriteServiceRow({
    role: 'provider',
    providerIds: ['provider-1'],
    row: { providerId: 'provider-1' },
  });
  assert.equal(own, true);

  const other = canWriteServiceRow({
    role: 'provider',
    providerIds: ['provider-1'],
    row: { providerId: 'provider-2' },
  });
  assert.equal(other, false);

  const newRow = canWriteServiceRow({
    role: 'provider',
    providerIds: ['provider-1'],
    row: { providerId: 'provider-1', title: 'New service' },
  });
  assert.equal(newRow, true);
});

test('a provider cannot create an unowned catalogue row', () => {
  assert.equal(canWriteServiceRow({ role: 'provider', providerIds: ['provider-1'], row: {} }), false);
});

test('providers are refused when the catalogue has no owner column', () => {
  assert.equal(
    canWriteServiceRow({
      role: 'provider',
      providerIds: ['provider-1'],
      row: { providerId: 'provider-1' },
      hasOwnerColumn: false,
    }),
    false,
  );
});

test('an admin retains authorized service-management access', () => {
  assert.equal(canWriteServiceRow({ role: 'admin', row: { providerId: 'provider-2' } }), true);
  assert.equal(canWriteServiceRow({ role: 'admin', row: {} }), true);
  assert.equal(canWriteServiceRow({ role: 'admin', row: {}, hasOwnerColumn: false }), true);
});

/* --------------------------------------------------- document links (model) */

test('non-admins cannot generate admin document links', () => {
  assert.equal(canMintDocumentLink('customer'), false);
  assert.equal(canMintDocumentLink('provider'), false);
  assert.equal(canMintDocumentLink(''), false);
  assert.equal(canMintDocumentLink(undefined), false);
});

test('an admin may generate document links', () => {
  assert.equal(canMintDocumentLink('admin'), true);
  assert.equal(canMintDocumentLink(' Admin '), true);
});

/* ------------------------------------------------------------- SQL contract */

// Comments cannot grant privileges, so policy assertions are made against
// executable SQL only: line and block comments are stripped first. The rollback
// and trigger assertions below deliberately use the raw text.
const executableSql = (text) =>
  String(text)
    .replace(/--[^\n]*/g, '')
    .replace(/\/\*[\s\S]*?\*\//g, '');

const migrationSql = executableSql(migration);

test('the guard migration installs the role guard as a BEFORE row trigger', () => {
  assert.match(guardMigration, /create trigger lsp_guard_profile_role\s+before insert or update on public\.profiles/i);
  assert.match(guardMigration, /drop trigger if exists lsp_guard_profile_role on public\.profiles/i);
  assert.match(guardMigration, /create or replace function public\.lsp_guard_profile_role\(\)/i);
  assert.match(guardMigration, /security invoker/i);
});

test('the guard pins the role on update and rejects privileged inserts', () => {
  assert.match(guardMigration, /new\.role := old\.role/);
  assert.match(guardMigration, /new\.role not in \('customer',\s*'provider'\)/);
  assert.match(guardMigration, /using errcode = '42501'/);
});

test('the guard decides trust from session identity, not the effective role', () => {
  // The fix: an elevation of any kind (SECURITY DEFINER, SET ROLE) makes these
  // two differ, and the guard then treats the caller as an app caller.
  assert.match(guardMigration, /v_session\s+text := session_user/);
  assert.match(guardMigration, /v_current\s+text := current_user/);
  assert.match(guardMigration, /v_session = v_current/);
  assert.match(guardMigration, /v_current not in \('anon', 'authenticated'/);
  assert.match(guardMigration, /pg_has_role\(v_current, 'lsp_role_provisioner', 'MEMBER'\)/);
  assert.match(guardMigration, /bool_or\(r\.rolsuper\)/);
});

test('the guard treats API request GUCs as a disqualifier only', () => {
  assert.match(guardMigration, /current_setting\('request\.jwt\.claims', true\)/);
  assert.match(guardMigration, /current_setting\('request\.method', true\)/);
  // Presence disqualifies: the flag is only ever used to remove trust.
  assert.match(guardMigration, /if not v_api_request and v_session = v_current then/);
});

test('the new migration declares the earlier guard superseded', () => {
  assert.match(guardMigration, /2026-11-24-role-guard-and-services-scope\.sql/);
  assert.match(guardMigration, /2026-11-23-phase0-admin-security\.sql/);
});

test('the guard migration revokes provisioner membership from API roles', () => {
  assert.match(guardMigration, /revoke lsp_role_provisioner from %I/);
  assert.match(guardMigration, /nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls/);
});

test('the migration contains no permissive services write policy', () => {
  assert.doesNotMatch(migrationSql, /using \(true\) with check \(true\)/i);
  assert.match(migrationSql, /drop policy if exists lsp_services_write on public\.services/i);
  assert.match(
    migrationSql,
    /provider_id in \(select public\.lsp_provider_ids\(\)\) or public\.lsp_is_admin\(\)/i,
  );
});

test('the guard migration fails closed when the helper functions are missing', () => {
  assert.match(guardMigration, /to_regprocedure\('public\.lsp_is_admin\(\)'\) is null/i);
  assert.match(guardMigration, /to_regprocedure\('public\.lsp_provider_ids\(\)'\) is null/i);
  assert.match(guardMigration, /raise exception 'lsp_preflight/i);
});

test('the migration ships rollback instructions', () => {
  assert.match(migration, /-- 5\. ROLLBACK/i);
  assert.match(migration, /drop function if exists public\.lsp_guard_profile_role\(\)/i);
  assert.match(migration, /drop policy if exists lsp_services_write on public\.services/i);
});

test('schema.sql protects fresh installs with the same guard trigger', () => {
  assert.match(schemaSql, /create or replace function public\.lsp_guard_profile_role\(\)/i);
  assert.match(schemaSql, /create trigger lsp_guard_profile_role before insert or update on public\.profiles/i);
  // Fresh installs must get the session-identity guard, not the old allowlist.
  assert.match(schemaSql, /v_session = v_current/);
  assert.doesNotMatch(schemaSql, /api_role text := current_user/);
});

test('the permissive services policy is gone from allow-authorized-writes.sql', () => {
  const servicesWrite = executableSql(permissiveScript).match(
    /create policy lsp_services_write on public\.services[\s\S]{0,240}?;/i,
  );
  assert.ok(servicesWrite, 'lsp_services_write should still be defined');
  assert.doesNotMatch(servicesWrite[0], /using \(true\)/i);
  assert.match(servicesWrite[0], /lsp_provider_ids\(\)/i);
});

test('both schema scripts keep the services write policy owner-or-admin', () => {
  const schemaPolicy = executableSql(schemaSql).match(
    /create policy lsp_services_write on public\.services[\s\S]{0,240}?;/i,
  );
  assert.ok(schemaPolicy, 'schema.sql should define lsp_services_write');
  assert.doesNotMatch(schemaPolicy[0], /using \(true\)/i);
  assert.match(schemaPolicy[0], /lsp_is_admin\(\)/i);
});
