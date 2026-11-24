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
  resolveProfileRoleChange,
} from '../src/lib/adminValidation.js';

const read = (relative) => readFileSync(new URL(relative, import.meta.url), 'utf8');

const migration = read('../supabase/migrations/2026-11-24-role-guard-and-services-scope.sql');
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

test('the migration installs the role guard as a BEFORE row trigger', () => {
  assert.match(migration, /create trigger lsp_guard_profile_role before insert or update on public\.profiles/i);
  assert.match(migration, /drop trigger if exists lsp_guard_profile_role on public\.profiles/i);
  assert.match(migration, /create or replace function public\.lsp_guard_profile_role\(\)/i);
});

test('the guard pins the role on update and rejects privileged inserts', () => {
  assert.match(migration, /new\.role := old\.role/);
  assert.match(migration, /new\.role not in \('customer','provider'\)/);
  assert.match(migration, /using errcode = '42501'/);
});

test('the guard only trusts the administrative allowlist', () => {
  assert.match(migration, /array\['postgres','supabase_admin','supabase_storage_admin','supabase_auth_admin','service_role'\]/);
  assert.match(migration, /if api_role <> 'authenticated' then/);
});

test('the migration contains no permissive services write policy', () => {
  assert.doesNotMatch(migration, /using \(true\) with check \(true\)/i);
  assert.match(migration, /drop policy if exists lsp_services_write on public\.services/i);
  assert.match(migration, /provider_id in \(select public\.lsp_provider_ids\(\)\) or public\.lsp_is_admin\(\)/i);
});

test('the migration fails closed when the helper functions are missing', () => {
  assert.match(migration, /to_regprocedure\('public\.lsp_is_admin\(\)'\) is null/i);
  assert.match(migration, /to_regprocedure\('public\.lsp_provider_ids\(\)'\) is null/i);
  assert.match(migration, /raise exception 'lsp_preflight/i);
});

test('the migration ships rollback instructions', () => {
  assert.match(migration, /-- 5\. ROLLBACK/i);
  assert.match(migration, /drop function if exists public\.lsp_guard_profile_role\(\)/i);
  assert.match(migration, /drop policy if exists lsp_services_write on public\.services/i);
});

test('schema.sql protects fresh installs with the same guard trigger', () => {
  assert.match(schemaSql, /create or replace function public\.lsp_guard_profile_role\(\)/i);
  assert.match(schemaSql, /create trigger lsp_guard_profile_role before insert or update on public\.profiles/i);
});

test('the permissive services policy is gone from allow-authorized-writes.sql', () => {
  const servicesWrite = permissiveScript.match(
    /create policy lsp_services_write on public\.services[\s\S]{0,240}?;/i,
  );
  assert.ok(servicesWrite, 'lsp_services_write should still be defined');
  assert.doesNotMatch(servicesWrite[0], /using \(true\)/i);
  assert.match(servicesWrite[0], /lsp_provider_ids\(\)/i);
});

test('both schema scripts keep the services write policy owner-or-admin', () => {
  const schemaPolicy = schemaSql.match(/create policy lsp_services_write on public\.services[\s\S]{0,240}?;/i);
  assert.ok(schemaPolicy, 'schema.sql should define lsp_services_write');
  assert.doesNotMatch(schemaPolicy[0], /using \(true\)/i);
  assert.match(schemaPolicy[0], /lsp_is_admin\(\)/i);
});
