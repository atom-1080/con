-- ===========================================================================
-- LSP Connect — 2026-11-24 — role-escalation guard + services write scoping
-- ===========================================================================
-- WHAT THIS FIXES
--   1. public.profiles.role could be self-assigned. lsp_profiles_update is
--      row-scoped (id = auth.uid()) and PostgreSQL RLS has no column-level
--      policies, so {"role":"admin"} in a PATCH to /rest/v1/profiles passed.
--      Anyone could then satisfy lsp_is_admin() and open the Admin module.
--   2. public.services could be written by any signed-in user wherever the
--      permissive `using (true) with check (true)` variant from
--      supabase/allow-authorized-writes.sql was applied.
--
-- WHY A TRIGGER AND NOT A COLUMN RESTRICTION
--   `revoke update (role) on public.profiles from authenticated` would also
--   break legitimate saves: src/lib/api.js ensureProfile() sends `role` in the
--   same payload as full_name/phone/city on every profile upsert, and a
--   column-level revoke rejects the whole statement, not just the changed
--   column. A BEFORE trigger can see OLD and NEW and pin only the role value,
--   which keeps normal profile saves working while making role immutable from
--   any client session.
--
-- ORDERING / DEPENDENCIES
--   * Requires public.profiles (supabase/schema.sql) and the helper functions
--     public.lsp_is_admin() / public.lsp_provider_ids(). Both are asserted
--     below and the migration aborts with a clear message if they are absent
--     (fail-closed rather than silently creating a weaker policy).
--   * Independent of 2026-11-23-phase0-admin-security.sql, but compatible with
--     it: section B3 of that migration defines the same function and trigger,
--     and this file uses CREATE OR REPLACE / DROP ... IF EXISTS so applying
--     either order, or both, converges on one definition. It reuses only that
--     validated B3 component; no other part of Phase 0 is applied here.
--   * Postgres 12+ (Supabase). Uses only plpgsql, pg_policies,
--     information_schema.columns, to_regprocedure and CREATE POLICY.
--   * Idempotent: safe to re-run.
--
-- NOT DONE HERE
--   No data changes, no grants, no revokes, no service-role credentials, and no
--   frontend-visible change. Existing policies are recreated equal-or-stricter;
--   bookings, payments, complaints, documents and customer/provider flows are
--   untouched.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- 0. Preflight — fail closed with an actionable message.
-- ---------------------------------------------------------------------------
do $$
begin
  if to_regclass('public.profiles') is null then
    raise exception 'lsp_preflight: public.profiles is missing; apply supabase/schema.sql first';
  end if;
  if to_regprocedure('public.lsp_is_admin()') is null then
    raise exception 'lsp_preflight: public.lsp_is_admin() is missing; apply supabase/schema.sql first';
  end if;
  if to_regprocedure('public.lsp_provider_ids()') is null then
    raise exception 'lsp_preflight: public.lsp_provider_ids() is missing; apply supabase/schema.sql first';
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- 1. Role guard. Reused verbatim from the validated Phase 0 section B3.
--
--    THE GATE: `trusted` is an ALLOWLIST of the roles Supabase uses for
--    privileged paths. Everything else must be `authenticated` with a real JWT
--    subject, or it is rejected with 42501.
--
--    current_user is used, not a request header: PostgREST sets the session
--    role from the signed JWT `role` claim, so it cannot be forged from a
--    browser. `authenticator` is the login role PostgREST switches away from
--    and is absent from the allowlist, so it is denied.
--
--    UPDATE pins role to old.role instead of raising, because api.js
--    ensureProfile() echoes `role` back on every save. Pinning keeps that save
--    working and makes the attempted change a no-op. INSERT restricts new rows
--    to customer/provider, so a profile cannot be born privileged.
--
--    Consequence, deliberately: an admin signed in through the app cannot
--    change any role either. Privileged role changes happen only through the
--    trusted administrative process (SQL Editor / service_role), which is the
--    requirement.
-- ---------------------------------------------------------------------------
create or replace function public.lsp_guard_profile_role()
returns trigger language plpgsql security invoker
set search_path = pg_catalog, public as $$
declare
  api_role text := current_user;
  trusted  constant text[] := array['postgres','supabase_admin','supabase_storage_admin','supabase_auth_admin','service_role'];
begin
  if api_role = any (trusted) then
    return new;                                        -- SQL Editor, migrations, service_role
  end if;

  if api_role <> 'authenticated' then
    raise exception 'lsp_write_denied: role % may not write public.profiles', api_role
      using errcode = '42501';                         -- anon and any unknown role
  end if;

  if (select auth.uid()) is null then
    raise exception 'lsp_write_denied: authenticated session without a subject'
      using errcode = '42501';
  end if;

  if tg_op = 'INSERT' then
    if new.role is null then
      new.role := 'customer';                          -- new row only
    end if;
    if new.role not in ('customer','provider') then
      raise exception 'lsp_role_escalation_blocked: cannot create a profile with role %', new.role
        using errcode = '42501';
    end if;
    return new;
  end if;

  if new.role is distinct from old.role then
    raise log 'lsp_guard_profile_role: blocked % -> % for profile %', old.role, new.role, new.id;
    new.role := old.role;
  end if;
  return new;
end $$;

drop trigger if exists lsp_guard_profile_role on public.profiles;
create trigger lsp_guard_profile_role before insert or update on public.profiles
  for each row execute function public.lsp_guard_profile_role();

-- ---------------------------------------------------------------------------
-- 2. Profiles policies — recreated unchanged in shape, documented for review.
--
--    lsp_profiles_update stays row-scoped: `id = auth.uid()` for a user's own
--    row, `lsp_is_admin()` for an admin acting on another row. Cross-user role
--    changes are blocked twice over — RLS rejects the row, and the trigger
--    pins role even when the row is reachable. The trigger, not the policy, is
--    what closes the column hole.
-- ---------------------------------------------------------------------------
drop policy if exists lsp_profiles_update on public.profiles;
create policy lsp_profiles_update on public.profiles for update to authenticated
  using (id = (select auth.uid()) or public.lsp_is_admin())
  with check (id = (select auth.uid()) or public.lsp_is_admin());

drop policy if exists lsp_profiles_insert on public.profiles;
create policy lsp_profiles_insert on public.profiles for insert to authenticated
  with check (id = (select auth.uid()));

-- ---------------------------------------------------------------------------
-- 3. Services write scope.
--
--    schema.sql declares public.services.provider_id (references
--    provider_profiles(id)); a database provisioned from an earlier or partial
--    script may not have it. The policy is chosen from the catalog rather than
--    assumed:
--      * owner column present -> provider may write only rows they own, admin
--        may write all (owner-or-admin).
--      * owner column absent  -> the shared catalogue has no owner, so writes
--        are admin-only. Provider catalogue work lives in public.provider_skills,
--        which is already owner-scoped, so no provider functionality is lost.
--    In both branches a customer has no write path: `using (true)` is gone.
-- ---------------------------------------------------------------------------
do $$
declare
  has_owner boolean;
begin
  select exists (
    select 1 from information_schema.columns
     where table_schema = 'public'
       and table_name   = 'services'
       and column_name  = 'provider_id'
  ) into has_owner;

  -- Read access must survive the change; create it only if the database lacks it.
  if not exists (
    select 1 from pg_policies
     where schemaname = 'public' and tablename = 'services' and policyname = 'lsp_services_read'
  ) then
    create policy lsp_services_read on public.services for select using (true);
  end if;

  drop policy if exists lsp_services_write on public.services;

  if has_owner then
    create policy lsp_services_write on public.services for all to authenticated
      using (provider_id in (select public.lsp_provider_ids()) or public.lsp_is_admin())
      with check (provider_id in (select public.lsp_provider_ids()) or public.lsp_is_admin());
    raise notice 'lsp_services_write: owner-or-admin (provider_id column present)';
  else
    create policy lsp_services_write on public.services for all to authenticated
      using (public.lsp_is_admin())
      with check (public.lsp_is_admin());
    raise notice 'lsp_services_write: admin-only (no provider_id column on public.services)';
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- 4. Read-only verification. Run these after applying; they change nothing.
-- ---------------------------------------------------------------------------
-- 4a. The guard must exist and be a BEFORE row trigger on profiles.
--   select tgname, tgenabled, tgtype
--     from pg_trigger
--    where tgrelid = 'public.profiles'::regclass and not tgisinternal;
--
-- 4b. Services must no longer be world-writable.
--   select policyname, cmd, qual, with_check
--     from pg_policies
--    where schemaname = 'public' and tablename = 'services';
--
-- 4c. Behavioural check, rolled back — run as a customer session, not as postgres.
--   begin;
--     select set_config('request.jwt.claims',
--            json_build_object('sub','<customer-uuid>','role','authenticated')::text, true);
--     set local role authenticated;
--     update public.profiles set role = 'admin' where id = '<customer-uuid>';
--     select role from public.profiles where id = '<customer-uuid>';  -- still 'customer'
--   rollback;
--
-- 4d. Same session, services write must affect zero rows.
--   begin;
--     select set_config('request.jwt.claims',
--            json_build_object('sub','<customer-uuid>','role','authenticated')::text, true);
--     set local role authenticated;
--     delete from public.services where true;                          -- 0 rows
--   rollback;

-- ---------------------------------------------------------------------------
-- 5. ROLLBACK
-- ---------------------------------------------------------------------------
-- Run the whole block in one transaction. Restores the exact pre-migration
-- definitions captured from supabase/schema.sql and
-- supabase/allow-authorized-writes.sql.
--
-- begin;
--
--   -- 5a. Remove the guard this migration (re)created.
--   drop trigger if exists lsp_guard_profile_role on public.profiles;
--   drop function if exists public.lsp_guard_profile_role();
--
--   -- 5b. Restore the original profiles policies (row-scoped, unchanged shape).
--   drop policy if exists lsp_profiles_update on public.profiles;
--   create policy lsp_profiles_update on public.profiles for update to authenticated
--     using (id = auth.uid() or public.lsp_is_admin())
--     with check (id = auth.uid() or public.lsp_is_admin());
--
--   drop policy if exists lsp_profiles_insert on public.profiles;
--   create policy lsp_profiles_insert on public.profiles for insert to authenticated
--     with check (id = auth.uid());
--
--   -- 5c. Restore the services write policy that was live before this migration.
--   --     Use the schema.sql owner-or-admin form, NOT the permissive
--   --     allow-authorized-writes.sql form: rolling back to `using (true)`
--   --     would reopen the defect. If the permissive form must be restored for
--   --     a compatibility reason, record that decision explicitly.
--   drop policy if exists lsp_services_write on public.services;
--   create policy lsp_services_write on public.services for all to authenticated
--     using (provider_id in (select public.lsp_provider_ids()) or public.lsp_is_admin())
--     with check (provider_id in (select public.lsp_provider_ids()) or public.lsp_is_admin());
--
-- commit;
--
-- NOTE ON PHASE 0: if 2026-11-23-phase0-admin-security.sql was applied before
-- this migration, dropping public.lsp_guard_profile_role() in 5a also removes
-- the Phase 0 B3 protection and re-opens self-promotion. In that case roll back
-- only 5c (the services policy) and keep the guard in place.
-- ===========================================================================
