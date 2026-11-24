-- ===========================================================================
-- LSP Connect — 2026-11-25 — role guard: trusted-session identity
-- ===========================================================================
-- SUPERSEDES the guard function in:
--   * supabase/migrations/2026-11-24-role-guard-and-services-scope.sql (section 1)
--   * supabase/schema.sql (bootstrap copy, also updated in this commit)
--   * 2026-11-23-phase0-admin-security.sql section B3 — a review artifact that
--     was never applied. If it is ever applied, apply this migration AFTER it.
--   Apply order is chronological, so this file runs last and its definition wins.
--
-- ---------------------------------------------------------------------------
-- THE DEFECT THIS FIXES
-- ---------------------------------------------------------------------------
-- The previous guard decided trust from `current_user` alone:
--
--     if current_user = any (array['postgres', ..., 'service_role']) then
--       return new;                       -- trusted
--
-- `current_user` is the EFFECTIVE role, and PostgreSQL changes it for the
-- duration of a SECURITY DEFINER function: inside such a function current_user
-- becomes the function owner. So any SECURITY DEFINER function owned by
-- postgres (or by service_role) that touches public.profiles would be classified
-- as trusted *because of its owner*, no matter who called it. An ordinary
-- customer calling that function through PostgREST /rest/v1/rpc/<name> would
-- therefore pass the gate, and the guard would allow the role change it exists
-- to block. Ownership of a function is a deployment fact, not a statement about
-- who is asking; using it as the trust signal is the design error.
--
-- ---------------------------------------------------------------------------
-- THE CORRECTED MECHANISM: session identity, not effective identity
-- ---------------------------------------------------------------------------
-- PostgreSQL exposes two identity values that differ in exactly the situation
-- that matters:
--
--   session_user  the login role of the connection. SECURITY DEFINER does NOT
--                 change it. Only a superuser can change it (SET SESSION
--                 AUTHORIZATION), and a superuser is already the highest
--                 authority, so it grants nothing extra.
--   current_user  the effective role for the current statement. SECURITY
--                 DEFINER, SET ROLE and PostgREST's per-request SET ROLE all
--                 change it.
--
-- A role change is therefore treated as a database-administration action only
-- when ALL of the following hold:
--
--   1. session_user = current_user
--      No role elevation of any kind is in effect. This is precisely the
--      condition that is false inside a SECURITY DEFINER function called by an
--      application role, so function ownership can no longer buy trust.
--
--   2. current_user is not an API role
--      ('anon','authenticated','authenticator','service_role',
--       'supabase_storage_admin','supabase_auth_admin').
--      Belt and braces: even if one of them were later granted the provisioner
--      role below, or the session identity checks were bypassed, an API role is
--      never an administration session.
--
--   3. The statement did not arrive as an API request.
--      PostgREST sets `request.jwt.claims` and `request.method` inside the
--      request transaction. These are used ONLY in the deny direction: their
--      presence disqualifies the session. Their absence never grants anything,
--      because conditions 1, 2 and 4 are independent and must also hold. This
--      is the opposite of trusting a custom GUC as proof of privilege: a forged
--      or missing GUC cannot create authority, it can only fail to remove it.
--      It also closes the "a definer function does SET SESSION AUTHORIZATION
--      postgres" route, which would otherwise satisfy condition 1.
--
--   4. current_user is a real administration identity:
--      a superuser (rolsuper), or an explicit member of the NOLOGIN role
--      public-facing lsp_role_provisioner. That role is created here, is
--      granted to nobody by default, is never granted to an API role, and
--      membership in it is a deliberate, auditable GRANT — not an accident of
--      who happened to create a function.
--
-- Everything else — including service_role requests, admin users signed in
-- through the app, and any SECURITY DEFINER function regardless of owner — is
-- held to the app rules below. Role values are then immutable for those callers.
--
-- ---------------------------------------------------------------------------
-- HOW SQL EDITOR ADMINISTRATION IS DISTINGUISHED FROM APPLICATION REQUESTS
-- ---------------------------------------------------------------------------
--   SQL Editor / psql as postgres:
--       session_user = postgres, current_user = postgres   -> equal
--       request.jwt.claims / request.method absent          -> not an API call
--       rolsuper = true                                     -> trusted
--     A role change is allowed.
--
--   PostgREST, direct UPDATE as a customer:
--       session_user = authenticator, current_user = authenticated -> unequal
--     Not trusted; app rules apply; role is pinned to its existing value.
--
--   PostgREST, RPC calling a SECURITY DEFINER function owned by postgres:
--       session_user = authenticator, current_user = postgres       -> unequal
--     Not trusted. This is the reported bypass, and it is now closed by
--     condition 1 alone, before ownership is ever consulted.
--
--   PostgREST with the service_role key (direct or via a definer function):
--       current_user = service_role is an API role (condition 2) and the request
--       GUCs are present (condition 3) -> not trusted. Role changes through the
--       service key are therefore refused too. Provisioning is a database
--       administration action, not an HTTP action.
--
--   psql as a member of lsp_role_provisioner with a direct connection:
--       session_user = current_user = that role, no request GUCs, membership
--       -> trusted. This is the supported non-superuser provisioning path.
--
-- ---------------------------------------------------------------------------
-- WHAT IS PRESERVED
-- ---------------------------------------------------------------------------
--   * api.js ensureProfile() inserts {id,email,role,...} and, on duplicate,
--     updates with the same payload including the echoed `role`. INSERT is
--     limited to 'customer'/'provider'; UPDATE pins the role to its current
--     value, so an echoed role is a no-op and the save still succeeds. Nothing
--     in the customer/provider flows changes.
--   * An auth.users signup trigger that inserts a profile (SECURITY DEFINER
--     owned by postgres, session_user = supabase_auth_admin) still works: the
--     INSERT rule only forbids privileged role values, it does not require an
--     administration session.
--   * service_role keeps full non-role write access to profiles for server-side
--     tooling. Only role changes are refused.
--
-- ---------------------------------------------------------------------------
-- ORDERING / DEPENDENCIES
--   * Requires public.profiles, public.lsp_is_admin(), public.lsp_provider_ids()
--     (asserted below; aborts with a clear message when absent).
--   * PostgreSQL 12+. Uses plpgsql, pg_roles, pg_has_role(...,'MEMBER'),
--     current_setting(..., true), to_regclass, to_regprocedure.
--   * Idempotent: safe to re-run. CREATE OR REPLACE / DROP ... IF EXISTS only.
--   * No data change, no DROP TABLE, no policy change, no grant to an API role.
-- ===========================================================================

-- ---------------------------------------------------------------------------
-- 0. Preflight — fail closed, and capture the current definition first.
-- ---------------------------------------------------------------------------
-- Run this BEFORE applying, and keep the output. It is the exact definition the
-- rollback in section 5 restores.
--   select p.oid::regprocedure as signature,
--          pg_get_userbyid(p.proowner) as owner,
--          p.prosecdef as security_definer,
--          p.proconfig as pinned_settings,
--          pg_get_functiondef(p.oid) as definition
--     from pg_proc p join pg_namespace n on n.oid = p.pronamespace
--    where n.nspname = 'public' and p.proname = 'lsp_guard_profile_role';
--
--   select tgname, tgenabled, pg_get_triggerdef(t.oid) as definition
--     from pg_trigger
--    where tgrelid = 'public.profiles'::regclass and tgname = 'lsp_guard_profile_role';

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
  if current_setting('server_version_num')::int < 120000 then
    raise exception 'lsp_preflight: PostgreSQL 12 or newer is required (found %)',
      current_setting('server_version');
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- 1. Provisioning role — an explicit, auditable grant instead of an allowlist.
--
--    NOLOGIN: it can never be used to open a connection.
--    NOINHERIT / NOSUPERUSER / NOBYPASSRLS: it carries no ambient power; it only
--    marks a session as an administration session.
--    Granted to postgres/supabase_admin when they exist, so a superuser session
--    is trusted by name as well as by rolsuper.
--    Never granted to anon/authenticated/authenticator/service_role; any such
--    membership found is revoked here.
--
--    If the applying role lacks CREATEROLE the role is skipped with a notice and
--    the migration continues: the rolsuper branch of the guard still works, so
--    the protection is never weakened by this step failing.
-- ---------------------------------------------------------------------------
do $$
declare
  r text;
begin
  if not exists (select 1 from pg_catalog.pg_roles where rolname = 'lsp_role_provisioner') then
    begin
      create role lsp_role_provisioner
        nologin noinherit nosuperuser nocreatedb nocreaterole noreplication nobypassrls;
      raise notice 'lsp_role_provisioner: created';
    exception
      when insufficient_privilege then
        raise notice 'lsp_role_provisioner: not created (applying role lacks CREATEROLE); superuser sessions can still provision roles';
    end;
  end if;

  if exists (select 1 from pg_catalog.pg_roles where rolname = 'lsp_role_provisioner') then
    foreach r in array array['postgres', 'supabase_admin'] loop
      if exists (select 1 from pg_catalog.pg_roles where rolname = r) then
        execute format('grant lsp_role_provisioner to %I', r);
      end if;
    end loop;

    foreach r in array array['anon', 'authenticated', 'authenticator', 'service_role'] loop
      if exists (select 1 from pg_catalog.pg_roles where rolname = r)
         and pg_catalog.pg_has_role(r, 'lsp_role_provisioner', 'MEMBER') then
        execute format('revoke lsp_role_provisioner from %I', r);
        raise notice 'lsp_role_provisioner: revoked from API role %', r;
      end if;
    end loop;
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- 2. The guard.
--
--    SECURITY INVOKER is mandatory: a SECURITY DEFINER guard would report its own
--    owner as both session_user and current_user and trust every caller.
--    search_path is pinned and every function is schema-qualified.
-- ---------------------------------------------------------------------------
create or replace function public.lsp_guard_profile_role()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog, public
as $guard$
declare
  v_session     text := session_user;   -- login identity; unchanged by SECURITY DEFINER
  v_current     text := current_user;   -- effective identity; becomes the definer's owner
  v_api_request boolean;
  v_is_super    boolean := false;
  v_trusted     boolean := false;
  v_role        text;
begin
  -- (3) API request detection. PostgREST sets these inside the request
  --     transaction. Deny-direction only: presence disqualifies, absence grants
  --     nothing on its own.
  v_api_request :=
        coalesce(current_setting('request.jwt.claims', true), '') <> ''
     or coalesce(current_setting('request.method', true), '') <> '';

  -- (1) + (2) + (4) genuine database-administration session.
  if not v_api_request and v_session = v_current then
    if v_current not in ('anon', 'authenticated', 'authenticator', 'service_role',
                         'supabase_storage_admin', 'supabase_auth_admin') then

      select coalesce(bool_or(r.rolsuper), false)
        into v_is_super
        from pg_catalog.pg_roles r
       where r.rolname = v_current;

      if v_is_super then
        v_trusted := true;
      elsif exists (select 1 from pg_catalog.pg_roles r
                     where r.rolname = 'lsp_role_provisioner') then
        v_trusted := pg_catalog.pg_has_role(v_current, 'lsp_role_provisioner', 'MEMBER');
      end if;
    end if;
  end if;

  -- ---------------------------------------------------------------- trusted --
  if v_trusted then
    if tg_op = 'INSERT' then
      v_role := coalesce(new.role, 'customer');
    else
      v_role := coalesce(new.role, old.role, 'customer');
    end if;

    if v_role not in ('customer', 'provider', 'admin') then
      raise exception 'lsp_role_invalid: % is not a permitted profile role', v_role
        using errcode = '22023';
    end if;

    new.role := v_role;
    return new;
  end if;

  -- ------------------------------------------------------------ app callers --
  -- The PostgREST login role never executes DML itself; seeing it means the
  -- request did not establish a role, so refuse rather than guess.
  if v_current = 'authenticator' then
    raise exception 'lsp_write_denied: the API login role may not write public.profiles'
      using errcode = '42501';
  end if;

  if tg_op = 'INSERT' then
    -- A profile may not be born privileged, whoever is inserting it: this also
    -- covers an auth signup trigger and a SECURITY DEFINER RPC.
    if new.role is null then
      new.role := 'customer';
    end if;
    if new.role not in ('customer', 'provider') then
      raise exception 'lsp_role_escalation_blocked: cannot create a profile with role %', new.role
        using errcode = '42501';
    end if;
    return new;
  end if;

  -- UPDATE: the role is immutable for every non-administration session, so a
  -- SECURITY DEFINER function gains nothing from its owner. The value is pinned
  -- rather than rejected because api.js ensureProfile() echoes `role` on every
  -- profile save; pinning keeps that save working and the attempt is recorded.
  if new.role is distinct from old.role then
    raise log 'lsp_guard_profile_role: blocked role change % -> % for profile % (session_user=%, current_user=%)',
      old.role, new.role, new.id, v_session, v_current;
    new.role := old.role;
  end if;
  return new;
end;
$guard$;

drop trigger if exists lsp_guard_profile_role on public.profiles;
create trigger lsp_guard_profile_role
  before insert or update on public.profiles
  for each row execute function public.lsp_guard_profile_role();

-- ---------------------------------------------------------------------------
-- 3. Reproducible verification cases. Nothing here was executed against any
--    database; run them by hand in the Supabase SQL Editor.
--
--    Each case is transactional and ends in ROLLBACK. Replace <customer-uuid> /
--    <provider-uuid> with real rows from public.profiles.
--
--    Why SET SESSION AUTHORIZATION and not SET ROLE: a SQL Editor session runs
--    as postgres, so SET ROLE alone leaves session_user = postgres. A SECURITY
--    DEFINER call would then see session_user = current_user = postgres and look
--    exactly like genuine administration. SET SESSION AUTHORIZATION authenticated
--    reproduces the PostgREST identity pair (session_user = authenticator,
--    current_user = authenticated) and is what makes case D meaningful.
-- ---------------------------------------------------------------------------

-- Case A — direct customer self-promotion. Expect: UPDATE 1, role still 'customer'.
-- begin;
--   select set_config('request.jwt.claims',
--     json_build_object('sub','<customer-uuid>','role','authenticated')::text, true);
--   set session authorization authenticated;
--   update public.profiles set role = 'admin' where id = '<customer-uuid>';
--   select role from public.profiles where id = '<customer-uuid>';
-- rollback;

-- Case B — direct provider self-promotion. Expect: UPDATE 1, role still 'provider'.
-- begin;
--   select set_config('request.jwt.claims',
--     json_build_object('sub','<provider-uuid>','role','authenticated')::text, true);
--   set session authorization authenticated;
--   update public.profiles set role = 'admin' where id = '<provider-uuid>';
--   select role from public.profiles where id = '<provider-uuid>';
-- rollback;

-- Case C — UPSERT self-promotion. Expect: ERROR 42501 lsp_role_escalation_blocked.
--   The BEFORE INSERT trigger fires before conflict resolution, so the privileged
--   value is refused before the UPDATE branch is ever reached.
-- begin;
--   select set_config('request.jwt.claims',
--     json_build_object('sub','<customer-uuid>','role','authenticated')::text, true);
--   set session authorization authenticated;
--   insert into public.profiles (id, email, role)
--   values ('<customer-uuid>', 'probe@example.test', 'admin')
--   on conflict (id) do update set role = excluded.role;
-- rollback;

-- Case D — self-promotion through a SECURITY DEFINER RPC owned by postgres.
--   Expect: role unchanged. Inside the function current_user is postgres while
--   session_user stays authenticated, so the guard classifies it as an app
--   caller and pins the role; the function's owner buys nothing.
-- begin;
--   create function public.lsp_probe_definer_promote(p_id uuid)
--   returns void language plpgsql security definer
--   set search_path = pg_catalog, public as $probe$
--   begin
--     update public.profiles set role = 'admin' where id = p_id;
--   end
--   $probe$;
--   grant execute on function public.lsp_probe_definer_promote(uuid) to authenticated;
--
--   select set_config('request.jwt.claims',
--     json_build_object('sub','<customer-uuid>','role','authenticated')::text, true);
--   set session authorization authenticated;
--   select public.lsp_probe_definer_promote('<customer-uuid>');
--   select role from public.profiles where id = '<customer-uuid>';   -- 'customer'
-- rollback;   -- also removes the probe function

-- Case D2 — the same function with the same owner, but the session identity
--   check removed. Included as a negative control: it shows the outcome the
--   previous guard produced, so the difference is attributable to this fix.
--   (Do not run against production.)

-- Case E — legitimate ordinary profile update. Expect: UPDATE 1, fields saved,
--   role still 'customer' (ensureProfile's echoed role is a no-op, not an error).
-- begin;
--   select set_config('request.jwt.claims',
--     json_build_object('sub','<customer-uuid>','role','authenticated')::text, true);
--   set session authorization authenticated;
--   update public.profiles
--      set full_name = 'Probe Name', phone = '0000000000', role = 'customer'
--    where id = '<customer-uuid>';
--   select full_name, role from public.profiles where id = '<customer-uuid>';
-- rollback;

-- Case F — trusted SQL Editor provisioning. Expect: UPDATE 1, role 'admin',
--   then ROLLBACK so the test leaves no administrator behind.
-- begin;
--   select session_user, current_user;               -- both 'postgres'
--   update public.profiles set role = 'admin' where id = '<customer-uuid>';
--   select role from public.profiles where id = '<customer-uuid>';   -- 'admin'
-- rollback;

-- Case G — service_role via the API must not change a role. Expect: UPDATE 1,
--   role unchanged; an INSERT with role 'admin' raises 42501.
-- begin;
--   select set_config('request.jwt.claims',
--     json_build_object('role','service_role')::text, true);
--   set session authorization service_role;
--   update public.profiles set role = 'admin' where id = '<customer-uuid>';
--   select role from public.profiles where id = '<customer-uuid>';   -- unchanged
-- rollback;

-- ---------------------------------------------------------------------------
-- 4. Post-apply inspection (read-only).
-- ---------------------------------------------------------------------------

-- 4a. The guard must be a BEFORE row trigger, enabled, and SECURITY INVOKER.
--   select t.tgname, t.tgenabled, t.tgtype,
--          p.prosecdef as security_definer, p.proconfig as pinned_settings
--     from pg_trigger t
--     join pg_proc p on p.oid = t.tgfoid
--    where t.tgrelid = 'public.profiles'::regclass
--      and t.tgname = 'lsp_guard_profile_role';
--   expect: tgenabled = 'O', security_definer = false, pinned_settings includes search_path

-- 4b. Every SECURITY DEFINER function in public, with its owner, its pinned
--     settings and whether an application role can call it. Nothing in this
--     schema needs a definer function that writes profiles.role; a row here that
--     does is a design decision to review, not a privilege the guard grants.
--   select p.proname,
--          pg_get_userbyid(p.proowner) as owner,
--          p.prosecdef as security_definer,
--          p.proconfig as pinned_settings,
--          has_function_privilege('authenticated', p.oid, 'EXECUTE') as callable_by_authenticated
--     from pg_proc p
--     join pg_namespace n on n.oid = p.pronamespace
--    where n.nspname = 'public' and p.prokind = 'f'
--    order by p.prosecdef desc, p.proname;

-- 4c. Heuristic: definer functions callable by authenticated whose body mentions
--     a write to public.profiles. Review each hit; the guard pins role for all of
--     them, but a function that disables the trigger or impersonates a superuser
--     is privileged code and must be treated as such (see the limitation below).
--   select p.oid::regprocedure as signature, pg_get_userbyid(p.proowner) as owner
--     from pg_proc p
--     join pg_namespace n on n.oid = p.pronamespace
--    where n.nspname = 'public' and p.prosecdef
--      and p.prosrc ~* '(insert\s+into|update|delete\s+from)\s+public\.profiles'
--      and has_function_privilege('authenticated', p.oid, 'EXECUTE');

-- 4d. Provisioner membership must contain no API role.
--   select r.rolname, m.rolname as member
--     from pg_auth_members am
--     join pg_roles r on r.oid = am.roleid
--     join pg_roles m on m.oid = am.member
--    where r.rolname = 'lsp_role_provisioner';
--   expect: only postgres / supabase_admin, or no rows

-- 4e. Behavioural summary, one row per scenario, all rolled back. Run 3A-3G.

-- ---------------------------------------------------------------------------
-- 5. ROLLBACK
-- ---------------------------------------------------------------------------
-- Preferred rollback: keep the hardened guard and remove only the provisioning
-- role. A role change is then possible from a superuser session only, which is
-- still correct and still blocks every application path.
--
--   begin;
--     revoke lsp_role_provisioner from postgres;        -- if it was granted
--     revoke lsp_role_provisioner from supabase_admin;  -- if it was granted
--     drop role if exists lsp_role_provisioner;
--   commit;
--
-- Full revert to the pre-migration definition. This restores the current_user
-- allowlist and therefore RE-OPENS the SECURITY DEFINER ownership bypass. Only
-- use it when something outside this migration depends on the old behaviour,
-- and record why.
--
--   begin;
--     create or replace function public.lsp_guard_profile_role()
--     returns trigger language plpgsql security invoker
--     set search_path = pg_catalog, public as $$
--     declare
--       api_role text := current_user;
--       trusted  constant text[] := array['postgres','supabase_admin','supabase_storage_admin','supabase_auth_admin','service_role'];
--     begin
--       if api_role = any (trusted) then
--         return new;
--       end if;
--       if api_role <> 'authenticated' then
--         raise exception 'lsp_write_denied: role % may not write public.profiles', api_role
--           using errcode = '42501';
--       end if;
--       if (select auth.uid()) is null then
--         raise exception 'lsp_write_denied: authenticated session without a subject'
--           using errcode = '42501';
--       end if;
--       if tg_op = 'INSERT' then
--         if new.role is null then
--           new.role := 'customer';
--         end if;
--         if new.role not in ('customer','provider') then
--           raise exception 'lsp_role_escalation_blocked: cannot create a profile with role %', new.role
--             using errcode = '42501';
--         end if;
--         return new;
--       end if;
--       if new.role is distinct from old.role then
--         new.role := old.role;
--       end if;
--       return new;
--     end $$;
--
--     drop trigger if exists lsp_guard_profile_role on public.profiles;
--     create trigger lsp_guard_profile_role before insert or update on public.profiles
--       for each row execute function public.lsp_guard_profile_role();
--   commit;
--
-- Dropping the guard entirely (no guard at all) is NOT a supported rollback: it
-- returns public.profiles to the state where any signed-in user can PATCH their
-- own role to 'admin'.
--
-- ---------------------------------------------------------------------------
-- 6. RESIDUAL LIMITATION — stated, not hidden
-- ---------------------------------------------------------------------------
-- This guard decides authority from values PostgreSQL itself sets (session_user,
-- current_user, request GUCs written by PostgREST before the transaction, role
-- attributes). None of them is reachable from the browser, the JWT payload, an
-- HTTP header, a custom GUC set by a client, localStorage or the frontend role
-- checks. That is the whole guarantee, and it is enough for requirement 1 and 2:
-- a function that merely inherits its owner's privileges cannot change a role.
--
-- It is not a defence against code that already runs as a database administrator.
-- A function owned by postgres can, by design, `alter table public.profiles
-- disable trigger lsp_guard_profile_role`, `drop trigger`, or `set session
-- authorization postgres`. No trigger can prevent that: a BEFORE trigger cannot
-- outrank the role that owns the table and the trigger. The mitigation is
-- procedural, not SQL — section 4b/4c exist so that the set of SECURITY DEFINER
-- functions touching profiles stays visible and empty, and provisioning stays a
-- manual SQL Editor action. Claiming otherwise would be a false guarantee.
-- ===========================================================================
