-- ============================================================================
-- LSP CONNECT — PHASE 0: ADMIN SECURITY FOUNDATION
-- STATUS: PROPOSAL ONLY — REVISION 7 — NOT APPLIED — NOTHING EXECUTED
--
-- ----------------------------------------------------------------------------
-- WHAT WAS ACTUALLY IN THE REPOSITORY WHEN REVISION 6 STARTED
-- (verified from Git, not recalled from a summary)
--
-- Seven commits touch this file: 5a00ff5, 5fb8086, bc67538, 0dca239,
-- 6a1a191 (revision 5), 4b13021 (revision 5 edit), e69b7dc.
--
--   1. Revisions 3, 4 and 5 of this file contain Sections A, B, C and D ONLY.
--      No committed revision contains a SECTION S. The strings 'SECTION S',
--      'S1.', 'S5.' and 'S13.' appear in none of the seven blobs (checked with
--      git grep across git rev-list --all). The test plan that the revision 5
--      header refers to ("see test plan", items 6-8) and that A12 refers to
--      ("the S13 authorization tests") was delivered in review chat and never
--      committed to this repository.
--
--   2. THEREFORE THE REVISION 5 SECTION S TEXT IS NOT RECOVERABLE FROM THIS
--      REPOSITORY. That is the single item Revision 6 could not recover
--      verbatim, and it is stated here instead of being quietly reinvented.
--      Section S below is rebuilt against the CURRENT Sections B and C:
--        - S5 is written to the five requirements in the revision 6 review;
--        - S1-S4, S6-S9, S12 and S13 are reconstructed from what this file
--          already asserts (A12 write matrix, B4.4/B4.5 guards, B6 services
--          note) and are tagged [RECONSTRUCTED] so they are never mistaken
--          for recovered revision 5 text.
--
--   3. The working tree already carried a file labelled "Revision 6"
--      (commit e69b7dc). It was read in full BEFORE any edit. It already
--      contained the four Section C spelling fixes and a restructured D.2,
--      but it had NO Section S and NO limitations list — which is precisely
--      what made it incomplete. All of its content is carried forward here.
--      Nothing was overwritten, discarded or re-derived from memory.
--
-- ----------------------------------------------------------------------------
-- REVISION 7 CHANGES (this review round)
--
--   1. ROLLBACK IS COMPLETE, OR THE MIGRATION REFUSES TO RUN (item 1).
--      Revision 6 assumed every object it touched was new, so D.1 could only
--      DROP. A pre-existing trigger, guard function or constraint was therefore
--      destroyed with no way back. Revision 7 adds:
--        A0c  trigger capture now records tgenabled and emits a ready-to-run
--             restore_statement (definition + enabled state).
--        A0g  constraint capture: definition, convalidated, deferrability and a
--             ready-to-run restore_statement. pg_get_constraintdef emits
--             NOT VALID, so validation state travels with the definition.
--        A0h  CONFLICT REGISTER: for each of the 11 created objects and the 3
--             replaced helpers, whether it pre-exists and whether D.1 must DROP
--             it or RESTORE it. This is the list D.1 is driven by.
--        B0b  FAIL-CLOSED PREFLIGHT: aborts the transaction before any object is
--             modified when a pre-existing trigger, guard function, constraint
--             or helper overload would be overwritten. A deliberate re-run needs
--             an explicit opt-in setting.
--        D.1  restructured: D.1.1 drops only what B created, D.1.2 restores the
--             three replaced helpers, D.1.3 restores pre-existing guard
--             functions, triggers and the constraint, D.1.4 verifies before
--             commit.
--
--   2. ROLE MEMBERSHIP IS TESTED CORRECTLY (item 2 — A4c, B2.1).
--      Revision 6 gated ownership reassignment on pg_has_role(..., 'USAGE').
--      'USAGE' means the role's privileges are available WITHOUT SET ROLE, which
--      an inherited membership satisfies even when SET ROLE is impossible: the
--      gate could pass and the ALTER then fail. Revision 7 reports version() and
--      server_version_num, uses 'SET' on PostgreSQL 16+ (which also honours a
--      membership granted WITHOUT SET) and 'MEMBER' below 16 (where no SET
--      option exists), treats superuser and current_user = owner as permitted,
--      and re-reads ownership after the ALTER to prove it took effect.
--
--   3. A10c SURVIVES A MISSING FUNCTION (item 3).
--      has_function_privilege(<text signature>) raises 42883 when the function
--      does not exist, which aborted the whole diagnostic batch on a database
--      where Section B had not run yet. A10c now resolves the name with
--      to_regprocedure() first and returns NULL for the privilege when the
--      function is absent. C5 gets the same treatment.
--
--   4. provider_profiles RLS DEPENDENCY MADE EXPLICIT (B2.3, C9).
--      The provider_profiles policies only constrain anything while RLS is
--      ENABLED there, and lsp_provider_ids() — which lsp_documents_owner calls —
--      can only bypass RLS if its owner is the provider_profiles owner and FORCE
--      RLS is off. Neither was checked: a wrong state is silent at apply time and
--      denies every provider access to their own documents later. B2.3 fails
--      closed on either condition; C9 reports the state read-only.
--
--   5. STILL NOT EXECUTED. No statement below has been run against any database.
--      Section S remains DESIGNED, NOT EXECUTED.
--
-- ----------------------------------------------------------------------------
-- REVISION 6 CHANGES (previous round — retained for provenance)
--
--   A. SECTION C — SQL CORRECTNESS
--      1. Every aggregate is count(*). There is no zero-argument count() call
--         anywhere in the file (C2, C4, C7, C8; A3, A11b already used count(*)).
--      2. scheman -> schemaname (C3).
--      3. acl_default -> acldefault (C5). The correct spelling has no
--         underscore; the revision 5 text also cast grantee 0 to regrole,
--         which raises for PUBLIC, so PUBLIC is labelled with a CASE instead.
--      4. coallesce -> coalesce (C7, both queries; also A3, A11b, C4).
--      5. Every statement in Sections A-D was re-read for valid PostgreSQL.
--         Two further defects were found and fixed while doing that:
--           - B2.1 put %I inside a RAISE format string. RAISE supports only %
--             and %%; %I is a format() specifier. The message would have
--             rendered "alter function public.<name>I() ..." — a wrong
--             instruction in the one error path an operator must act on.
--             It now passes format() as an argument.
--           - C5's grantee cast (see 3) would have raised 42704/42846.
--
--   B. S5 — TRIGGER ATTRIBUTION, REBUILT (Section S)
--      The untrusted role gets real table privileges, an explicit permissive
--      RLS policy, and a POSITIVE CONTROL (the identical statement succeeds
--      with the guard trigger disabled). The 42501 is then asserted to carry
--      the trigger's exact message, which rules out both the ACL message and
--      the RLS message. A trusted-role control proves the statement is valid.
--      Everything runs in one transaction that ends in ROLLBACK, with
--      post-rollback assertions for the role, the policy, the grants and the
--      trigger state.
--
--   C. ROLLBACK MAP (D.2) — restructured into a table that separates
--      BLOCKED ATTEMPTS (never written to disk, nothing to restore) from
--      PERSISTED CHANGES (written, not reversible, logged only), and states
--      for each replaced policy/function/owner/grant which capture query
--      restores it (A0b, A0, A0e, A0f).
--
--   D. C8 — validated instead of asserted: per-kind counts plus a ROLLUP total,
--      and C8c diffs the hard-coded expected set of ELEVEN objects against the
--      catalogue in both directions, so an object that Section B creates but
--      the inventory forgets is reported as MISSING instead of being silently
--      absent from a total.
--
--   E. LIMITATIONS — the four known exposures are preserved explicitly and
--      verbatim in intent at the end of the file, each with why this migration
--      does not fix it.
--
--   F. Nothing executed, no authentication setting changed, no account created,
--      no frontend file touched, nothing deployed.
--
-- ----------------------------------------------------------------------------
-- RUN ORDER: A (capture + inspect, read-only) -> B (one transaction) -> C
--            (verify) -> S (tests, each self-contained and rolled back).
--            D only if a regression appears. Run in the Supabase SQL Editor as
--            the project owner. Never from a browser, never with the anon key.
--
-- SAFETY: idempotent, additive, fail closed (every gate raises, so a partial
--         security migration is impossible), no drops of tables/columns/data,
--         no deletes, no RLS weakening, no authentication change.
-- ============================================================================


-- ============================================================================
-- SECTION A — CAPTURE AND INSPECT (READ-ONLY)
-- ============================================================================

-- A0. CAPTURE BEFORE MIGRATING — FUNCTIONS.
--     Save this output. Section D restores only what is recorded here: body,
--     owner, ACL, configuration flags and the SECURITY DEFINER bit.
--     A helper that returns no row here did not exist before this migration.
select p.proname,
       pg_get_userbyid(p.proowner)          as owner,
       p.prosecdef                          as security_definer,
       p.proconfig                          as pinned_settings,
       p.proacl                             as acl,
       pg_get_functiondef(p.oid)            as definition
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public' and p.proname like 'lsp\_%'
order by p.proname;

-- A0b. CAPTURE BEFORE MIGRATING — POLICIES. permissive, roles, cmd, qual and
--      with_check together are everything needed to recreate a policy exactly.
select tablename, policyname, permissive, roles, cmd, qual, with_check
from pg_policies
where schemaname = 'public' and policyname like 'lsp\_%'
order by tablename, policyname;

-- A0c. CAPTURE BEFORE MIGRATING — TRIGGERS on the three tables this migration
--      touches. tgenabled is captured because enabled state is STATE, not part of
--      the definition: 'O' enabled, 'D' disabled, 'R' replica only, 'A' always.
--      restore_statement rebuilds the trigger from its definition AND reapplies
--      the enabled state, so D.1 R6 is mechanical instead of remembered.
--      B0b aborts if any of the three guard names already exists, so this capture
--      is only needed when you override that gate deliberately.
select c.relname as table_name,
       t.tgname,
       t.tgenabled,
       case t.tgenabled when 'O' then 'enabled'
                        when 'D' then 'disabled'
                        when 'R' then 'replica only'
                        when 'A' then 'always' end as enabled_state,
       pg_get_triggerdef(t.oid) as definition,
       pg_get_triggerdef(t.oid)
         || case t.tgenabled
              when 'D' then format('; alter table %I.%I disable trigger %I;', n.nspname, c.relname, t.tgname)
              when 'R' then format('; alter table %I.%I enable replica trigger %I;', n.nspname, c.relname, t.tgname)
              when 'A' then format('; alter table %I.%I enable always trigger %I;', n.nspname, c.relname, t.tgname)
              else '' end as restore_statement
from pg_trigger t
join pg_class c on c.oid = t.tgrelid
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and not t.tgisinternal
  and c.relname in ('profiles','provider_profiles','provider_documents')
order by c.relname, t.tgname;

-- A0d. CAPTURE BEFORE MIGRATING — table privileges, PUBLIC and inheritance
--      included (has_table_privilege resolves both).
select c.relname,
       has_table_privilege('anon',          c.oid, 'SELECT') as anon_select,
       has_table_privilege('anon',          c.oid, 'INSERT') as anon_insert,
       has_table_privilege('authenticated', c.oid, 'INSERT') as auth_insert,
       has_table_privilege('authenticated', c.oid, 'UPDATE') as auth_update,
       has_table_privilege('authenticated', c.oid, 'DELETE') as auth_delete
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r'
order by c.relname;

-- A0e. CAPTURE BEFORE MIGRATING — helper ACLs as READY-TO-RUN restore text.
--      B2.2 revokes and re-grants EXECUTE, so the previous ACL must be
--      reproducible, not merely visible. A0's acl column is the record; this
--      query renders it as statements for D.1 R4.
--      Restoring exactly means: revoke everything from PUBLIC first (PostgreSQL
--      grants EXECUTE to PUBLIC by default), then replay the grants below.
select p.proname,
       case when a.grantee = 0 then 'PUBLIC'
            else pg_get_userbyid(a.grantee) end as grantee,
       a.privilege_type,
       format('grant %s on function public.%I() to %s%s;',
              a.privilege_type,
              p.proname,
              case when a.grantee = 0 then 'public'
                   else quote_ident(pg_get_userbyid(a.grantee)) end,
              case when a.is_grantable then ' with grant option' else '' end)
         as restore_statement
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
cross join lateral aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
where n.nspname = 'public' and p.proname like 'lsp\_%'
order by 1, 2;

-- A0f. CAPTURE BEFORE MIGRATING — policies as READY-TO-RUN restore text.
--      A0b is the record; this renders the same rows as CREATE POLICY
--      statements so D.1 R1 is mechanical and cannot drift from the capture.
select format('create policy %I on public.%I as %s for %s to %s%s%s;',
              policyname, tablename, permissive, cmd,
              array_to_string(roles, ', '),
              case when qual       is null then '' else ' using (' || qual || ')' end,
              case when with_check is null then '' else ' with check (' || with_check || ')' end)
         as restore_statement
from pg_policies
where schemaname = 'public' and policyname like 'lsp\_%'
order by tablename, policyname;

-- A0g. CAPTURE BEFORE MIGRATING — CONSTRAINTS on public.profiles.
--      B1 adds profiles_role_allowed only when the name is absent, so a
--      pre-existing constraint of that name is left untouched by B and D.1 must
--      know whether it is allowed to drop it. convalidated matters: B creates it
--      NOT VALID, so a VALIDATED constraint of that name came from somewhere else
--      and restoring it as NOT VALID would silently weaken it.
--      pg_get_constraintdef emits NOT VALID for an unvalidated constraint, so
--      restore_statement reproduces the definition AND the validation state.
select c.conname,
       c.contype,
       c.convalidated,
       c.condeferrable,
       c.condeferred,
       c.conkey,
       pg_get_constraintdef(c.oid) as definition,
       format('alter table public.profiles add constraint %I %s;',
              c.conname, pg_get_constraintdef(c.oid)) as restore_statement
from pg_constraint c
where c.conrelid = 'public.profiles'::regclass
order by c.conname;

-- A0h. CONFLICT REGISTER — the exact list D.1 is driven by.
--      One row per object B creates (11) and per helper B replaces (3).
--        scope         'created'  = B should create it
--                      'replaced' = it exists by design and B overwrites it
--        pre_existing  is it already in the catalogue?
--        rollback_action  what D.1 must do about it
--      Read this before opening D.1. A pre-existing object that is not identical
--      to what B installs is a conflict, and B0b aborts on it unless you opt in
--      deliberately. Every row marked RESTORE needs its A0/A0c/A0g output saved
--      before B runs.
with expected(scope, kind, name, on_object) as (
  values
    ('created',  'trigger',         'lsp_guard_profile_role',          'profiles'),
    ('created',  'trigger',         'lsp_guard_provider_verification', 'provider_profiles'),
    ('created',  'trigger',         'lsp_guard_document_status',       'provider_documents'),
    ('created',  'guard function',  'lsp_guard_profile_role',          '(function)'),
    ('created',  'guard function',  'lsp_guard_provider_verification', '(function)'),
    ('created',  'guard function',  'lsp_guard_document_status',       '(function)'),
    ('created',  'policy',          'lsp_providers_insert',            'provider_profiles'),
    ('created',  'policy',          'lsp_providers_update',            'provider_profiles'),
    ('created',  'policy',          'lsp_profiles_insert',             'profiles'),
    ('created',  'policy',          'lsp_documents_owner',             'provider_documents'),
    ('created',  'constraint',      'profiles_role_allowed',           'profiles'),
    ('replaced', 'helper function', 'lsp_role',                        '(function)'),
    ('replaced', 'helper function', 'lsp_is_admin',                    '(function)'),
    ('replaced', 'helper function', 'lsp_provider_ids',                '(function)')
),
present(kind, name, on_object) as (
  select 'trigger', t.tgname, c.relname
  from pg_trigger t
  join pg_class c on c.oid = t.tgrelid
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and not t.tgisinternal
  union all
  select 'guard function', p.proname, '(function)'
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public' and pg_get_function_identity_arguments(p.oid) = ''
  union all
  select 'helper function', p.proname, '(function)'
  from pg_proc p join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public' and pg_get_function_identity_arguments(p.oid) = ''
  union all
  select 'policy', policyname, tablename
  from pg_policies where schemaname = 'public'
  union all
  select 'constraint', conname, 'profiles'
  from pg_constraint where conrelid = 'public.profiles'::regclass
)
select e.scope, e.kind, e.name, e.on_object,
       (p.name is not null) as pre_existing,
       case when p.name is not null then 'RESTORE (D.1.3) — do NOT drop'
            else 'DROP (D.1.1) — created by B' end as rollback_action
from expected e
left join present p
  on p.kind = e.kind and p.name = e.name and p.on_object = e.on_object
order by e.scope, e.kind, e.name;

-- A1. Every policy on the public schema. Non-lsp_* rows are outside this
--     migration and must be reviewed manually.
select tablename, policyname, cmd, roles, qual, with_check
from pg_policies where schemaname = 'public' order by tablename, policyname;

-- A2. relforcerowsecurity MUST be false on public.profiles, otherwise B2.1 aborts.
select c.relname, c.relrowsecurity as rls_enabled, c.relforcerowsecurity as rls_forced
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r' order by c.relname;

-- A3. Role distribution and the NULL/invalid totals.
select coalesce(role, '(null)') as role, count(*) as accounts
from public.profiles group by role order by accounts desc;

select count(*) as total_profiles,
       count(*) filter (where role is null) as null_roles,
       count(*) filter (where role not in ('customer','provider','admin')) as invalid_roles
from public.profiles;

-- A4. Helpers: owner, SECURITY DEFINER flag, pinned settings.
select p.proname, p.proowner::regrole as owner, p.prosecdef as security_definer,
       p.proconfig as pinned_settings
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public' and p.proname like 'lsp\_%' order by p.proname;

-- A4b. The role B2.1 will assign: the owner of public.profiles.
select c.relname, r.rolname as table_owner
from pg_class c join pg_roles r on r.oid = c.relowner
where c.oid = 'public.profiles'::regclass;

-- A4c. WHO IS EXECUTING THIS SCRIPT, ON WHICH SERVER, AND CAN IT REASSIGN
--      OWNERSHIP? Ownership reassignment (B2.1) needs the ability to SET ROLE to
--      the new owner. Revision 6 tested pg_has_role(..., 'USAGE'), which is a
--      DIFFERENT privilege: 'USAGE' means the role's privileges are available
--      WITHOUT SET ROLE, so an inherited membership satisfies it even when
--      SET ROLE is impossible — the gate could pass and the ALTER then fail.
--      Correct, version-compatible test:
--        PostgreSQL 16+   pg_has_role(..., 'SET')    — also honours a membership
--                                                      granted WITHOUT SET
--        PostgreSQL < 16  pg_has_role(..., 'MEMBER') — no SET option exists, so
--                                                      membership IS the capability
--      A superuser can always SET ROLE to any role, and a session that already IS
--      the owner needs no switch, so both count as permitted.
--      Expect current_user = postgres and can_reassign_helper_owner = true.
select version() as server_version,
       current_setting('server_version_num')::int as server_version_num,
       current_user as executing_role,
       session_user as login_role,
       (select r.rolsuper from pg_roles r where r.rolname = current_user) as executing_is_superuser,
       (select r.rolcreaterole from pg_roles r where r.rolname = current_user) as executing_can_create_role,
       o.profiles_owner,
       o.provider_profiles_owner,
       o.provider_documents_owner,
       case when current_setting('server_version_num')::int >= 160000
            then 'SET' else 'MEMBER' end as membership_check_used,
       case when current_setting('server_version_num')::int >= 160000
            then pg_has_role(current_user, o.profiles_owner, 'SET')
            else pg_has_role(current_user, o.profiles_owner, 'MEMBER') end as can_set_role_to_profiles_owner,
       pg_has_role(current_user, o.profiles_owner, 'USAGE') as usage_privilege_not_sufficient,
       (current_user = o.profiles_owner
        or coalesce((select r.rolsuper from pg_roles r where r.rolname = current_user), false)
        or case when current_setting('server_version_num')::int >= 160000
                then pg_has_role(current_user, o.profiles_owner, 'SET')
                else pg_has_role(current_user, o.profiles_owner, 'MEMBER') end
       ) as can_reassign_helper_owner
from (
  select (select r.rolname from pg_class c join pg_roles r on r.oid = c.relowner
           where c.oid = 'public.profiles'::regclass) as profiles_owner,
         (select r.rolname from pg_class c join pg_roles r on r.oid = c.relowner
           where c.oid = to_regclass('public.provider_profiles')) as provider_profiles_owner,
         (select r.rolname from pg_class c join pg_roles r on r.oid = c.relowner
           where c.oid = to_regclass('public.provider_documents')) as provider_documents_owner
) o;

-- A5. Column privileges on profiles — if UPDATE on `role` appears, escalation is reachable.
select grantee, privilege_type, column_name
from information_schema.column_privileges
where table_schema = 'public' and table_name = 'profiles'
  and grantee in ('anon','authenticated')
order by grantee, privilege_type, column_name;

-- A6. Existing non-internal triggers across the public schema.
select c.relname as table_name, t.tgname, pg_get_triggerdef(t.oid) as definition
from pg_trigger t join pg_class c on c.oid = t.tgrelid
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and not t.tgisinternal order by c.relname, t.tgname;

-- A7. Provider INSERT policy. Expect lsp_providers_insert keyed on user_id.
--     No row => provider registration is denied by RLS and B4.0 is required.
select policyname, cmd, roles, qual, with_check
from pg_policies where schemaname = 'public' and tablename = 'provider_profiles'
order by policyname;

-- A8. Services policy. Expect the permissive FOR ALL (using true / check true).
select policyname, cmd, roles, qual, with_check
from pg_policies where schemaname = 'public' and tablename = 'services'
order by policyname;

-- A9. Legacy NULL/invalid roles. REPORTED ONLY — never rewritten by this migration.
select id, email, role from public.profiles
where role is null or role not in ('customer','provider','admin')
order by role nulls first, email;

-- A10b. Any non-SELECT policy whose roles include anon or PUBLIC. A row here means
--       an unauthenticated session can reach a write path.
select tablename, policyname, cmd, roles from pg_policies
where schemaname = 'public' and cmd <> 'SELECT'
  and (roles::text like '%anon%' or roles::text = '{public}')
order by tablename, policyname;

-- A10c. Column-level probes on profiles (PUBLIC- and inheritance-aware).
--       has_function_privilege() given a TEXT signature resolves the name and
--       raises 42883 when the function does not exist — which aborted this whole
--       diagnostic batch on any database where Section B had not run yet.
--       to_regprocedure() resolves the same name to NULL instead of raising, so
--       existence is tested first and the privilege probe is skipped when absent:
--       the column reads as NULL ("not applicable yet"), never as an error and
--       never as false ("exists but denied").
select has_table_privilege('anon','public.profiles','INSERT') as anon_insert,
       has_table_privilege('anon','public.profiles','UPDATE') as anon_update,
       has_table_privilege('anon','public.profiles','DELETE') as anon_delete,
       has_column_privilege('anon','public.profiles','role','UPDATE') as anon_update_role,
       has_column_privilege('authenticated','public.profiles','role','UPDATE') as auth_update_role,
       to_regprocedure('public.lsp_is_admin()') is not null as lsp_is_admin_exists,
       case when to_regprocedure('public.lsp_is_admin()') is null then null
            else has_function_privilege('anon', to_regprocedure('public.lsp_is_admin()'), 'EXECUTE')
       end as anon_exec_is_admin,
       case when to_regprocedure('public.lsp_is_admin()') is null then null
            else has_function_privilege('authenticated', to_regprocedure('public.lsp_is_admin()'), 'EXECUTE')
       end as auth_exec_is_admin,
       to_regprocedure('public.lsp_role()') is not null as lsp_role_exists,
       to_regprocedure('public.lsp_provider_ids()') is not null as lsp_provider_ids_exists;
-- expect BEFORE B: lsp_is_admin_exists = false, both exec columns NULL.
-- expect AFTER B:  lsp_is_admin_exists = true, anon_exec_is_admin = false,
--                  auth_exec_is_admin = true.

-- A11. Documents/skills policies and the document status distribution.
select tablename, policyname, cmd, roles, qual, with_check from pg_policies
where schemaname = 'public' and tablename in ('provider_documents','provider_skills')
order by tablename, policyname;

-- A11b. The real columns of provider_documents. B4.5 diffs the whole row as jsonb
--       and excludes only 'status' and 'updated_at'. The live table created by
--       allow-authorized-writes.sql has id, provider_id, document_type, file_url,
--       status, created_at — no updated_at, so removing that key is a no-op.
select column_name, data_type, is_nullable, column_default
from information_schema.columns
where table_schema = 'public' and table_name = 'provider_documents'
order by ordinal_position;

select coalesce(status,'(null)') as status, count(*) as documents
from public.provider_documents group by status order by documents desc;

-- A12. The write matrix per table — the ground truth for the S13 authorization
--      tests. Read this before interpreting any S13 result.
select tablename, policyname, cmd, roles
from pg_policies
where schemaname = 'public' and cmd in ('INSERT','UPDATE','ALL','DELETE')
order by tablename, policyname;


-- ============================================================================
-- SECTION B — MIGRATION (one transaction; any failure rolls back everything)
-- ============================================================================

begin;

-- B0. OBJECT INVENTORY — everything this migration creates, and therefore
--     everything Section D must undo. C8 re-derives this from the catalogue and
--     C8c diffs it in both directions.
--       CREATED  3 triggers   lsp_guard_profile_role         on public.profiles
--                             lsp_guard_provider_verification on public.provider_profiles
--                             lsp_guard_document_status       on public.provider_documents
--       CREATED  3 functions  the three guard functions above
--       CREATED  4 policies   lsp_providers_insert, lsp_providers_update,
--                             lsp_profiles_insert, lsp_documents_owner
--       CREATED  1 constraint profiles_role_allowed
--                             = 11 objects present after B (C8/C8c validate this)
--       REPLACED 3 functions  lsp_role, lsp_is_admin, lsp_provider_ids
--                             (may pre-exist; A0 captured their previous bodies)
--       CHANGED  n ACLs       EXECUTE on the 3 helpers (B2.2; A0e captured the
--                             previous ACL as restore text)
--       CHANGED  n owners     the 3 helpers, only if they were not already
--                             owned by the profiles owner (B2.1; A0 captured)
--     The 3 replaced helpers are deliberately NOT part of the 11 and are NOT
--     dropped by D.1 — many policies call them. C8b reports them separately.
--
--     "Created" here means PRESENT AFTER B, not necessarily new: the four
--     policies and the constraint are dropped-and-recreated only where they
--     already existed (A7 expects lsp_providers_insert to be live, A0b records
--     all of them). The six genuinely new objects are the 3 triggers and the
--     3 guard functions; C8c names all eleven explicitly.

-- B0b. CONFLICT PREFLIGHT — FAIL CLOSED BEFORE ANY OBJECT IS MODIFIED.
--      Revision 6 overwrote whatever it found: CREATE OR REPLACE on the three
--      guard functions, DROP TRIGGER + CREATE TRIGGER on the three names, and
--      ADD CONSTRAINT only-if-absent. Its rollback could only drop, so a
--      pre-existing object was destroyed with no way back. This block runs before
--      the first modification and aborts the transaction instead.
--
--      Aborts when:
--        * one of the three guard trigger NAMES already exists on any table in
--          public — B drops those names unconditionally;
--        * a guard FUNCTION already exists — CREATE OR REPLACE would overwrite a
--          body that D.1 cannot replay from A0 automatically;
--        * profiles_role_allowed exists and is VALIDATED (B creates NOT VALID, so
--          a validated one is somebody else's), or checks a different column, or
--          uses a different role vocabulary;
--        * a helper name resolves to more than one function in public, or to one
--          with a different return type — CREATE OR REPLACE would rewrite one and
--          leave the policies calling another.
--
--      DELIBERATE RE-RUN, only after saving A0, A0c, A0g and A0h:
--        set local lsp.allow_preexisting_objects = 'on';
--      Default is abort. The setting is read with current_setting(..., true), so
--      an unset value is never an error.
--
--      Note this gate is why A0c/A0g are captures and not assumptions: if it does
--      abort, the capture you saved is the only copy of what was there.
do $$
declare
  v_conflicts text[]  := '{}';
  v_override  boolean := coalesce(current_setting('lsp.allow_preexisting_objects', true), 'off') = 'on';
  v_def       text;
  v_con_valid boolean;
  v_con_key   smallint[];
  v_literals  text[];
  v_ret       text;
  v_retset    boolean;
  r           record;
begin
  -- (1) Guard trigger names, anywhere in public.
  for r in
    select c.relname, t.tgname, pg_get_triggerdef(t.oid) as def
    from pg_trigger t
    join pg_class c on c.oid = t.tgrelid
    join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and not t.tgisinternal
      and t.tgname in ('lsp_guard_profile_role','lsp_guard_provider_verification','lsp_guard_document_status')
  loop
    v_conflicts := v_conflicts || format('trigger %I on public.%I would be dropped by B: %s',
                                         r.tgname, r.relname, r.def);
  end loop;

  -- (2) Guard functions.
  for r in
    select p.proname, pg_get_userbyid(p.proowner) as owner, p.prosecdef, p.proconfig
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and p.proname in ('lsp_guard_profile_role','lsp_guard_provider_verification','lsp_guard_document_status')
      and pg_get_function_identity_arguments(p.oid) = ''
  loop
    v_conflicts := v_conflicts || format('function public.%I() would be overwritten by CREATE OR REPLACE (owner %s, security definer %s, config %s)',
                                         r.proname, r.owner, r.prosecdef,
                                         coalesce(array_to_string(r.proconfig, ','), '(none)'));
  end loop;

  -- (3) profiles_role_allowed: absent is the normal case; present must match what
  --     B would create, otherwise D.1 would be deciding to drop someone else's.
  select pg_get_constraintdef(c.oid), c.convalidated, c.conkey
    into v_def, v_con_valid, v_con_key
  from pg_constraint c
  where c.conrelid = 'public.profiles'::regclass
    and c.conname = 'profiles_role_allowed';

  if found then
    if v_con_valid then
      v_conflicts := v_conflicts || format('constraint profiles_role_allowed exists and is VALIDATED — B creates it NOT VALID, so this is a different object: %s', v_def);
    else
      select array_agg(distinct m[1] order by m[1]) into v_literals
      from regexp_matches(v_def, '''([a-z_]+)''', 'g') as m;

      if v_literals is distinct from array['admin','customer','provider'] then
        v_conflicts := v_conflicts || format('constraint profiles_role_allowed exists with a different role vocabulary (%s): %s',
                                             coalesce(array_to_string(v_literals, ','), '(none)'), v_def);
      elsif v_con_key is distinct from array[(select a.attnum from pg_attribute a
                                               where a.attrelid = 'public.profiles'::regclass
                                                 and a.attname = 'role'
                                                 and not a.attisdropped)] then
        v_conflicts := v_conflicts || format('constraint profiles_role_allowed exists but does not check exactly profiles.role (conkey %s): %s',
                                             v_con_key, v_def);
      end if;
    end if;
  end if;

  -- (4) Helper overloads and return types.
  for r in
    select p.proname,
           count(*) as n,
           string_agg(format('%s -> %s%s',
                             coalesce(nullif(pg_get_function_identity_arguments(p.oid), ''), '(no args)'),
                             format_type(p.prorettype, null),
                             case when p.proretset then ' setof' else '' end),
                      '; ' order by p.oid) as sigs
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and p.proname in ('lsp_role','lsp_is_admin','lsp_provider_ids')
    group by p.proname
  loop
    if r.n > 1 then
      v_conflicts := v_conflicts || format('public.%I has %s functions in public (%s) — CREATE OR REPLACE would rewrite only one and the policies would keep calling another',
                                           r.proname, r.n, r.sigs);
    else
      select format_type(p.prorettype, null), p.proretset
        into v_ret, v_retset
      from pg_proc p join pg_namespace n on n.oid = p.pronamespace
      where n.nspname = 'public' and p.proname = r.proname
        and pg_get_function_identity_arguments(p.oid) = '';

      if    (r.proname = 'lsp_role'         and (v_ret <> 'text'    or v_retset))
         or (r.proname = 'lsp_is_admin'     and (v_ret <> 'boolean' or v_retset))
         or (r.proname = 'lsp_provider_ids' and (v_ret <> 'uuid'    or not v_retset)) then
        v_conflicts := v_conflicts || format('public.%I() exists with return type %s%s, which is not what B installs — CREATE OR REPLACE would fail or create an overload',
                                             r.proname, v_ret, case when v_retset then ' setof' else '' end);
      end if;
    end if;
  end loop;

  if coalesce(array_length(v_conflicts, 1), 0) > 0 then
    if v_override then
      raise notice 'lsp: % pre-existing object(s) detected, continuing because lsp.allow_preexisting_objects = on. D.1 must RESTORE these, not drop them: %',
        array_length(v_conflicts, 1), array_to_string(v_conflicts, ' | ');
    else
      raise exception 'lsp_preflight_conflict: % pre-existing object(s) would be overwritten and could not be restored automatically. Nothing has been modified. Save A0, A0c, A0g and A0h, then either drop or rename them deliberately, or re-run with  set local lsp.allow_preexisting_objects = ''on'';  after saving that output.',
        array_length(v_conflicts, 1)
        using detail = array_to_string(v_conflicts, E'\n');
    end if;
  else
    raise notice 'lsp: preflight clear — none of the 11 created objects and none of the 3 replaced helpers is a conflict';
  end if;
end $$;

-- B1. Role vocabulary. profiles.role is plain text with no constraint (there is
--     no app_role enum). NOT VALID scans nothing, rejects nothing and rewrites
--     nothing on apply, but is enforced for every later INSERT/UPDATE. A CHECK
--     passes on NULL, so B3 handles NULL for new rows. Consequence: a legacy row
--     holding an out-of-range value becomes un-editable (23514) until you fix it
--     deliberately. A9 lists those rows first; none is modified here.
do $$
begin
  if not exists (select 1 from pg_constraint
                 where conname = 'profiles_role_allowed'
                   and conrelid = 'public.profiles'::regclass) then
    alter table public.profiles
      add constraint profiles_role_allowed
      check (role in ('customer','provider','admin')) not valid;
  end if;
end $$;

-- B2. Authorization helpers. SECURITY DEFINER is required: they are called from
--     policies ON profiles, and a SECURITY INVOKER read would re-enter that
--     policy (42P17). search_path pinned, every name schema-qualified, stable,
--     and they return only the caller's own status.
create or replace function public.lsp_role()
returns text language sql stable security definer
set search_path = pg_catalog, public as $$
  select p.role from public.profiles p where p.id = (select auth.uid());
$$;

create or replace function public.lsp_is_admin()
returns boolean language sql stable security definer
set search_path = pg_catalog, public as $$
  select exists (select 1 from public.profiles p
                 where p.id = (select auth.uid()) and p.role = 'admin');
$$;

create or replace function public.lsp_provider_ids()
returns setof uuid language sql stable security definer
set search_path = pg_catalog, public as $$
  select pp.user_id from public.provider_profiles pp
  where pp.user_id = (select auth.uid());
$$;

-- B2.1 OWNER GATE. CREATE OR REPLACE never changes an existing function's owner,
--      and a SECURITY DEFINER function bypasses RLS only when its owner is the
--      table owner (or has BYPASSRLS). Otherwise every policy caller fails with
--      42P17 — a total outage. Ownership is established and verified here, and
--      any failure aborts the whole transaction.
--      NOTE: RAISE supports only % and %%; %I is a format() specifier, so the
--      manual instruction is built with format() and passed as an argument.
do $$
declare
  tbl_owner  text;
  fn         record;
  v_srv_num  int     := current_setting('server_version_num')::int;
  v_check    text    := case when current_setting('server_version_num')::int >= 160000
                             then 'SET' else 'MEMBER' end;
  v_can_set  boolean;
  v_is_super boolean;
begin
  select r.rolname into tbl_owner
  from pg_class c join pg_roles r on r.oid = c.relowner
  where c.oid = 'public.profiles'::regclass;

  if tbl_owner is null then
    raise exception 'lsp_owner_gate_failed: public.profiles not found';
  end if;

  if exists (select 1 from pg_class
             where oid = 'public.profiles'::regclass and relforcerowsecurity) then
    raise exception 'lsp_owner_gate_failed: FORCE ROW LEVEL SECURITY is on for public.profiles; a SECURITY DEFINER helper cannot bypass forced RLS (42P17). Run: alter table public.profiles no force row level security;';
  end if;

  -- Can this session actually SET ROLE to the table owner? Ownership reassignment
  -- needs exactly that, and revision 6 tested the wrong privilege:
  --   'USAGE'  = the role's privileges are available WITHOUT SET ROLE. An inherited
  --              membership satisfies it even when SET ROLE is impossible, so the
  --              gate could pass and the ALTER then fail with 42501.
  --   'SET'    = SET ROLE is possible (PostgreSQL 16+, and it honours a membership
  --              granted WITHOUT SET, which is the case 'USAGE' also accepts).
  --   'MEMBER' = membership, which before 16 IS the same capability because no SET
  --              option exists yet.
  -- Superusers can always SET ROLE to any role, and a session that already IS the
  -- owner needs no switch, so both count as permitted.
  v_is_super := coalesce((select r.rolsuper from pg_roles r where r.rolname = current_user), false);

  if v_srv_num >= 160000 then
    v_can_set := pg_has_role(current_user, tbl_owner, 'SET');
  else
    v_can_set := pg_has_role(current_user, tbl_owner, 'MEMBER');
  end if;

  raise notice 'lsp: server %, membership check %, can_set_role_to_% = % (superuser %, current_user %)',
    current_setting('server_version'), v_check, tbl_owner, v_can_set, v_is_super, current_user;

  if not (v_can_set or v_is_super or current_user = tbl_owner) then
    raise exception 'lsp_owner_gate_failed: this session (%) cannot SET ROLE to % (the owner of public.profiles), so ALTER FUNCTION ... OWNER TO % would fail with 42501. Server %, check used %, can_set_role = false. Run the script as % (or as a superuser).',
      current_user, tbl_owner, tbl_owner, current_setting('server_version'), v_check, tbl_owner;
  end if;

  for fn in
    select p.proname, pg_get_userbyid(p.proowner) as owner
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and p.proname in ('lsp_role','lsp_is_admin','lsp_provider_ids')
  loop
    if fn.owner <> tbl_owner then
      begin
        execute format('alter function public.%I() owner to %I', fn.proname, tbl_owner);
        raise notice 'lsp: % owner reassigned % -> %', fn.proname, fn.owner, tbl_owner;
      exception when others then
        raise exception 'lsp_owner_gate_failed: public.% is owned by % but must be owned by %. Reassignment failed: %. Run manually: %',
          fn.proname, fn.owner, tbl_owner, sqlerrm,
          format('alter function public.%I() owner to %I;', fn.proname, tbl_owner);
      end;
    end if;
  end loop;

  -- Prove the reassignment took effect. ALTER ... OWNER TO can be accepted and
  -- still leave a different owner, and a SECURITY DEFINER helper owned by the
  -- wrong role silently fails every policy caller with 42P17 later. Re-read, do
  -- not assume.
  for fn in
    select p.proname, pg_get_userbyid(p.proowner) as owner
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public'
      and p.proname in ('lsp_role','lsp_is_admin','lsp_provider_ids')
      and pg_get_function_identity_arguments(p.oid) = ''
  loop
    if fn.owner <> tbl_owner then
      raise exception 'lsp_owner_gate_failed: ownership verification failed — public.%() is still owned by % after reassignment (expected %). Aborting: a SECURITY DEFINER helper owned by the wrong role cannot bypass RLS for its callers.',
        fn.proname, fn.owner, tbl_owner;
    end if;
  end loop;

  if not exists (select 1 from pg_proc p join pg_namespace n on n.oid = p.pronamespace
                 where n.nspname = 'public' and p.proname = 'lsp_is_admin' and p.prosecdef) then
    raise exception 'lsp_owner_gate_failed: lsp_is_admin() is not SECURITY DEFINER';
  end if;

  raise notice 'lsp: owner gate passed (table owner = %)', tbl_owner;
end $$;

-- B2.2 Privileges on the helpers. Revoke from PUBLIC as well as anon: revoking
--      only anon would leave the implicit PUBLIC grant in place. A0e captured
--      the previous ACL as restore text for D.1 R4.
revoke all on function public.lsp_role()         from public, anon;
revoke all on function public.lsp_is_admin()     from public, anon;
revoke all on function public.lsp_provider_ids() from public, anon;
grant execute on function public.lsp_role()         to authenticated, service_role;
grant execute on function public.lsp_is_admin()     to authenticated, service_role;
grant execute on function public.lsp_provider_ids() to authenticated, service_role;

-- B2.3 RLS DEPENDENCY GATE (provider_profiles).
--      Two objects above only work if row security is configured the way they
--      assume, and neither condition was checked in revision 6:
--
--        (a) lsp_providers_insert / lsp_providers_update constrain NOTHING unless
--            RLS is ENABLED on provider_profiles. With RLS off the policies are
--            inert and any authenticated user can write any provider row — the
--            opposite of the intent, with no error to notice.
--
--        (b) lsp_provider_ids() is SECURITY DEFINER and reads provider_profiles.
--            A SECURITY DEFINER function bypasses RLS only when its owner owns the
--            table or holds BYPASSRLS, and FORCE ROW LEVEL SECURITY removes the
--            owner's exemption. If either is wrong the helper returns ZERO rows
--            for every caller, lsp_documents_owner matches nothing, and every
--            provider silently loses access to their own documents. B2.1 aligns
--            the helpers with the PROFILES owner only, so a provider_profiles
--            owned by a different role is exactly the case that breaks.
--
--      Both states are silent at apply time and expensive later, so this gate
--      aborts the transaction rather than leaving a notice.
do $$
declare
  v_tbl      text;
  v_owner    text;
  v_rls      boolean;
  v_forced   boolean;
  v_dep      record;
  v_fn_owner text;
  v_bypass   boolean;
begin
  -- (a) RLS enabled on every table whose policy this migration writes.
  foreach v_tbl in array array['profiles','provider_profiles','provider_documents'] loop
    select c.relrowsecurity, c.relforcerowsecurity, pg_get_userbyid(c.relowner)
      into v_rls, v_forced, v_owner
    from pg_class c
    where c.oid = to_regclass(format('public.%I', v_tbl));

    if not found then
      raise exception 'lsp_rls_gate_failed: public.%I does not exist, but this migration writes a policy on it. Create it first.', v_tbl;
    end if;

    if not v_rls then
      raise exception 'lsp_rls_gate_failed: RLS is DISABLED on public.%I (owner %). The policy this migration creates there would have no effect, so any authenticated user could write any row. Enable it deliberately — alter table public.%I enable row level security; — after checking which rows become invisible to clients, then re-run.',
        v_tbl, v_owner, v_tbl;
    end if;

    raise notice 'lsp: RLS enabled on public.% (owner %, force rls %)', v_tbl, v_owner, v_forced;
  end loop;

  -- (b) Each SECURITY DEFINER helper must be able to bypass RLS on the table it
  --     reads, or it returns zero rows to every caller.
  for v_dep in
    select * from (values
      ('lsp_role',         'profiles'),
      ('lsp_is_admin',     'profiles'),
      ('lsp_provider_ids', 'provider_profiles')
    ) as t(fn, tbl)
  loop
    select pg_get_userbyid(p.proowner) into v_fn_owner
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.proname = v_dep.fn
      and pg_get_function_identity_arguments(p.oid) = '';

    select pg_get_userbyid(c.relowner), c.relforcerowsecurity
      into v_owner, v_forced
    from pg_class c
    where c.oid = to_regclass(format('public.%I', v_dep.tbl));

    select coalesce(r.rolbypassrls, false) or coalesce(r.rolsuper, false)
      into v_bypass
    from pg_roles r where r.rolname = v_fn_owner;

    if v_forced and not coalesce(v_bypass, false) then
      raise exception 'lsp_rls_gate_failed: FORCE ROW LEVEL SECURITY is on for public.%I, so %() (SECURITY DEFINER, owner %) cannot bypass RLS and would return zero rows for every caller. Run: alter table public.%I no force row level security;',
        v_dep.tbl, v_dep.fn, v_fn_owner, v_dep.tbl;
    end if;

    if v_fn_owner is distinct from v_owner and not coalesce(v_bypass, false) then
      raise exception 'lsp_rls_gate_failed: %() is owned by %, but public.%I is owned by % and % lacks BYPASSRLS. RLS therefore applies inside the SECURITY DEFINER helper: it returns zero rows for every caller and every policy that calls it denies — providers lose access to their own documents with no error anywhere. Reassign the helper to the table owner, or grant bypassrls deliberately, then re-run.',
        v_dep.fn, v_fn_owner, v_dep.tbl, v_owner, v_fn_owner;
    end if;

    raise notice 'lsp: RLS dependency OK — %() owned by % can bypass RLS on public.%',
      v_dep.fn, v_fn_owner, v_dep.tbl;
  end loop;

  raise notice 'lsp: RLS dependency gate passed';
end $$;

-- B3. ROLE ESCALATION GUARD (public.profiles).
--     RLS is row-scoped, never column-scoped: no policy can stop a self-update of
--     {"role":"admin"}. Only a BEFORE trigger sees old and new values.
--
--     THE GATE: trusted is an ALLOWLIST of the roles Supabase actually uses for
--     privileged paths. Everything else must be 'authenticated' with a real JWT
--     subject, or it is rejected with 42501.
--
--     Why current_user and not a request header: PostgREST sets the session role
--     from the *signed* JWT `role` claim, so current_user cannot be forged from a
--     browser. `authenticator` is the login role PostgREST switches away from
--     before running any statement — it never executes DML itself, and if it did,
--     it is absent from the allowlist and is not 'authenticated', so it is
--     rejected. The same holds for any custom or future role: absent from the
--     allowlist means denied, which is the fail-closed polarity an earlier
--     revision lacked. Section S5 exercises exactly this branch with a real
--     non-trusted role, and proves the resulting 42501 came from here.
--
--     Role is immutable on UPDATE (silently kept, so profile saves that echo
--     `role` keep working, which is what api.js ensureProfile() does). No admin
--     branch: a client-supplied role change could demote an admin on next login.
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

-- B4. Policies. Each is recreated equal-or-stricter. bookings, customer_addresses,
--     notifications and the provider_profiles SELECT policy are NOT touched.
--     B4.0 provider_profiles INSERT on the real key (user_id; there is no id
--     column). Re-creating it is a no-op where the live policy is already correct
--     and repairs a database where only the schema.sql variant was attempted (that
--     one references a non-existent `id` and therefore creates no policy at all).
drop policy if exists lsp_providers_insert on public.provider_profiles;
create policy lsp_providers_insert on public.provider_profiles for insert to authenticated
  with check (user_id = (select auth.uid()) or public.lsp_is_admin());

-- B4.1 profiles INSERT: a self-created profile may never be privileged.
drop policy if exists lsp_profiles_insert on public.profiles;
create policy lsp_profiles_insert on public.profiles for insert to authenticated
  with check (id = (select auth.uid()) and role in ('customer','provider'));

-- B4.2 provider_profiles UPDATE on user_id, with the admin branch verification needs.
drop policy if exists lsp_providers_update on public.provider_profiles;
create policy lsp_providers_update on public.provider_profiles for update to authenticated
  using (user_id = (select auth.uid()) or public.lsp_is_admin())
  with check (user_id = (select auth.uid()) or public.lsp_is_admin());

-- B4.3 provider_documents: provider owns their rows, admin may review all.
--      DELIBERATE TIGHTENING, flagged for review: the live policy reads
--        provider_id = auth.uid() or lsp_is_admin()
--      so any signed-in user — including one with no provider_profiles row — can
--      create a document row stamped with their own uid. lsp_provider_ids()
--      requires an actual provider_profiles row, which is the correct ownership
--      test. If your provider registration uploads a document BEFORE creating
--      provider_profiles, use the live predicate instead:
--        using (provider_id = (select auth.uid()) or public.lsp_is_admin())
--        with check (provider_id = (select auth.uid()) or public.lsp_is_admin())
drop policy if exists lsp_documents_owner on public.provider_documents;
create policy lsp_documents_owner on public.provider_documents for all to authenticated
  using (provider_id in (select public.lsp_provider_ids()) or public.lsp_is_admin())
  with check (provider_id in (select public.lsp_provider_ids()) or public.lsp_is_admin());

-- B4.4 Verification guard: a provider must not approve themselves. The policy
--      above still lets them edit their own row; this pins only the deciding field.
--      Coercion (not an error) on INSERT keeps registration working.
create or replace function public.lsp_guard_provider_verification()
returns trigger language plpgsql security invoker
set search_path = pg_catalog, public as $$
declare
  api_role text := current_user;
  trusted  constant text[] := array['postgres','supabase_admin','supabase_storage_admin','supabase_auth_admin','service_role'];
begin
  if api_role = any (trusted) then
    return new;
  end if;
  if api_role <> 'authenticated' then
    raise exception 'lsp_write_denied: role % may not write public.provider_profiles', api_role
      using errcode = '42501';
  end if;
  if public.lsp_is_admin() then
    return new;                                        -- admin verification decision
  end if;

  if tg_op = 'INSERT' then
    if new.verification_status in ('approved','verified') then
      new.verification_status := 'pending';
    end if;
    return new;
  end if;

  if new.verification_status is distinct from old.verification_status then
    raise log 'lsp_guard_provider_verification: blocked % -> % for %',
      old.verification_status, new.verification_status, new.user_id;
    new.verification_status := old.verification_status;
  end if;
  return new;
end $$;

drop trigger if exists lsp_guard_provider_verification on public.provider_profiles;
create trigger lsp_guard_provider_verification before insert or update on public.provider_profiles
  for each row execute function public.lsp_guard_provider_verification();

-- B4.5 DOCUMENT GUARD. Without it a provider can mark their own document
--      'approved' (the policy is FOR ALL), which makes admin review meaningless.
--      PRESERVED: uploads, metadata edits (document_type, file_url) on documents
--      that are pending/rejected, any non-privileged status, and the whole admin
--      path — the admin check returns before any pinning.
--      PINNED: status itself, provider_id (ownership is immutable), and — on an
--      already approved/verified document — any substantive edit, which resets
--      status to 'pending' so changed evidence is reviewed again.
--      The diff is taken over the whole row as jsonb, so it needs no column names
--      and cannot fail on a schema difference; only 'status' and 'updated_at' are
--      excluded, and removing a key that does not exist is a no-op. The live table
--      has no updated_at (see A11b). Order matters: the reset returns early, so the
--      later status pin cannot undo it.
create or replace function public.lsp_guard_document_status()
returns trigger language plpgsql security invoker
set search_path = pg_catalog, public as $$
declare
  api_role text := current_user;
  trusted  constant text[] := array['postgres','supabase_admin','supabase_storage_admin','supabase_auth_admin','service_role'];
begin
  if api_role = any (trusted) then
    return new;
  end if;
  if api_role <> 'authenticated' then
    raise exception 'lsp_write_denied: role % may not write public.provider_documents', api_role
      using errcode = '42501';
  end if;
  if public.lsp_is_admin() then
    return new;
  end if;

  if tg_op = 'INSERT' then
    if new.status is null or new.status in ('approved','verified','rejected') then
      new.status := 'pending';                         -- no self-approval on upload
    end if;
    return new;
  end if;

  new.provider_id := old.provider_id;                  -- ownership is immutable

  if old.status in ('approved','verified')
     and (to_jsonb(new) - 'status' - 'updated_at')
         is distinct from (to_jsonb(old) - 'status' - 'updated_at') then
    new.status := 'pending';                           -- evidence changed: re-review
    raise log 'lsp_guard_document_status: document % reset to pending after edit', old.id;
    return new;
  end if;

  if new.status is distinct from old.status then
    raise log 'lsp_guard_document_status: blocked % -> % for document %',
      old.status, new.status, old.id;
    new.status := old.status;
  end if;
  return new;
end $$;

drop trigger if exists lsp_guard_document_status on public.provider_documents;
create trigger lsp_guard_document_status before insert or update on public.provider_documents
  for each row execute function public.lsp_guard_document_status();

-- B5. OPTIONAL hardening — review before enabling. Supabase grants CREATE on
--     schema public by default; B2/B3 already defend via pinned search_path and
--     schema-qualified names, so this is defence in depth.
-- revoke create on schema public from anon, authenticated;

-- B6. DOCUMENTED, NOT CHANGED — public.services. Current live definition:
--       create policy lsp_services_write on public.services for all
--         to authenticated using (true) with check (true);
--     Any signed-in user can insert, rewrite or delete catalogue rows. It does not
--     expose bookings, profiles, payments or documents. Owner-scoping is
--     impossible on the live table (no provider_id column), and provider
--     catalogue work lives in provider_skills, which is already owner-scoped.
--     SECURE FUTURE DESIGN (later phase, after both pre-conditions hold):
--       drop policy if exists lsp_services_write on public.services;
--       create policy lsp_services_read on public.services for select
--         to authenticated using (true);
--       create policy lsp_services_admin_write on public.services for all
--         to authenticated using (public.lsp_is_admin())
--         with check (public.lsp_is_admin());
--     PRE-CONDITIONS: (a) A8 shows the permissive policy is still live;
--     (b) a repository check proves no customer or provider flow writes
--     `services`. If (b) cannot be proven, add provider_id and scope writes with
--     provider_id = auth.uid() — a schema change needing its own approval.

commit;


-- ============================================================================
-- SECTION C — POST-MIGRATION VERIFICATION (READ-ONLY)
-- ----------------------------------------------------------------------------
-- Every statement below was re-read for valid PostgreSQL. Aggregates are all
-- count(*); the catalogue columns are schemaname / tablename / policyname; the
-- ACL helper is acldefault (no underscore); coalesce is spelled coalesce.
-- No statement in this section writes, and none raises, so the whole batch runs
-- even when a check fails.
-- ============================================================================

-- C1. Helpers: SECURITY DEFINER, pinned search_path, owned by the profiles owner.
select p.proname,
       p.proowner::regrole as owner,
       p.prosecdef as security_definer,
       p.proconfig as pinned_settings,
       (p.proowner = (select relowner from pg_class
                      where oid = 'public.profiles'::regclass)) as owner_matches_profiles
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public' and p.proname like 'lsp\_%'
order by p.proname;

-- C1b. The three guard functions MUST be SECURITY INVOKER and carry a pinned
--      search_path. S5 depends on this: if a guard were SECURITY DEFINER,
--      current_user inside it would be the owner (trusted) and an untrusted
--      caller would silently pass the gate.
select p.proname,
       not p.prosecdef as security_invoker,
       p.proconfig as pinned_settings
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public' and p.proname like 'lsp\_guard%'
order by p.proname;
-- expect: 3 rows, security_invoker = true, pinned_settings mentions search_path

-- C2. Guard triggers: exactly THREE — the same three Section D.1 drops.
select count(*) as guard_triggers,
       count(*) = 3 as matches_rollback
from pg_trigger t
join pg_class c on c.oid = t.tgrelid
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and t.tgname like 'lsp\_guard%';
-- expect: guard_triggers = 3, matches_rollback = true

-- C2b. No lsp_* trigger anywhere except the three guarded tables. Expect 0 rows:
--      a row here means B created something D.1 does not undo.
select c.relname as table_name, t.tgname
from pg_trigger t
join pg_class c on c.oid = t.tgrelid
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and t.tgname like 'lsp\_%'
  and c.relname not in ('profiles','provider_profiles','provider_documents')
order by c.relname, t.tgname;

-- C3. Recreated policies have the expected shape; the provider ones must use user_id.
select tablename, policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'public'
  and policyname in ('lsp_providers_insert','lsp_providers_update',
                     'lsp_profiles_insert','lsp_documents_owner')
order by policyname;

-- C4. ADMIN REPORT ONLY. Phase 0 neither creates nor requires an admin account;
--     ZERO admins is a valid Phase 0 result and this never fails.
select count(*) filter (where role = 'admin') as admin_accounts,
       count(*) as total_profiles
from public.profiles;

select id, email from public.profiles
where role = 'admin' order by email;

-- C5. Effective EXECUTE privilege, PUBLIC and inheritance included.
--     grantee 0 is PUBLIC and cannot be cast to regrole, so it is labelled here.
select p.proname,
       case when a.grantee = 0 then 'PUBLIC'
            else pg_get_userbyid(a.grantee) end as grantee,
       a.privilege_type
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
cross join lateral aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
where n.nspname = 'public' and p.proname like 'lsp\_%'
order by 1, 2;

--     Same 42883 hazard as A10c: a text signature raises when the function is
--     absent, so resolve it first. A NULL column here means "not applicable",
--     never "denied".
select to_regprocedure('public.lsp_is_admin()') is not null as lsp_is_admin_exists,
       case when to_regprocedure('public.lsp_is_admin()') is null then null
            else has_function_privilege('anon', to_regprocedure('public.lsp_is_admin()'), 'EXECUTE')
       end as anon_can_execute,
       case when to_regprocedure('public.lsp_is_admin()') is null then null
            else has_function_privilege('authenticated', to_regprocedure('public.lsp_is_admin()'), 'EXECUTE')
       end as auth_can_execute;
-- expect: lsp_is_admin_exists = true, anon_can_execute = false, auth_can_execute = true

-- C6. Constraint present and still NOT VALID (no row scanned or rewritten).
select conname, convalidated, pg_get_constraintdef(oid) as definition
from pg_constraint where conname = 'profiles_role_allowed';

-- C7. Distributions must equal A3/A11: this migration modifies no existing row.
select coalesce(role, '(null)') as role, count(*) as accounts
from public.profiles group by role order by accounts desc;

select coalesce(status, '(null)') as status, count(*) as documents
from public.provider_documents group by status order by documents desc;

-- C8. OBJECT INVENTORY from the catalogue — per-kind counts plus a TOTAL row
--     produced by GROUP BY ROLLUP. Expect trigger 3, guard function 3, policy 4,
--     constraint 1, TOTAL 11.
--     VALIDATED, not asserted: B0 enumerates the same eleven objects, and C8c
--     diffs that list against the catalogue in both directions. A total of 11
--     here would still be wrong if one expected object were missing and an
--     unrelated one present, which is why C8c exists.
with created as (
  select 'trigger'::text as kind, t.tgname::text as name, c.relname::text as on_object
  from pg_trigger t
  join pg_class c on c.oid = t.tgrelid
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and not t.tgisinternal and t.tgname like 'lsp\_guard%'
  union all
  select 'guard function', p.proname, '(function)'
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public' and p.proname like 'lsp\_guard%'
  union all
  select 'policy', policyname, tablename
  from pg_policies
  where schemaname = 'public'
    and policyname in ('lsp_providers_insert','lsp_providers_update',
                       'lsp_profiles_insert','lsp_documents_owner')
  union all
  select 'constraint', conname, 'profiles'
  from pg_constraint
  where conname = 'profiles_role_allowed'
    and conrelid = 'public.profiles'::regclass
)
select coalesce(kind, 'TOTAL') as kind, count(*) as objects
from created
group by rollup (kind)
order by grouping(kind), kind;
-- expect: constraint 1, guard function 3, policy 4, trigger 3, TOTAL 11 last
-- ordering by grouping(kind) keeps the TOTAL row last under any collation.

-- C8b. The 3 REPLACED helpers — deliberately outside the 11 and NOT dropped by
--      D.1, because policies call them. These are restored from A0, not removed.
select p.proname as replaced_helper,
       p.proowner::regrole as owner,
       p.prosecdef as security_definer,
       p.proconfig as pinned_settings
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public'
  and p.proname in ('lsp_role','lsp_is_admin','lsp_provider_ids')
order by 1;

-- C8c. INVENTORY DIFF — the hard-coded expected set of ELEVEN objects, compared
--      with the catalogue in BOTH directions. Expect 0 rows.
--        MISSING    = Section B should have created it and the catalogue lacks it
--        UNEXPECTED = the catalogue has it and this inventory does not know it
--      A row in either direction is a defect in B0/C8, not in PostgreSQL.
with expected(kind, name, on_object) as (
  values
    ('trigger',        'lsp_guard_profile_role',          'profiles'),
    ('trigger',        'lsp_guard_provider_verification', 'provider_profiles'),
    ('trigger',        'lsp_guard_document_status',       'provider_documents'),
    ('guard function', 'lsp_guard_profile_role',          '(function)'),
    ('guard function', 'lsp_guard_provider_verification', '(function)'),
    ('guard function', 'lsp_guard_document_status',       '(function)'),
    ('policy',         'lsp_providers_insert',            'provider_profiles'),
    ('policy',         'lsp_providers_update',            'provider_profiles'),
    ('policy',         'lsp_profiles_insert',             'profiles'),
    ('policy',         'lsp_documents_owner',             'provider_documents'),
    ('constraint',     'profiles_role_allowed',           'profiles')
),
actual(kind, name, on_object) as (
  select 'trigger'::text, t.tgname::text, c.relname::text
  from pg_trigger t
  join pg_class c on c.oid = t.tgrelid
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = 'public' and not t.tgisinternal and t.tgname like 'lsp\_guard%'
  union all
  select 'guard function', p.proname, '(function)'
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public' and p.proname like 'lsp\_guard%'
  union all
  select 'policy', policyname, tablename
  from pg_policies
  where schemaname = 'public'
    and policyname in ('lsp_providers_insert','lsp_providers_update',
                       'lsp_profiles_insert','lsp_documents_owner')
  union all
  select 'constraint', conname, 'profiles'
  from pg_constraint
  where conname = 'profiles_role_allowed'
    and conrelid = 'public.profiles'::regclass
)
select 'MISSING' as direction, kind, name, on_object
from (select * from expected except select * from actual) m
union all
select 'UNEXPECTED', kind, name, on_object
from (select * from actual except select * from expected) u
order by direction, kind, name;
-- expect: 0 rows

-- C8d. The expected set really has eleven members — a guard against editing the
--      list above and forgetting what B0 claims.
with expected(kind, name, on_object) as (
  values
    ('trigger',        'lsp_guard_profile_role',          'profiles'),
    ('trigger',        'lsp_guard_provider_verification', 'provider_profiles'),
    ('trigger',        'lsp_guard_document_status',       'provider_documents'),
    ('guard function', 'lsp_guard_profile_role',          '(function)'),
    ('guard function', 'lsp_guard_provider_verification', '(function)'),
    ('guard function', 'lsp_guard_document_status',       '(function)'),
    ('policy',         'lsp_providers_insert',            'provider_profiles'),
    ('policy',         'lsp_providers_update',            'provider_profiles'),
    ('policy',         'lsp_profiles_insert',             'profiles'),
    ('policy',         'lsp_documents_owner',             'provider_documents'),
    ('constraint',     'profiles_role_allowed',           'profiles')
)
select count(*) as expected_objects,
       count(*) = 11 as matches_b0_claim,
       count(*) = count(distinct (kind, name)) as no_duplicates
from expected;
-- expect: expected_objects = 11, matches_b0_claim = true, no_duplicates = true

-- C9. RLS DEPENDENCY, POST-MIGRATION. Read-only mirror of B2.3: B2.3 aborts when
--     the state is wrong, C9 shows what the state actually is.
--     provider_profiles must have RLS ENABLED or lsp_providers_insert /
--     lsp_providers_update constrain nothing; each SECURITY DEFINER helper must
--     be able to bypass RLS on the table it reads, or it returns zero rows and
--     every policy calling it denies.
select c.relname,
       c.relrowsecurity as rls_enabled,
       c.relforcerowsecurity as rls_forced,
       pg_get_userbyid(c.relowner) as table_owner
from pg_class c join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relname in ('profiles','provider_profiles','provider_documents')
order by c.relname;
-- expect: rls_enabled = true for all three, rls_forced = false

select p.proname,
       pg_get_userbyid(p.proowner) as helper_owner,
       coalesce(r.rolbypassrls, false) as owner_bypassrls,
       coalesce(r.rolsuper, false) as owner_superuser,
       case p.proname when 'lsp_provider_ids' then 'provider_profiles' else 'profiles' end as reads_table
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
left join pg_roles r on r.oid = p.proowner
where n.nspname = 'public'
  and p.proname in ('lsp_role','lsp_is_admin','lsp_provider_ids')
order by p.proname;
-- expect: for each row, helper_owner = the owner of reads_table, or
--         owner_bypassrls / owner_superuser = true


-- ============================================================================
-- SECTION D — ROLLBACK (only if a real regression appears)
-- ----------------------------------------------------------------------------
-- THIS IS NOT AUTOMATIC. It restores what A0, A0b, A0c, A0e, A0f, A0g and A0h
-- recorded and nothing else. Without that saved output, D.1 can remove the new
-- objects but cannot put a pre-existing one back. Every line is a comment until
-- you deliberately uncomment it, and each one names the A0h row that licenses it.
-- ============================================================================

-- D.1  RESTORE — the exact original state, or nothing.
-- ----------------------------------------------------------------------------
-- D.1 IS DRIVEN BY A0h. For each of the 14 objects B creates or replaces, A0h
-- reports pre_existing and a rollback_action. Read it before uncommenting
-- anything, then run only the branch it licenses:
--
--   pre_existing = false -> D.1.1 drops the object (B created it)
--   pre_existing = true  -> D.1.3 restores the captured original (do NOT drop)
--
-- Revision 6 ran one unconditional DROP list. Against a pre-existing trigger,
-- guard function or constraint that list deleted an object the migration had
-- overwritten, and nothing could put it back. Dropping a pre-existing object is
-- now a named mistake, not a default.
--
-- Requires the saved Section A output: A0 (function definition, owner, ACL),
-- A0c (trigger definition + tgenabled), A0g (constraint definition +
-- convalidated), A0e/A0f (ready-to-run restore text), A0h (which branch applies).
-- Without that output only the pre_existing = false branch is safe.
--
-- ORDER MATTERS: triggers reference functions, so drop a trigger before the
-- function it calls, and restore a function before the trigger that calls it.

-- D.1.0 PRECONDITIONS.
--   The session must be able to SET ROLE to every owner D.1.2 restores to. A4c's
--   can_reassign_helper_owner proves it for the APPLY session; re-check it if the
--   rollback runs from a different one. The trigger drops take ACCESS EXCLUSIVE
--   on all three tables: stop clients first.
--   begin;

-- D.1.1 DROP ONLY WHAT B CREATED. Uncomment a line only when A0h reports
--       pre_existing = false for that object. When A0h reports true, that object
--       belongs in D.1.3 and dropping it here destroys the original.
--
-- -- triggers first, so the functions below are unreferenced
-- drop trigger if exists lsp_guard_document_status       on public.provider_documents;  -- A0h false only
-- drop trigger if exists lsp_guard_provider_verification on public.provider_profiles;  -- A0h false only
-- drop trigger if exists lsp_guard_profile_role          on public.profiles;           -- A0h false only
--
-- drop function if exists public.lsp_guard_document_status();        -- A0h false only
-- drop function if exists public.lsp_guard_provider_verification();  -- A0h false only
-- drop function if exists public.lsp_guard_profile_role();           -- A0h false only
--
-- -- The constraint is NOT VALID: no row was scanned or rewritten, so dropping it
-- -- restores nothing except its own absence. A0h still decides.
-- alter table public.profiles drop constraint if exists profiles_role_allowed;       -- A0h false only
--
-- drop policy if exists lsp_profiles_insert  on public.profiles;                      -- A0h false only
-- drop policy if exists lsp_providers_insert on public.provider_profiles;             -- A0h false only
-- drop policy if exists lsp_providers_update on public.provider_profiles;             -- A0h false only
-- drop policy if exists lsp_documents_owner  on public.provider_documents;            -- A0h false only

-- D.1.2 RESTORE THE FOUR POLICIES AND THE THREE HELPERS (R1-R4). The helpers
--       always pre-exist, so they are never dropped — many policies call them and
--       dropping them would break every one of those policies. Policies are
--       dropped by D.1.1 only when A0h says B created them; when one pre-existed,
--       B replaced it and R1 puts the captured definition back.
--
-- -- R1 <four CREATE POLICY statements from A0f (raw rows: A0b), with
-- --      permissive/roles/cmd/qual/with_check exactly as captured. Run
-- --      "drop policy if exists <name> on <table>;" first for each: CREATE POLICY
-- --      has no OR REPLACE, so recreating without the drop fails with 42710. If
-- --      A0h says a policy was absent before B, D.1.1 already removed it and
-- --      there is nothing to restore for that row.>
--
-- -- R2 <paste the CREATE OR REPLACE FUNCTION statements for lsp_role,
-- --      lsp_is_admin and lsp_provider_ids from A0's definition column.
-- --      pg_get_functiondef output includes the SET search_path clauses and the
-- --      SECURITY DEFINER bit, so those come back with the body. It does NOT
-- --      include the owner or the ACL — those are R3 and R4.>
--
-- -- R3 <for each of the three, restore the owner recorded by A0's owner column:
-- --      alter function public.lsp_role() owner to <owner-from-A0>;
-- --      Needs the same SET ROLE privilege B2.1 required.>
--
-- -- R4 <restore the ACL recorded by A0's acl column, using A0e's rendered
-- --      statements. Restore EXACTLY, which means revoking first: PostgreSQL
-- --      grants EXECUTE on a new function to PUBLIC, so a plain re-grant would
-- --      leave a PUBLIC grant that did not exist before.
-- --        revoke all on function public.lsp_role() from public, anon, authenticated, service_role;
-- --        <then replay A0e's grant lines for that function>>

-- D.1.3 RESTORE PRE-EXISTING OBJECTS (R5-R7). Run only the lines whose A0h row
--       says pre_existing = true. Order: function before the trigger that calls
--       it, trigger before its table is used again.
--
-- -- R5 <guard function, if A0h: true. Paste A0's pg_get_functiondef for it, then
-- --      restore owner and ACL exactly as R3/R4 do for the helpers:
-- --        alter function public.lsp_guard_profile_role() owner to <A0 owner>;
-- --        revoke all on function public.lsp_guard_profile_role() from public, anon, authenticated, service_role;
-- --        <replay A0e grant lines for that function>>
--
-- -- R6 <trigger, if A0h: true. Paste A0c's restore_statement verbatim: it
-- --      carries the definition AND the enabled state, because a trigger captured
-- --      as tgenabled = 'D' must come back DISABLED.
-- --        <A0c definition>;  alter table public.profiles disable trigger lsp_guard_profile_role;
-- --      tgenabled = 'O' needs no second statement; 'R' and 'A' each have their
-- --      own and A0c emits the right one.>
--
-- -- R7 <constraint, if A0h: true. Paste A0g's restore_statement verbatim:
-- --        alter table public.profiles add constraint profiles_role_allowed <definition>;
-- --      pg_get_constraintdef emits NOT VALID when the captured constraint was
-- --      unvalidated, so validation state returns with the definition. Compare
-- --      the result against A0g's convalidated column — a captured
-- --      convalidated = true must come back validated.>

-- D.1.4 VERIFY BEFORE COMMIT. Do not commit on faith.
--   Re-run the read-only checks and compare against the captured output:
--     C1/C1b  helpers: definer, pinned search_path, owner = profiles owner, ACL
--             identical to A0's "before" text
--     C2      guard triggers: count 0 if all three were created by B, otherwise
--             the A0c count, with the same tgenabled values
--     C6      profiles_role_allowed: absent, or A0g's definition AND convalidated
--     A0h     every row now reads the opposite of its captured pre_existing
--   Only then:
-- -- commit;

-- D.1.5 WHAT IS NOT REVERSIBLE EVEN HERE. Rows written between apply and
--       rollback are untouched by every statement above: the guard triggers are
--       BLOCKED-ATTEMPT guards (D.2 items 17-20) and the PERSISTED coercions
--       (D.2 items 21-23) stay written. The raise log is their only record. D.1
--       restores the SCHEMA, not the data.

-- D.2  OBJECT-BY-OBJECT RESTORE MAP.
-- ----------------------------------------------------------------------------
-- Two different things are being tracked here, and conflating them was the
-- defect in revision 5:
--
--   BLOCKED ATTEMPT  — the trigger rewrote the value in memory before the row
--                      was written. Nothing reached disk. There is no old value
--                      to restore, because no value changed. Rollback is not
--                      even relevant: the attempt never persisted, with or
--                      without a rollback.
--   PERSISTED CHANGE — a different value is now stored. Rollback does not put
--                      the old value back; only the raise log records it.
--
-- | # | object                                  | before B      | effect of B | restore | recoverable from |
-- |---|-----------------------------------------|---------------|-------------|---------|------------------|
-- | 1 | trigger lsp_guard_profile_role          | A0c: absent or pre-existing | created, or overwritten if pre-existing | A0h false: drop (D.1.1); A0h true: R6 | YES — A0c definition + tgenabled |
-- | 2 | trigger lsp_guard_provider_verification | A0c: absent or pre-existing | created, or overwritten if pre-existing | A0h false: drop (D.1.1); A0h true: R6 | YES — A0c definition + tgenabled |
-- | 3 | trigger lsp_guard_document_status       | A0c: absent or pre-existing | created, or overwritten if pre-existing | A0h false: drop (D.1.1); A0h true: R6 | YES — A0c definition + tgenabled |
-- | 4 | function lsp_guard_profile_role         | A0: absent or pre-existing | created, or body overwritten by CREATE OR REPLACE | A0h false: drop (D.1.1); A0h true: R5 | YES — A0 definition, owner, ACL |
-- | 5 | function lsp_guard_provider_verification| A0: absent or pre-existing | created, or body overwritten by CREATE OR REPLACE | A0h false: drop (D.1.1); A0h true: R5 | YES — A0 definition, owner, ACL |
-- | 6 | function lsp_guard_document_status      | A0: absent or pre-existing | created, or body overwritten by CREATE OR REPLACE | A0h false: drop (D.1.1); A0h true: R5 | YES — A0 definition, owner, ACL |
-- | 7 | constraint profiles_role_allowed        | A0g: absent, or present (B leaves a same-named one untouched) | created NOT VALID if absent; unchanged if present | A0h false: drop (D.1.1); A0h true: R7 | YES — A0g definition + convalidated; no row scanned or rewritten |
-- | 8 | policy lsp_profiles_insert              | A0b row or absent | replaced | drop + R1 | YES — A0b/A0f, exactly |
-- | 9 | policy lsp_providers_insert             | A0b row (expected live) | replaced | drop + R1 | YES — A0b/A0f, exactly |
-- |10 | policy lsp_providers_update             | A0b row or absent | replaced | drop + R1 | YES — A0b/A0f, exactly |
-- |11 | policy lsp_documents_owner              | A0b row or absent | replaced | drop + R1 | YES — A0b/A0f, exactly |
-- |12 | function lsp_role body                  | A0 row        | replaced    | R2      | YES — A0 definition column |
-- |13 | function lsp_is_admin body              | A0 row        | replaced    | R2      | YES — A0 definition column |
-- |14 | function lsp_provider_ids body          | A0 row        | replaced    | R2      | YES — A0 definition column |
-- |15 | helper ownership (3 functions)          | A0 owner      | changed only if not already the profiles owner | R3 | YES — A0 owner column; needs the SET ROLE privilege B2.1 required |
-- |16 | helper EXECUTE ACL (3 functions)        | A0 acl        | revoked from PUBLIC+anon, granted to authenticated+service_role | R4 | YES — A0 acl column, rendered by A0e |
--
-- BLOCKED ATTEMPTS — never written, nothing to restore:
-- |17 | profiles.role change (UPDATE)          | — | new.role := old.role before the row is written; the stored value is unchanged |
-- |18 | provider_profiles.verification_status change (UPDATE) | — | new.verification_status := old.verification_status before the row is written |
-- |19 | provider_documents.provider_id change (UPDATE) | — | new.provider_id := old.provider_id before the row is written. The attempted provider_id never reaches disk, so there is no ownership drift to undo and no row to repair. This is a BLOCKED ATTEMPT, not a persisted change. |
-- |20 | provider_documents.status change (UPDATE) | — | new.status := old.status before the row is written |
--
--   Why 19 is called out separately: a rejected provider_id change looks like a
--   data change in the logs (the raise log line names the document) but leaves
--   the table byte-identical. Only rows in the PERSISTED list below actually
--   differ from their pre-migration value.
--
-- PERSISTED CHANGES — written, NOT reversible, logged only:
-- |21 | (a) provider_profiles.verification_status stored as 'pending' where an INSERT asked for 'approved'/'verified' (B4.4 coercion) |
-- |22 | (b) provider_documents.status stored as 'pending' where an INSERT asked for approved/verified/rejected (B4.5) |
-- |23 | (c) provider_documents.status reset to 'pending' when a provider edited an already approved/verified document (B4.5) |
--
--   The raise log lines are the only record of which rows were affected:
--     'lsp_guard_provider_verification: blocked % -> % for %'
--     'lsp_guard_document_status: blocked % -> % for document %'
--     'lsp_guard_document_status: document % reset to pending after edit'
--   LOG-level messages are subject to log_min_messages; if the server does not
--   emit them, no record exists. Capture them before relying on this map.

-- D.3  NOT AT RISK.
--   No row is deleted, no column or table is dropped, no policy is weakened, no
--   table grant is changed, and the migration itself modifies no existing
--   profile or document row. The only rows that can change are those written by
--   an authenticated client after B commits, listed in D.2 items 21-23.


-- ============================================================================
-- SECTION S — TEST PLAN
-- ----------------------------------------------------------------------------
-- STATUS: DESIGNED, NOT EXECUTED. Nothing in this section has been run.
--
-- PROVENANCE (see the header): the revision 5 Section S text is not in this
-- repository — no committed revision contains it. S5 below is rebuilt to the
-- five requirements of the revision 6 review. S1-S4, S6-S9, S12 and S13 are
-- marked [RECONSTRUCTED]: they are derived from what Sections A, B and C
-- already assert, not recovered verbatim.
--
-- HOW TO READ THE RESULTS
--   * "SQL Editor" tests run here, as the project owner, and need no account.
--   * "Client session" tests need a real signed-in user (a JWT), because the
--     guard reads auth.uid() and PostgREST sets the role from the signed token.
--     They are NOT runnable in the SQL Editor and are NOT claimed as run.
--   * A test that cannot run is recorded as not run. None of these has passed.
-- ============================================================================

-- ----------------------------------------------------------------------------
-- S1 [RECONSTRUCTED] — preconditions and identity (SQL Editor, read-only)
-- ----------------------------------------------------------------------------
-- Covered by A4c/A2; repeated here as the test-plan entry point.
select current_user as executing_role,
       session_user as login_role,
       (select r.rolname from pg_class c join pg_roles r on r.oid = c.relowner
        where c.oid = 'public.profiles'::regclass) as profiles_owner,
       (select relrowsecurity from pg_class where oid = 'public.profiles'::regclass) as rls_on_profiles,
       (select relforcerowsecurity from pg_class where oid = 'public.profiles'::regclass) as rls_forced;
-- expect: executing_role = profiles_owner = postgres, rls_forced = false

-- ----------------------------------------------------------------------------
-- S2 [RECONSTRUCTED] — helper semantics without a JWT (SQL Editor, read-only)
-- ----------------------------------------------------------------------------
-- In the SQL Editor there is no request JWT, so auth.uid() is NULL. These
-- results are CORRECT for that context, not a failure.
select public.lsp_role() as my_role,
       public.lsp_is_admin() as i_am_admin,
       (select count(*) from public.lsp_provider_ids()) as my_provider_rows;
-- expect: NULL, false, 0

-- ----------------------------------------------------------------------------
-- S3 [RECONSTRUCTED] — helper EXECUTE privilege matrix (SQL Editor, read-only)
-- ----------------------------------------------------------------------------
select has_function_privilege('anon','public.lsp_is_admin()','EXECUTE')          as anon_exec,
       has_function_privilege('authenticated','public.lsp_is_admin()','EXECUTE') as auth_exec,
       has_function_privilege('anon','public.lsp_role()','EXECUTE')              as anon_exec_role,
       has_function_privilege('authenticated','public.lsp_role()','EXECUTE')     as auth_exec_role;
-- expect: false, true, false, true

-- ----------------------------------------------------------------------------
-- S4 [RECONSTRUCTED] — profiles INSERT policy shape (SQL Editor, read-only)
-- ----------------------------------------------------------------------------
select policyname, cmd, roles, with_check
from pg_policies
where schemaname = 'public' and tablename = 'profiles' and policyname = 'lsp_profiles_insert';
-- expect: 1 row, cmd = INSERT, with_check restricts id = auth.uid()
--         AND role in ('customer','provider')

-- ============================================================================
-- S5 — TRIGGER ATTRIBUTION TEST  (the redesigned test)
-- ----------------------------------------------------------------------------
-- CLAIM UNDER TEST
--   When a non-trusted role writes public.profiles, the 42501 comes from
--   lsp_guard_profile_role, and not from a missing grant and not from RLS.
--
-- WHY EACH STEP EXISTS
--   S5.2  the scratch role holds real table privileges -> "permission denied for
--         table profiles" (ACL-layer 42501) cannot be the cause;
--   S5.3  an explicit permissive RLS policy admits the role -> "new row violates
--         row-level security policy" (RLS 42501) cannot be the cause;
--   S5.5  POSITIVE CONTROL: with the guard trigger disabled the identical
--         statement SUCCEEDS -> privileges, RLS, the row and the statement are
--         all sufficient;
--   S5.6  with the trigger enabled the identical statement raises 42501 and the
--         message is the trigger's own text, naming the untrusted role -> the
--         trigger ran, interpolated current_user, and raised it;
--   S5.7  the trusted role succeeds on the same statement with the trigger
--         enabled -> the trigger is not failing for an unrelated reason.
--   The only difference between S5.5 and S5.6 is the trigger.
--
-- WHY current_user IS THE UNTRUSTED ROLE
--   lsp_guard_profile_role is SECURITY INVOKER (asserted in S5.0 and C1b), so
--   current_user inside it is the role executing the statement. S5.4 proves the
--   SET ROLE switch takes effect, and S5.6 proves the trigger observed it,
--   because the raised message contains the role name the trigger read from
--   current_user. A SECURITY DEFINER guard would instead see the owner (trusted)
--   and this test would silently pass — which is why S5.0 aborts in that case.
--
-- PREREQUISITES
--   * run as postgres (or a role that can CREATE ROLE, i.e. superuser or
--     CREATEROLE) — A4c confirms;
--   * public.profiles has at least one row. profiles.id has a FOREIGN KEY to
--     auth.users(id), so this test CANNOT fabricate a row; it uses an existing
--     one and S5.0 aborts with a clear message when the table is empty;
--   * no role named lsp_test_untrusted already exists (S5.1 aborts if it does,
--     so the rollback always removes what the test created).
--
-- LOCKS AND COST
--   ALTER TABLE ... DISABLE TRIGGER takes ACCESS EXCLUSIVE on public.profiles
--   for the rest of the transaction, blocking concurrent writes to profiles.
--   Run in a maintenance window. The rollback releases it.
--
-- NOT PERSISTED
--   The role, its schema/table grants, the temporary policy, the trigger enable
--   state and the no-op row update all disappear at ROLLBACK. S5.9 verifies
--   that afterwards.
-- ============================================================================

begin;

-- S5.0 Preconditions -------------------------------------------------------
do $$
declare
  v_rows    integer;
  v_invoker boolean;
begin
  -- A row with a VALID role is required, not merely any row: profiles_role_allowed
  -- is NOT VALID, so it does not police existing rows but IS enforced on every
  -- UPDATE. Testing against a legacy out-of-range row would fail the positive
  -- control with 23514 and prove nothing about the trigger.
  select count(*) into v_rows from public.profiles
  where role in ('customer','provider','admin');

  if v_rows = 0 then
    raise exception 'S5 ABORT: public.profiles has no row with a role in (customer, provider, admin). The test needs one such row (profiles.id references auth.users, so no synthetic row can be created). A9 lists the legacy rows.';
  end if;

  select not p.prosecdef into v_invoker
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = 'public' and p.proname = 'lsp_guard_profile_role';

  if v_invoker is null then
    raise exception 'S5 ABORT: public.lsp_guard_profile_role() does not exist. Run Section B first.';
  end if;
  if not v_invoker then
    raise exception 'S5 ABORT: lsp_guard_profile_role() is SECURITY DEFINER. current_user inside it would be the owner (trusted), the untrusted-role test would pass for the wrong reason, and the gate would be unenforceable for real clients.';
  end if;

  raise notice 'S5.0 OK: % profile row(s) with a valid role; guard is SECURITY INVOKER', v_rows;
end $$;

-- S5.1 Scratch untrusted role (transactional) -------------------------------
do $$
begin
  if exists (select 1 from pg_roles where rolname = 'lsp_test_untrusted') then
    raise exception 'S5 ABORT: role lsp_test_untrusted already exists. Drop it first; the test must create it so that ROLLBACK removes it.';
  end if;
  execute 'create role lsp_test_untrusted nologin';
  raise notice 'S5.1 OK: role lsp_test_untrusted created inside the transaction';
end $$;

-- S5.2 Real table privileges ----------------------------------------------
grant usage on schema public to lsp_test_untrusted;
grant select, update on public.profiles to lsp_test_untrusted;

do $$
begin
  if not has_table_privilege('lsp_test_untrusted','public.profiles','SELECT') then
    raise exception 'S5 ABORT: scratch role lacks SELECT on public.profiles';
  end if;
  if not has_table_privilege('lsp_test_untrusted','public.profiles','UPDATE') then
    raise exception 'S5 ABORT: scratch role lacks UPDATE on public.profiles';
  end if;
  raise notice 'S5.2 OK: scratch role holds SELECT and UPDATE (an ACL denial is now impossible)';
end $$;
-- INSERT is deliberately not granted: the test only needs to modify an existing
-- row, and profiles.id references auth.users so it cannot insert one anyway.

-- S5.3 RLS membership -----------------------------------------------------
-- An explicit permissive policy for this role, so RLS admits the row instead of
-- raising its own 42501. Transactional; dropped by the rollback.
drop policy if exists lsp_test_untrusted_probe on public.profiles;
create policy lsp_test_untrusted_probe on public.profiles
  for all to lsp_test_untrusted using (true) with check (true);

do $$
declare
  v_rls boolean;
begin
  select relrowsecurity into v_rls
  from pg_class where oid = 'public.profiles'::regclass;

  if v_rls then
    raise notice 'S5.3 OK: RLS is enabled and lsp_test_untrusted_probe admits the scratch role (an RLS denial is now impossible)';
  else
    raise notice 'S5.3 OK: RLS is disabled on public.profiles, so the policy is inert and the write is admitted regardless';
  end if;
end $$;

-- S5.4 The role switch really happens -------------------------------------
do $$
declare
  v_cur text;
  v_ses text;
begin
  set local role lsp_test_untrusted;
  v_cur := current_user;
  v_ses := session_user;
  reset role;

  if v_cur <> 'lsp_test_untrusted' then
    raise exception 'S5 ABORT: current_user after SET ROLE is %, expected lsp_test_untrusted', v_cur;
  end if;
  raise notice 'S5.4 OK: current_user = % while session_user = %', v_cur, v_ses;
end $$;

-- S5.5 POSITIVE CONTROL — trigger disabled, the write must SUCCEED ---------
alter table public.profiles disable trigger lsp_guard_profile_role;

do $$
declare
  v_id   uuid;
  v_rows integer;
begin
  select id into v_id from public.profiles
  where role in ('customer','provider','admin') order by id limit 1;

  set local role lsp_test_untrusted;
  execute 'update public.profiles set role = role where id = $1' using v_id;
  get diagnostics v_rows = row_count;
  reset role;

  if v_rows <> 1 then
    raise exception 'S5 FAIL: positive control updated % row(s), expected 1', v_rows;
  end if;
  raise notice 'S5.5 OK: untrusted role updated 1 row with the trigger disabled — privileges, RLS and the statement are sufficient';
end $$;

-- S5.6 NEGATIVE CONTROL — trigger enabled, the same statement must raise 42501
alter table public.profiles enable trigger lsp_guard_profile_role;

do $$
declare
  v_id    uuid;
  v_state text;
  v_msg   text;
begin
  select id into v_id from public.profiles
  where role in ('customer','provider','admin') order by id limit 1;

  set local role lsp_test_untrusted;
  begin
    execute 'update public.profiles set role = role where id = $1' using v_id;
    -- reaching here means the trigger did not reject the write
  exception when others then
    get stacked diagnostics v_state = returned_sqlstate,
                            v_msg   = message_text;
  end;
  reset role;

  if v_state is null then
    raise exception 'S5 FAIL: the untrusted update SUCCEEDED with the trigger enabled. The guard is not reached or not effective.';
  end if;
  if v_state <> '42501' then
    raise exception 'S5 FAIL: expected SQLSTATE 42501, got % (%)', v_state, v_msg;
  end if;
  if v_msg is distinct from
       'lsp_write_denied: role lsp_test_untrusted may not write public.profiles' then
    raise exception 'S5 FAIL: 42501 did not come from the role gate. Actual message: %', v_msg;
  end if;
  raise notice 'S5.6 OK: 42501 raised by lsp_guard_profile_role with current_user = lsp_test_untrusted (%)', v_msg;
end $$;

-- ATTRIBUTION, stated precisely:
--   * ACL denial would read  'permission denied for table profiles'
--   * RLS denial would read  'new row violates row-level security policy for table "profiles"'
--   * the uid gate would read 'lsp_write_denied: authenticated session without a subject'
-- The exact-match assertion above accepts only the role-gate message, and only
-- with the untrusted role's name in it — which is current_user as the trigger
-- saw it.

-- S5.7 TRUSTED CONTROL — the same statement still works for postgres -------
do $$
declare
  v_id   uuid;
  v_rows integer;
begin
  select id into v_id from public.profiles
  where role in ('customer','provider','admin') order by id limit 1;

  update public.profiles set role = role where id = v_id;
  get diagnostics v_rows = row_count;

  if v_rows <> 1 then
    raise exception 'S5 FAIL: trusted control updated % row(s), expected 1', v_rows;
  end if;
  raise notice 'S5.7 OK: current_user = % (trusted) passed the same statement with the trigger enabled', current_user;
end $$;

-- S5.8 State assertions before rollback ------------------------------------
do $$
begin
  if not exists (select 1 from pg_trigger
                 where tgrelid = 'public.profiles'::regclass
                   and tgname  = 'lsp_guard_profile_role'
                   and tgenabled = 'O') then
    raise exception 'S5 FAIL: lsp_guard_profile_role is not enabled before rollback';
  end if;
  raise notice 'S5.8 OK: trigger re-enabled; rolling back now';
end $$;

rollback;

-- S5.9 POST-ROLLBACK VERIFICATION (read-only) ------------------------------
-- Run after the rollback. Every column below must show "nothing left".
-- to_regrole() is used instead of has_table_privilege() because the latter
-- raises "role does not exist" once the rollback has removed the role — which is
-- exactly the state we want to observe.
select to_regrole('lsp_test_untrusted') is not null            as scratch_role_exists,
       (select count(*) from pg_policies
         where schemaname = 'public' and tablename = 'profiles'
           and policyname = 'lsp_test_untrusted_probe')       as probe_policy_rows,
       (select tgenabled from pg_trigger
         where tgrelid = 'public.profiles'::regclass
           and tgname   = 'lsp_guard_profile_role')           as trigger_state;
-- expect: scratch_role_exists = false, probe_policy_rows = 0, trigger_state = 'O'

-- ----------------------------------------------------------------------------
-- S6 [RECONSTRUCTED] — role immutability on UPDATE (CLIENT SESSION, not run)
-- ----------------------------------------------------------------------------
-- As a signed-in customer, PATCH /rest/v1/profiles?id=eq.<own id> with
--   {"role":"admin"}
-- expect: HTTP 200 (the write is accepted, not rejected), and
--         select role from profiles where id = auth.uid()  ->  unchanged.
-- Reason it cannot run here: the guard needs a real JWT subject; in the SQL
-- Editor auth.uid() is NULL and the gate raises 'authenticated session without
-- a subject' instead, which tests a different branch.
-- NOT EXECUTED.

-- ----------------------------------------------------------------------------
-- S7 [RECONSTRUCTED] — verification_status pinning (CLIENT SESSION, not run)
-- ----------------------------------------------------------------------------
-- As a signed-in provider with a provider_profiles row:
--   UPDATE own row SET verification_status = 'approved'
-- expect: 200, stored value unchanged ('pending' stays 'pending').
-- The INSERT branch instead COERCES an 'approved' claim to 'pending' (D.2 #21).
-- NOT EXECUTED.

-- ----------------------------------------------------------------------------
-- S8 [RECONSTRUCTED] — document status and ownership pinning (CLIENT SESSION)
-- ----------------------------------------------------------------------------
-- As a signed-in provider:
--   UPDATE own provider_documents SET status = 'approved'
--     -> 200, status unchanged
--   UPDATE own provider_documents SET provider_id = <another provider's id>
--     -> 200, provider_id unchanged (BLOCKED ATTEMPT, D.2 #19: nothing persisted)
-- Both are row-level no-ops that look like successful writes to the client,
-- which is why S8 must assert the STORED value, not the HTTP status.
-- NOT EXECUTED.

-- ----------------------------------------------------------------------------
-- S9 [RECONSTRUCTED] — approved document edit resets to pending (CLIENT SESSION)
-- ----------------------------------------------------------------------------
-- As a signed-in provider with an approved document:
--   UPDATE own provider_documents SET file_url = '<new url>' WHERE id = <approved id>
-- expect: 200, status becomes 'pending' (D.2 #23 — PERSISTED, not reversible).
-- NOT EXECUTED.

-- ----------------------------------------------------------------------------
-- S10 [RECONSTRUCTED] — document guard truth table (design; per-row as client)
-- ----------------------------------------------------------------------------
-- | tg_op  | old.status | attempted change            | stored outcome |
-- |--------|------------|-----------------------------|----------------|
-- | INSERT | n/a        | status approved/verified    | pending        |
-- | INSERT | n/a        | status rejected             | pending        |
-- | INSERT | n/a        | status pending              | pending        |
-- | INSERT | n/a        | status NULL                 | pending        |
-- | UPDATE | pending    | status approved             | pending        |
-- | UPDATE | approved   | status rejected             | approved       |
-- | UPDATE | approved   | file_url changed            | pending        |
-- | UPDATE | approved   | provider_id changed         | provider_id unchanged, status unchanged |
-- | UPDATE | rejected   | file_url changed            | file_url changed, status rejected |
-- | ANY    | ANY        | (admin session)             | returned before any pinning |
-- NOT EXECUTED.

-- ----------------------------------------------------------------------------
-- S11 [RECONSTRUCTED] — provider INSERT coercion (CLIENT SESSION, not run)
-- ----------------------------------------------------------------------------
-- As a signed-in user with no provider_profiles row:
--   INSERT INTO provider_profiles (user_id, business_name, verification_status)
--   VALUES (auth.uid(), 'X', 'approved')
-- expect: 200, stored verification_status = 'pending' (D.2 #21 — PERSISTED).
-- NOT EXECUTED.

-- ----------------------------------------------------------------------------
-- S12 [RECONSTRUCTED] — services policy is REPORT ONLY (SQL Editor, read-only)
-- ----------------------------------------------------------------------------
-- This migration deliberately does NOT change services (B6).
select policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'public' and tablename = 'services'
order by policyname;
-- expect: the permissive FOR ALL policy, using (true) with check (true) —
-- unchanged. See LIMITATION L2.

-- ----------------------------------------------------------------------------
-- S13 [RECONSTRUCTED] — per-table authorization matrix (CLIENT SESSION)
-- ----------------------------------------------------------------------------
-- Ground truth is A12's output. For every table A12 lists, as (a) anon,
-- (b) a signed-in customer, (c) a signed-in provider, (d) a signed-in admin,
-- record INSERT/UPDATE/DELETE outcomes. Compare each row with A12; any
-- difference is either a defect in this migration or a pre-existing exposure to
-- record as a limitation. Tables this migration touches: profiles,
-- provider_profiles, provider_documents. Tables it deliberately leaves alone:
-- bookings, customer_addresses, notifications, services, provider_skills.
-- NOT EXECUTED.


-- ============================================================================
-- LIMITATIONS — PRESERVED FROM REVISION 5, NOT FIXED BY THIS MIGRATION
-- ----------------------------------------------------------------------------
-- Each of these is a real exposure that survives Phase 0. They are listed here
-- so that a passing Section C and a passing Section S cannot be mistaken for a
-- clean bill of health.
-- ============================================================================

-- L1. provider_profiles SELECT exposure.
--     The provider_profiles SELECT policy is NOT touched by this migration
--     (B4.0/B4.2 replace only the INSERT and UPDATE policies). Every
--     authenticated user can read every provider row: business name, bio, city,
--     service category, years of experience, hourly rate, availability and
--     verification status. This is broad but it is what the customer browsing
--     flow depends on, so narrowing it needs a product decision, not a
--     security patch. Options for a later phase: restrict SELECT to rows with a
--     public-facing verification/availability state, or expose a curated view
--     and revoke SELECT on the table.
--     NOT FIXED HERE.

-- L2. Permissive services write policy.
--     public.services still carries FOR ALL TO authenticated USING (true)
--     WITH CHECK (true) (B6). Any signed-in user — customer or provider — can
--     insert, rewrite or delete catalogue rows. Owner-scoping is impossible on
--     the live table because it has no provider_id column; adding one is a
--     schema change that needs its own approval, and a repository check must
--     first prove no customer or provider flow writes `services`.
--     NOT FIXED HERE.

-- L3. Provider document deletion.
--     lsp_documents_owner is FOR ALL, so DELETE is granted to the owning
--     provider, and the guard trigger is BEFORE INSERT OR UPDATE only — it never
--     sees a DELETE. A provider can therefore delete their own document rows,
--     removing the evidence of a rejected or approved document and defeating the
--     review trail. There is no soft delete and no audit table.
--     NOT FIXED HERE.

-- L4. Storage-object replacement is not detectable through row-level changes.
--     The document guard compares row values. Replacing the file behind an
--     unchanged file_url — or overwriting the object at the same storage path —
--     changes no column, so the approved/verified -> pending reset (B4.5) does
--     not fire and an approved document can be swapped for different evidence.
--     Detecting it needs storage-level versioning or a content hash column,
--     neither of which this migration adds.
--     NOT FIXED HERE.

-- L5. Further limitations of this revision, stated so they are not mistaken for
--     solved problems:
--     * profiles_role_allowed is NOT VALID. No existing row was scanned or
--       rewritten, so a legacy out-of-range role keeps its value and becomes
--       un-editable (23514) until corrected deliberately (A9 lists those rows).
--     * No admin account is created. Zero admins is a valid Phase 0 state, and
--       C4 is a report, not a gate.
--     * The guard rejects any role outside its allowlist. A future custom role
--       that legitimately needs to write these tables must be added to the
--       allowlist explicitly; it fails closed until then.
--     * Blocked attempts are recorded only by raise log at LOG level, which
--       depends on log_min_messages. There is no audit table, so D.2 items 21-23
--       may have no retrievable record of which rows changed.
--     * The client-session tests (S6-S11, S13) require real signed-in accounts
--       and were NOT run. No result in this file is a passing test result.


-- ============================================================================
-- END OF PROPOSAL — REVISION 6 — NOTHING EXECUTED
-- ============================================================================
