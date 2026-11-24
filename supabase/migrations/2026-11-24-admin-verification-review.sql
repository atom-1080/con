-- ============================================================================
-- LSP Connect — admin provider-verification function (additive, idempotent)
-- ----------------------------------------------------------------------------
-- This file is NOT executed by the application and was NOT run against any
-- database. Apply it manually in the Supabase SQL editor, after
-- supabase/schema.sql, which defines public.lsp_is_admin().
--
-- Purpose: give the Admin portal one atomic, role-checked statement for
-- approving or rejecting a provider. The caller's role is re-checked inside the
-- database, so a non-administrator calling it directly is rejected with
-- SQLSTATE 42501 even if the frontend is bypassed entirely.
--
-- Applying this file is optional. src/lib/admin.js (reviewVerification) calls
-- this function when it exists and otherwise falls back to a direct UPDATE that
-- Row Level Security already restricts to administrators, so the portal works
-- either way and nothing breaks if the function is absent.
--
-- Rollback:
--   drop function if exists public.lsp_admin_review_verification(uuid, text);
-- ============================================================================

create or replace function public.lsp_admin_review_verification(
  p_provider_id uuid,
  p_status      text
)
returns public.provider_profiles
language plpgsql
security definer
set search_path = public
as $$
declare
  v_key_column text;
  v_status     text := lower(trim(coalesce(p_status, '')));
  v_row        public.provider_profiles;
begin
  if not public.lsp_is_admin() then
    raise exception 'Only administrators may review provider verification.'
      using errcode = '42501';
  end if;

  if p_provider_id is null then
    raise exception 'A provider identifier is required.' using errcode = '22023';
  end if;

  if v_status not in ('approved', 'rejected') then
    raise exception 'Unsupported verification status: %', p_status
      using errcode = '22023';
  end if;

  -- provider_profiles is keyed by id in schema.sql and by user_id in the live
  -- project, so the key column is detected rather than assumed.
  select case
           when exists (
             select 1
               from information_schema.columns
              where table_schema = 'public'
                and table_name = 'provider_profiles'
                and column_name = 'user_id'
           ) then 'user_id'
           else 'id'
         end
    into v_key_column;

  execute format(
    'update public.provider_profiles
        set verification_status = $1,
            updated_at = now()
      where %I = $2
      returning *', v_key_column)
    using v_status, p_provider_id
    into v_row;

  if v_row is null then
    raise exception 'No provider profile matches that identifier.'
      using errcode = 'P0002';
  end if;

  return v_row;
end;
$$;

revoke all on function public.lsp_admin_review_verification(uuid, text) from public;
grant execute on function public.lsp_admin_review_verification(uuid, text) to authenticated;

comment on function public.lsp_admin_review_verification(uuid, text) is
  'Admin-only provider verification decision. Re-checks lsp_is_admin() and raises 42501 for anyone else.';
