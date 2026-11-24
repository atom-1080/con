-- ============================================================================
-- LSP Connect — AUTHORISED WRITE ACCESS
-- ----------------------------------------------------------------------------
-- Purpose: let every signed-in (authenticated) user save their own details,
-- while keeping each record isolated to its owner.
--
--   customer  -> profile, saved addresses, new bookings
--   provider  -> provider profile, skills, services, booking status changes
--   admin     -> everything (demo role)
--
-- HOW TO RUN
--   Supabase Dashboard -> SQL Editor -> New query -> paste -> Run.
--   The app's anon key can never do this, so it must be run once by you.
--
-- SAFETY
--   * CREATE TABLE IF NOT EXISTS  -> never replaces an existing table
--   * ADD COLUMN IF NOT EXISTS    -> only adds missing columns
--   * DROP POLICY IF EXISTS       -> only replaces the lsp_* policies below
--   * No DROP TABLE, no DELETE, no UPDATE of your rows. Nothing is lost.
--   * Safe to run more than once.
--
-- This file is written against the schema that is actually live in your
-- project (provider_profiles keyed by user_id, bookings using issue_description)
-- and also works on a database created fresh from supabase/schema.sql.
-- ============================================================================

create extension if not exists "pgcrypto";

-- ---------------------------------------------------------------------------
-- 1. Make sure the tables exist (skipped entirely when they already do)
-- ---------------------------------------------------------------------------
create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  role text default 'customer',
  full_name text,
  email text,
  phone text,
  city text,
  avatar_url text,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create table if not exists public.service_categories (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  icon text,
  created_at timestamptz default now()
);

create table if not exists public.provider_profiles (
  user_id uuid primary key references auth.users (id) on delete cascade,
  business_name text,
  service_category_id uuid,
  bio text,
  city text,
  years_experience integer,
  hourly_rate numeric,
  is_available boolean default true,
  verification_status text default 'pending',
  rating numeric,
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create table if not exists public.provider_skills (
  id uuid primary key default gen_random_uuid(),
  provider_id uuid,
  category_id uuid,
  name text,
  created_at timestamptz default now()
);

create table if not exists public.provider_documents (
  id uuid primary key default gen_random_uuid(),
  provider_id uuid,
  document_type text,
  file_url text,
  status text default 'pending',
  created_at timestamptz default now()
);

create table if not exists public.services (
  id uuid primary key default gen_random_uuid(),
  name text,
  description text,
  category_id uuid,
  provider_id uuid,
  title text,
  price numeric,
  duration_minutes integer,
  is_active boolean default true,
  created_at timestamptz default now()
);

create table if not exists public.customer_addresses (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid references auth.users (id) on delete cascade,
  label text,
  address_line text,
  city text,
  state text,
  postal_code text,
  is_default boolean default false,
  created_at timestamptz default now()
);

create table if not exists public.bookings (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid references auth.users (id) on delete cascade,
  provider_id uuid,
  category_id uuid,
  service_address text,
  city text,
  issue_description text,
  status text default 'pending',
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);

create table if not exists public.booking_photos (
  id uuid primary key default gen_random_uuid(),
  booking_id uuid,
  file_url text,
  caption text,
  created_at timestamptz default now()
);

create table if not exists public.quotations (
  id uuid primary key default gen_random_uuid(),
  booking_id uuid,
  provider_id uuid,
  amount numeric,
  notes text,
  status text default 'pending',
  created_at timestamptz default now()
);

create table if not exists public.payments (
  id uuid primary key default gen_random_uuid(),
  booking_id uuid,
  customer_id uuid,
  amount numeric,
  method text,
  status text default 'pending',
  created_at timestamptz default now()
);

create table if not exists public.reviews (
  id uuid primary key default gen_random_uuid(),
  booking_id uuid,
  customer_id uuid,
  provider_id uuid,
  rating integer,
  comment text,
  created_at timestamptz default now()
);

create table if not exists public.complaints (
  id uuid primary key default gen_random_uuid(),
  booking_id uuid,
  raised_by uuid,
  subject text,
  details text,
  status text default 'open',
  created_at timestamptz default now()
);

create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid,
  title text,
  body text,
  is_read boolean default false,
  created_at timestamptz default now()
);

-- ---------------------------------------------------------------------------
-- 2. Additive column repair: the columns the write policies rely on.
--    Only missing columns are added; existing values are untouched.
-- ---------------------------------------------------------------------------
do $$
declare
  spec  text;
  parts text[];
  tbl   text;
  col   text;
  typ   text;
  specs text[] := array[
    'profiles.role:text',
    'profiles.full_name:text',
    'profiles.email:text',
    'profiles.phone:text',
    'profiles.city:text',
    'profiles.updated_at:timestamptz',
    'provider_profiles.user_id:uuid',
    'provider_profiles.business_name:text',
    'provider_profiles.bio:text',
    'provider_profiles.city:text',
    'provider_profiles.service_category_id:uuid',
    'provider_profiles.years_experience:integer',
    'provider_profiles.hourly_rate:numeric',
    'provider_profiles.is_available:boolean',
    'provider_profiles.verification_status:text',
    'provider_profiles.updated_at:timestamptz',
    'provider_skills.provider_id:uuid',
    'provider_skills.category_id:uuid',
    'customer_addresses.customer_id:uuid',
    'customer_addresses.label:text',
    'customer_addresses.address_line:text',
    'customer_addresses.city:text',
    'customer_addresses.state:text',
    'customer_addresses.postal_code:text',
    'customer_addresses.is_default:boolean',
    'bookings.customer_id:uuid',
    'bookings.provider_id:uuid',
    'bookings.category_id:uuid',
    'bookings.service_address:text',
    'bookings.city:text',
    'bookings.issue_description:text',
    'bookings.status:text',
    'bookings.updated_at:timestamptz',
    'notifications.user_id:uuid',
    'notifications.title:text',
    'notifications.body:text',
    'notifications.is_read:boolean',
    'reviews.customer_id:uuid',
    'reviews.provider_id:uuid',
    'quotations.provider_id:uuid',
    'payments.customer_id:uuid',
    'complaints.raised_by:uuid',
    'services.provider_id:uuid'
  ];
begin
  foreach spec in array specs loop
    parts := string_to_array(spec, ':');
    tbl := split_part(parts[1], '.', 1);
    col := split_part(parts[1], '.', 2);
    typ := parts[2];
    if to_regclass('public.' || tbl) is not null then
      execute format('alter table public.%I add column if not exists %I %s', tbl, col, typ);
    end if;
  end loop;
end $$;

-- ---------------------------------------------------------------------------
-- 3. Helper functions (security definer avoids recursive policy checks)
-- ---------------------------------------------------------------------------
create or replace function public.lsp_role()
returns text language sql stable security definer set search_path = public as $$
  select coalesce((select role from public.profiles where id = auth.uid()), 'customer');
$$;

create or replace function public.lsp_is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select public.lsp_role() = 'admin';
$$;

-- The provider_profiles rows that belong to the signed-in user. Keyed by
-- user_id, which is the primary key in the live project.
create or replace function public.lsp_provider_ids()
returns setof uuid language sql stable security definer set search_path = public as $$
  select user_id from public.provider_profiles where user_id = auth.uid();
$$;

-- ---------------------------------------------------------------------------
-- 4. Row level security on for every table (no table is ever left open)
-- ---------------------------------------------------------------------------
do $$
declare
  t text;
begin
  foreach t in array array[
    'profiles', 'service_categories', 'provider_profiles', 'provider_skills',
    'provider_documents', 'services', 'customer_addresses', 'bookings',
    'booking_photos', 'quotations', 'payments', 'reviews', 'complaints',
    'notifications'
  ] loop
    if to_regclass('public.' || t) is not null then
      execute format('alter table public.%I enable row level security', t);
    end if;
  end loop;
end $$;

-- ---------------------------------------------------------------------------
-- 5. profiles — you may create and edit your own row
-- ---------------------------------------------------------------------------
drop policy if exists lsp_profiles_select on public.profiles;
create policy lsp_profiles_select on public.profiles for select to authenticated using (
  id = auth.uid()
  or public.lsp_is_admin()
  or exists (select 1 from public.provider_profiles p where p.user_id = profiles.id)
  or exists (
    select 1 from public.bookings b
    where (b.customer_id = auth.uid() and b.provider_id = profiles.id)
       or (b.customer_id = profiles.id and b.provider_id = auth.uid())
  )
);

drop policy if exists lsp_profiles_insert on public.profiles;
create policy lsp_profiles_insert on public.profiles for insert to authenticated
  with check (id = auth.uid());

drop policy if exists lsp_profiles_update on public.profiles;
create policy lsp_profiles_update on public.profiles for update to authenticated
  using (id = auth.uid() or public.lsp_is_admin())
  with check (id = auth.uid() or public.lsp_is_admin());

-- NOTE: this policy is row-scoped only. It does not stop a self-update of
-- {"role":"admin"}. Apply supabase/migrations/2026-11-24-role-guard-and-services-scope.sql
-- (or the identical trigger in supabase/schema.sql) to close that hole.

-- ---------------------------------------------------------------------------
-- 6. provider_profiles — providers create and edit their own listing
-- ---------------------------------------------------------------------------
drop policy if exists lsp_providers_read on public.provider_profiles;
create policy lsp_providers_read on public.provider_profiles for select using (true);

drop policy if exists lsp_providers_insert on public.provider_profiles;
create policy lsp_providers_insert on public.provider_profiles for insert to authenticated
  with check (user_id = auth.uid() or public.lsp_is_admin());

drop policy if exists lsp_providers_update on public.provider_profiles;
create policy lsp_providers_update on public.provider_profiles for update to authenticated
  using (user_id = auth.uid() or public.lsp_is_admin())
  with check (user_id = auth.uid() or public.lsp_is_admin());

-- ---------------------------------------------------------------------------
-- 7. provider_skills / provider_documents — owner write
-- ---------------------------------------------------------------------------
drop policy if exists lsp_skills_read on public.provider_skills;
create policy lsp_skills_read on public.provider_skills for select using (true);

drop policy if exists lsp_skills_write on public.provider_skills;
create policy lsp_skills_write on public.provider_skills for all to authenticated
  using (provider_id = auth.uid() or public.lsp_is_admin())
  with check (provider_id = auth.uid() or public.lsp_is_admin());

drop policy if exists lsp_documents_owner on public.provider_documents;
create policy lsp_documents_owner on public.provider_documents for all to authenticated
  using (provider_id = auth.uid() or public.lsp_is_admin())
  with check (provider_id = auth.uid() or public.lsp_is_admin());

-- ---------------------------------------------------------------------------
-- 8. services — shared catalogue, owner-or-admin writes.
--    This section previously read `using (true) with check (true)`, which let
--    any signed-in customer insert, rewrite or delete catalogue rows. That form
--    must never be re-applied. This now matches supabase/schema.sql.
-- ---------------------------------------------------------------------------
drop policy if exists lsp_services_read on public.services;
create policy lsp_services_read on public.services for select using (true);

drop policy if exists lsp_services_write on public.services;
create policy lsp_services_write on public.services for all to authenticated
  using (provider_id in (select public.lsp_provider_ids()) or public.lsp_is_admin())
  with check (provider_id in (select public.lsp_provider_ids()) or public.lsp_is_admin());

-- ---------------------------------------------------------------------------
-- 9. service_categories — readable by all, maintained by admins
-- ---------------------------------------------------------------------------
drop policy if exists lsp_categories_read on public.service_categories;
create policy lsp_categories_read on public.service_categories for select using (true);

drop policy if exists lsp_categories_write on public.service_categories;
create policy lsp_categories_write on public.service_categories for all to authenticated
  using (public.lsp_is_admin()) with check (public.lsp_is_admin());

-- ---------------------------------------------------------------------------
-- 10. customer_addresses — strictly the owner
-- ---------------------------------------------------------------------------
drop policy if exists lsp_addresses_owner on public.customer_addresses;
create policy lsp_addresses_owner on public.customer_addresses for all to authenticated
  using (customer_id = auth.uid() or public.lsp_is_admin())
  with check (customer_id = auth.uid() or public.lsp_is_admin());

-- ---------------------------------------------------------------------------
-- 11. bookings — the customer creates it, the assigned provider actions it.
--     One shared record: both sides read and update the same row.
-- ---------------------------------------------------------------------------
drop policy if exists lsp_bookings_select on public.bookings;
create policy lsp_bookings_select on public.bookings for select to authenticated using (
  customer_id = auth.uid()
  or provider_id = auth.uid()
  or public.lsp_is_admin()
);

drop policy if exists lsp_bookings_insert on public.bookings;
create policy lsp_bookings_insert on public.bookings for insert to authenticated
  with check (customer_id = auth.uid() or public.lsp_is_admin());

drop policy if exists lsp_bookings_update on public.bookings;
create policy lsp_bookings_update on public.bookings for update to authenticated
  using (customer_id = auth.uid() or provider_id = auth.uid() or public.lsp_is_admin())
  with check (customer_id = auth.uid() or provider_id = auth.uid() or public.lsp_is_admin());

-- ---------------------------------------------------------------------------
-- 12. notifications — the owner only
-- ---------------------------------------------------------------------------
drop policy if exists lsp_notifications_owner on public.notifications;
create policy lsp_notifications_owner on public.notifications for all to authenticated
  using (user_id = auth.uid() or public.lsp_is_admin())
  with check (user_id = auth.uid() or public.lsp_is_admin());

-- ---------------------------------------------------------------------------
-- 13. Booking-related tables — participants of that booking, or admins
-- ---------------------------------------------------------------------------
drop policy if exists lsp_booking_photos_access on public.booking_photos;
create policy lsp_booking_photos_access on public.booking_photos for all to authenticated
  using (
    public.lsp_is_admin() or exists (
      select 1 from public.bookings b
      where b.id = booking_photos.booking_id
        and (b.customer_id = auth.uid() or b.provider_id = auth.uid())
    )
  )
  with check (
    public.lsp_is_admin() or exists (
      select 1 from public.bookings b
      where b.id = booking_photos.booking_id
        and (b.customer_id = auth.uid() or b.provider_id = auth.uid())
    )
  );

drop policy if exists lsp_quotations_access on public.quotations;
create policy lsp_quotations_access on public.quotations for all to authenticated
  using (
    public.lsp_is_admin()
    or provider_id = auth.uid()
    or exists (select 1 from public.bookings b where b.id = quotations.booking_id and b.customer_id = auth.uid())
  )
  with check (
    public.lsp_is_admin()
    or provider_id = auth.uid()
    or exists (select 1 from public.bookings b where b.id = quotations.booking_id and b.customer_id = auth.uid())
  );

drop policy if exists lsp_payments_access on public.payments;
create policy lsp_payments_access on public.payments for all to authenticated
  using (
    public.lsp_is_admin()
    or customer_id = auth.uid()
    or exists (select 1 from public.bookings b where b.id = payments.booking_id and b.provider_id = auth.uid())
  )
  with check (
    public.lsp_is_admin()
    or customer_id = auth.uid()
    or exists (select 1 from public.bookings b where b.id = payments.booking_id and b.provider_id = auth.uid())
  );

drop policy if exists lsp_reviews_access on public.reviews;
create policy lsp_reviews_access on public.reviews for all to authenticated
  using (public.lsp_is_admin() or customer_id = auth.uid() or provider_id = auth.uid())
  with check (public.lsp_is_admin() or customer_id = auth.uid() or provider_id = auth.uid());

drop policy if exists lsp_complaints_access on public.complaints;
create policy lsp_complaints_access on public.complaints for all to authenticated
  using (
    public.lsp_is_admin()
    or raised_by = auth.uid()
    or exists (
      select 1 from public.bookings b
      where b.id = complaints.booking_id
        and (b.customer_id = auth.uid() or b.provider_id = auth.uid())
    )
  )
  with check (
    public.lsp_is_admin()
    or raised_by = auth.uid()
    or exists (
      select 1 from public.bookings b
      where b.id = complaints.booking_id
        and (b.customer_id = auth.uid() or b.provider_id = auth.uid())
    )
  );

-- ---------------------------------------------------------------------------
-- 14. Grants — RLS above still decides which rows are visible
-- ---------------------------------------------------------------------------
grant usage on schema public to anon, authenticated;
grant select, insert, update, delete on all tables in schema public to authenticated;
grant select on public.service_categories, public.provider_profiles, public.services, public.provider_skills to anon;

-- ---------------------------------------------------------------------------
-- 15. Verification — prints a summary so you can confirm it worked
--     (read-only SELECTs; they change nothing)
-- ---------------------------------------------------------------------------
select 'policies created' as check, count(*)::text as value
  from pg_policies
 where schemaname = 'public' and policyname like 'lsp\_%';

select 'tables with RLS enabled' as check, count(*)::text as value
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
 where n.nspname = 'public' and c.relkind = 'r' and c.relrowsecurity;

select 'bookings write columns' as check,
       string_agg(column_name, ', ' order by column_name) as value
  from information_schema.columns
 where table_schema = 'public' and table_name = 'bookings'
   and column_name in ('customer_id','city','issue_description',
                       'service_address','category_id','updated_at');

select 'write access by table' as check,
       tablename || ' -> ' || string_agg(distinct cmd, '/' order by cmd) as value
  from pg_policies
 where schemaname = 'public' and policyname like 'lsp\_%'
   and cmd in ('INSERT','UPDATE','ALL')
 group by tablename
 order by tablename;
