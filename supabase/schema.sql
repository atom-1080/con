-- ============================================================================
-- LSP Connect — Supabase setup / repair script
-- ----------------------------------------------------------------------------
-- Safe to run more than once on the existing project. It is NON-DESTRUCTIVE:
--   * CREATE TABLE IF NOT EXISTS  -> existing tables are left untouched
--   * ADD COLUMN IF NOT EXISTS    -> only missing columns are added
--   * DROP POLICY IF EXISTS       -> only the policies named lsp_* are replaced
--   * seeds categories only when they are missing (no duplicate rows)
-- It never drops a table, column, row or bucket, and never deletes bookings.
--
-- Two statements modify data, and both are additive:
--   * provider_profiles.user_id is filled from id where it is still empty, so
--     existing provider profiles can be linked to their auth user.
--   * service_categories receives the standard category list when missing.
--
-- Run in Supabase -> SQL Editor. Service-role keys are never needed in the app.
-- ============================================================================

create extension if not exists "pgcrypto";

-- ---------------------------------------------------------------- profiles --
create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  role text not null default 'customer',
  full_name text,
  email text,
  phone text,
  city text,
  avatar_url text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.profiles add column if not exists role text default 'customer';
alter table public.profiles add column if not exists full_name text;
alter table public.profiles add column if not exists email text;
alter table public.profiles add column if not exists phone text;
alter table public.profiles add column if not exists city text;
alter table public.profiles add column if not exists created_at timestamptz default now();
alter table public.profiles add column if not exists updated_at timestamptz default now();

-- ------------------------------------------------------- service categories --
create table if not exists public.service_categories (
  id uuid primary key default gen_random_uuid(),
  name text not null,
  description text,
  icon text,
  created_at timestamptz not null default now()
);

alter table public.service_categories add column if not exists description text;
alter table public.service_categories add column if not exists created_at timestamptz default now();

-- ------------------------------------------------------- provider profiles --
create table if not exists public.provider_profiles (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users (id) on delete cascade,
  business_name text,
  service_category_id uuid,
  bio text,
  city text,
  years_experience integer,
  hourly_rate numeric,
  is_available boolean not null default true,
  verification_status text default 'pending',
  rating numeric,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.provider_profiles add column if not exists user_id uuid;
alter table public.provider_profiles add column if not exists business_name text;
alter table public.provider_profiles add column if not exists service_category_id uuid;
alter table public.provider_profiles add column if not exists bio text;
alter table public.provider_profiles add column if not exists city text;
alter table public.provider_profiles add column if not exists years_experience integer;
alter table public.provider_profiles add column if not exists hourly_rate numeric;
alter table public.provider_profiles add column if not exists is_available boolean default true;
alter table public.provider_profiles add column if not exists verification_status text default 'pending';
alter table public.provider_profiles add column if not exists rating numeric;
alter table public.provider_profiles add column if not exists created_at timestamptz default now();
alter table public.provider_profiles add column if not exists updated_at timestamptz default now();

-- additive backfill: link existing provider rows to their auth user
update public.provider_profiles set user_id = id where user_id is null;

-- ---------------------------------------------------------- provider skills --
create table if not exists public.provider_skills (
  id uuid primary key default gen_random_uuid(),
  provider_id uuid references public.provider_profiles (id) on delete cascade,
  name text not null,
  created_at timestamptz not null default now()
);

alter table public.provider_skills add column if not exists provider_id uuid;
alter table public.provider_skills add column if not exists name text;
alter table public.provider_skills add column if not exists created_at timestamptz default now();

-- ------------------------------------------------------ provider documents --
create table if not exists public.provider_documents (
  id uuid primary key default gen_random_uuid(),
  provider_id uuid references public.provider_profiles (id) on delete cascade,
  document_type text,
  file_url text,
  status text default 'pending',
  created_at timestamptz not null default now()
);

-- ----------------------------------------------------------------- services --
create table if not exists public.services (
  id uuid primary key default gen_random_uuid(),
  provider_id uuid references public.provider_profiles (id) on delete cascade,
  title text not null,
  description text,
  price numeric,
  duration_minutes integer,
  is_active boolean not null default true,
  created_at timestamptz not null default now()
);

alter table public.services add column if not exists provider_id uuid;
alter table public.services add column if not exists title text;
alter table public.services add column if not exists description text;
alter table public.services add column if not exists price numeric;
alter table public.services add column if not exists is_active boolean default true;
alter table public.services add column if not exists created_at timestamptz default now();

-- ------------------------------------------------------- customer addresses --
create table if not exists public.customer_addresses (
  id uuid primary key default gen_random_uuid(),
  customer_id uuid references auth.users (id) on delete cascade,
  label text,
  address_line text,
  city text,
  state text,
  postal_code text,
  is_default boolean not null default false,
  created_at timestamptz not null default now()
);

alter table public.customer_addresses add column if not exists customer_id uuid;
alter table public.customer_addresses add column if not exists label text;
alter table public.customer_addresses add column if not exists address_line text;
alter table public.customer_addresses add column if not exists city text;
alter table public.customer_addresses add column if not exists state text;
alter table public.customer_addresses add column if not exists postal_code text;
alter table public.customer_addresses add column if not exists is_default boolean default false;
alter table public.customer_addresses add column if not exists created_at timestamptz default now();

-- ----------------------------------------------------------------- bookings --
-- One row per job. The customer inserts it, the assigned provider updates its
-- status; both modules read the same record.
create table if not exists public.bookings (
  id uuid primary key default gen_random_uuid(),
  client_token text,
  customer_id uuid references auth.users (id) on delete cascade,
  provider_id uuid,
  provider_profile_id uuid references public.provider_profiles (id) on delete set null,
  service_id uuid references public.services (id) on delete set null,
  category_id uuid,
  scheduled_date date,
  scheduled_time text,
  service_address text,
  description text,
  status text not null default 'pending',
  amount numeric,
  rejection_reason text,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.bookings add column if not exists client_token text;
alter table public.bookings add column if not exists customer_id uuid;
alter table public.bookings add column if not exists provider_id uuid;
alter table public.bookings add column if not exists provider_profile_id uuid;
alter table public.bookings add column if not exists service_id uuid;
alter table public.bookings add column if not exists category_id uuid;
alter table public.bookings add column if not exists scheduled_date date;
alter table public.bookings add column if not exists scheduled_time text;
alter table public.bookings add column if not exists service_address text;
alter table public.bookings add column if not exists description text;
alter table public.bookings add column if not exists status text default 'pending';
alter table public.bookings add column if not exists amount numeric;
alter table public.bookings add column if not exists rejection_reason text;
alter table public.bookings add column if not exists created_at timestamptz default now();
alter table public.bookings add column if not exists updated_at timestamptz default now();

-- duplicate-submission guard (one booking per client token)
create unique index if not exists bookings_client_token_key
  on public.bookings (client_token) where client_token is not null;
create index if not exists bookings_customer_idx on public.bookings (customer_id);
create index if not exists bookings_provider_idx on public.bookings (provider_id);

-- ---------------------------------------------------------- related tables --
create table if not exists public.booking_photos (
  id uuid primary key default gen_random_uuid(),
  booking_id uuid references public.bookings (id) on delete cascade,
  file_url text,
  caption text,
  created_at timestamptz not null default now()
);

create table if not exists public.quotations (
  id uuid primary key default gen_random_uuid(),
  booking_id uuid references public.bookings (id) on delete cascade,
  provider_id uuid,
  amount numeric,
  notes text,
  status text default 'pending',
  created_at timestamptz not null default now()
);

create table if not exists public.payments (
  id uuid primary key default gen_random_uuid(),
  booking_id uuid references public.bookings (id) on delete cascade,
  customer_id uuid,
  amount numeric,
  method text,
  status text default 'pending',
  created_at timestamptz not null default now()
);

create table if not exists public.reviews (
  id uuid primary key default gen_random_uuid(),
  booking_id uuid references public.bookings (id) on delete cascade,
  customer_id uuid,
  provider_id uuid,
  rating integer,
  comment text,
  created_at timestamptz not null default now()
);

create table if not exists public.complaints (
  id uuid primary key default gen_random_uuid(),
  booking_id uuid references public.bookings (id) on delete set null,
  raised_by uuid,
  subject text,
  details text,
  status text default 'open',
  created_at timestamptz not null default now()
);

create table if not exists public.notifications (
  id uuid primary key default gen_random_uuid(),
  user_id uuid,
  title text,
  body text,
  is_read boolean not null default false,
  created_at timestamptz not null default now()
);

-- ------------------------------------------------------------- helper fns --
-- Security-definer helpers keep policies simple and avoid recursive RLS.
create or replace function public.lsp_role()
returns text language sql stable security definer set search_path = public as $$
  select coalesce((select role from public.profiles where id = auth.uid()), 'customer');
$$;

create or replace function public.lsp_is_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select public.lsp_role() = 'admin';
$$;

-- provider_profiles rows owned by the signed-in user (id may equal user_id)
create or replace function public.lsp_provider_ids()
returns setof uuid language sql stable security definer set search_path = public as $$
  select id from public.provider_profiles where user_id = auth.uid() or id = auth.uid();
$$;

-- -------------------------------------------------------------------- RLS ---
alter table public.profiles enable row level security;
alter table public.service_categories enable row level security;
alter table public.provider_profiles enable row level security;
alter table public.provider_skills enable row level security;
alter table public.provider_documents enable row level security;
alter table public.services enable row level security;
alter table public.customer_addresses enable row level security;
alter table public.bookings enable row level security;
alter table public.booking_photos enable row level security;
alter table public.quotations enable row level security;
alter table public.payments enable row level security;
alter table public.reviews enable row level security;
alter table public.complaints enable row level security;
alter table public.notifications enable row level security;

-- profiles: own row, provider listings, and people you share a booking with
drop policy if exists lsp_profiles_select on public.profiles;
create policy lsp_profiles_select on public.profiles for select to authenticated using (
  id = auth.uid()
  or public.lsp_is_admin()
  or exists (select 1 from public.provider_profiles p where p.user_id = profiles.id or p.id = profiles.id)
  or exists (
    select 1 from public.bookings b
    where (b.customer_id = auth.uid() and (b.provider_id = profiles.id or b.provider_profile_id = profiles.id))
       or (b.customer_id = profiles.id and (b.provider_id = auth.uid() or b.provider_profile_id in (select public.lsp_provider_ids())))
  )
);

drop policy if exists lsp_profiles_insert on public.profiles;
create policy lsp_profiles_insert on public.profiles for insert to authenticated
  with check (id = auth.uid());

drop policy if exists lsp_profiles_update on public.profiles;
create policy lsp_profiles_update on public.profiles for update to authenticated
  using (id = auth.uid() or public.lsp_is_admin())
  with check (id = auth.uid() or public.lsp_is_admin());

-- Role escalation guard. RLS is row-scoped and has no column-level policies, so
-- lsp_profiles_update alone cannot stop a self-update of {"role":"admin"}. Only
-- a BEFORE trigger sees OLD and NEW. The role is pinned on UPDATE (so
-- api.js ensureProfile(), which echoes `role` on every save, keeps working) and
-- new rows are limited to customer/provider. Privileged role changes happen only
-- through the trusted administrative process (SQL Editor / service_role).
-- Mirrors supabase/migrations/2026-11-24-role-guard-and-services-scope.sql.
create or replace function public.lsp_guard_profile_role()
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
    raise exception 'lsp_write_denied: role % may not write public.profiles', api_role
      using errcode = '42501';
  end if;

  if (select auth.uid()) is null then
    raise exception 'lsp_write_denied: authenticated session without a subject'
      using errcode = '42501';
  end if;

  if tg_op = 'INSERT' then
    if new.role is null then
      new.role := 'customer';
    end if;
    if new.role not in ('customer','provider') then
      raise exception 'lsp_role_escalation_blocked: cannot create a profile with role %', new.role
        using errcode = '42501';
    end if;
    return new;
  end if;

  if new.role is distinct from old.role then
    new.role := old.role;
  end if;
  return new;
end $$;

drop trigger if exists lsp_guard_profile_role on public.profiles;
create trigger lsp_guard_profile_role before insert or update on public.profiles
  for each row execute function public.lsp_guard_profile_role();

-- categories: readable by everyone, maintained by admins
drop policy if exists lsp_categories_read on public.service_categories;
create policy lsp_categories_read on public.service_categories for select using (true);

drop policy if exists lsp_categories_write on public.service_categories;
create policy lsp_categories_write on public.service_categories for all to authenticated
  using (public.lsp_is_admin()) with check (public.lsp_is_admin());

-- provider listings are public to signed-in users
drop policy if exists lsp_providers_read on public.provider_profiles;
create policy lsp_providers_read on public.provider_profiles for select using (true);

drop policy if exists lsp_providers_insert on public.provider_profiles;
create policy lsp_providers_insert on public.provider_profiles for insert to authenticated
  with check (user_id = auth.uid() or id = auth.uid());

drop policy if exists lsp_providers_update on public.provider_profiles;
create policy lsp_providers_update on public.provider_profiles for update to authenticated
  using (user_id = auth.uid() or id = auth.uid() or public.lsp_is_admin())
  with check (user_id = auth.uid() or id = auth.uid() or public.lsp_is_admin());

-- services & skills: public read, owner write
drop policy if exists lsp_services_read on public.services;
create policy lsp_services_read on public.services for select using (true);

drop policy if exists lsp_services_write on public.services;
create policy lsp_services_write on public.services for all to authenticated
  using (provider_id in (select public.lsp_provider_ids()) or public.lsp_is_admin())
  with check (provider_id in (select public.lsp_provider_ids()) or public.lsp_is_admin());

drop policy if exists lsp_skills_read on public.provider_skills;
create policy lsp_skills_read on public.provider_skills for select using (true);

drop policy if exists lsp_skills_write on public.provider_skills;
create policy lsp_skills_write on public.provider_skills for all to authenticated
  using (provider_id in (select public.lsp_provider_ids()) or public.lsp_is_admin())
  with check (provider_id in (select public.lsp_provider_ids()) or public.lsp_is_admin());

drop policy if exists lsp_documents_owner on public.provider_documents;
create policy lsp_documents_owner on public.provider_documents for all to authenticated
  using (provider_id in (select public.lsp_provider_ids()) or public.lsp_is_admin())
  with check (provider_id in (select public.lsp_provider_ids()) or public.lsp_is_admin());

-- addresses: strictly the owner
drop policy if exists lsp_addresses_owner on public.customer_addresses;
create policy lsp_addresses_owner on public.customer_addresses for all to authenticated
  using (customer_id = auth.uid() or public.lsp_is_admin())
  with check (customer_id = auth.uid() or public.lsp_is_admin());

-- bookings: the customer creates it, the assigned provider actions it
drop policy if exists lsp_bookings_select on public.bookings;
create policy lsp_bookings_select on public.bookings for select to authenticated using (
  customer_id = auth.uid()
  or provider_id = auth.uid()
  or provider_profile_id in (select public.lsp_provider_ids())
  or public.lsp_is_admin()
);

drop policy if exists lsp_bookings_insert on public.bookings;
create policy lsp_bookings_insert on public.bookings for insert to authenticated
  with check (customer_id = auth.uid());

drop policy if exists lsp_bookings_update on public.bookings;
create policy lsp_bookings_update on public.bookings for update to authenticated
  using (
    customer_id = auth.uid()
    or provider_id = auth.uid()
    or provider_profile_id in (select public.lsp_provider_ids())
    or public.lsp_is_admin()
  )
  with check (
    customer_id = auth.uid()
    or provider_id = auth.uid()
    or provider_profile_id in (select public.lsp_provider_ids())
    or public.lsp_is_admin()
  );

-- photos follow the booking they belong to
drop policy if exists lsp_booking_photos_access on public.booking_photos;
create policy lsp_booking_photos_access on public.booking_photos for all to authenticated
  using (
    exists (
      select 1 from public.bookings b
      where b.id = booking_photos.booking_id
        and (b.customer_id = auth.uid() or b.provider_id = auth.uid() or public.lsp_is_admin())
    )
  )
  with check (
    exists (
      select 1 from public.bookings b
      where b.id = booking_photos.booking_id
        and (b.customer_id = auth.uid() or b.provider_id = auth.uid() or public.lsp_is_admin())
    )
  );

-- notifications: the owner only
drop policy if exists lsp_notifications_owner on public.notifications;
create policy lsp_notifications_owner on public.notifications for all to authenticated
  using (user_id = auth.uid() or public.lsp_is_admin())
  with check (user_id = auth.uid() or public.lsp_is_admin());

-- remaining demo tables: participants of the booking or admins
do $$
declare
  t text;
begin
  foreach t in array array['quotations', 'payments', 'reviews', 'complaints'] loop
    execute format('drop policy if exists lsp_%s_access on public.%I', t, t);
    execute format(
      'create policy lsp_%s_access on public.%I for all to authenticated using (public.lsp_is_admin()) with check (public.lsp_is_admin())',
      t, t
    );
  end loop;
end $$;

-- ------------------------------------------------------------------ grants --
grant usage on schema public to anon, authenticated;
grant select, insert, update, delete on all tables in schema public to authenticated;
grant select on public.service_categories, public.provider_profiles, public.services, public.provider_skills to anon;

-- ------------------------------------------------------- category seed data --
insert into public.service_categories (name, description)
select v.name, v.description
from (values
  ('Plumbing', 'Leaks, pipes, taps and drainage'),
  ('Electrical', 'Wiring, sockets, lighting and faults'),
  ('Cleaning', 'Domestic and office cleaning'),
  ('Carpentry', 'Furniture, doors and fittings'),
  ('Painting', 'Interior and exterior painting'),
  ('Appliance Repair', 'Fridges, cookers and washing machines'),
  ('Gardening', 'Lawns, hedges and landscaping'),
  ('Moving & Delivery', 'Packing, moving and transport')
) as v(name, description)
where not exists (
  select 1 from public.service_categories c where lower(c.name) = lower(v.name)
);

-- ---------------------------------------------------------- admin demo role --
-- Create the admin account through Supabase Authentication (or the app), then:
--   update public.profiles set role = 'admin' where email = 'admin@lspconnect.app';
-- Public registration in the app only ever creates customer or provider roles.
