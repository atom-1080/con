# LSP Connect — Admin portal

The seven approved Admin screens (28–35) are now a real module: every figure and
row comes from Supabase, and every privileged operation is authorised by the
database rather than by the browser.

The visual identity, the Customer and Provider modules, and the 35 Stitch
screens under `public/screens/` are unchanged.

## Screens

| Screen | Route | What it does |
| --- | --- | --- |
| 28 Admin login | `#/login/admin` | Supabase Auth sign-in, then a database role check. Non-admins are refused. |
| 29 Dashboard | `#/admin` | Live counts: customers, providers, pending verifications, bookings (total/active/completed), open complaints, recorded payments, plus recent activity. |
| 30 Users | `#/admin/users` | Customer and provider lists with search, pagination and a detail panel. |
| 31 Services | `#/admin/services` | Category and service catalogue with create/edit, rate validation and active flag. |
| 32 Bookings | `#/admin/bookings` | Read-only oversight with search, status and date filters and a detail panel. |
| 33 Verification | `#/admin/verification` | Pending providers, submitted documents, approve/reject with confirmation. |
| 34 Complaints | `#/admin/complaints` | Complaint list, detail and status change where the schema supports it. |
| 35 Payments | `#/admin/payments` | Monitoring only: recorded payments, totals and per-booking detail. |

## How access is enforced

1. `src/lib/admin.js` starts every call with `requireAdmin()`, which reads the
   signed-in user's `profiles` row and rejects anything whose role is not
   `admin`. The role is never read from `localStorage`, the URL or component
   state.
2. The Supabase session is the only credential used. There is no service-role
   key, secret key or privileged token anywhere in the frontend.
3. Row Level Security in `supabase/schema.sql` decides what is returned, using
   `public.lsp_is_admin()`. Widening the frontend would not widen the data.
4. Router-level role checks in `src/main.js` redirect a non-admin away from
   `/admin/*` before any admin view renders.

## Database requirements

Nothing new is required for reads and for the writes the portal performs: the
existing policies in `supabase/schema.sql` already grant administrators access
to profiles, providers, documents, services, categories, bookings, complaints
and payments, and they are the authority for every query here.

Two optional items:

- `supabase/migrations/2026-11-23-phase0-admin-security.sql` — Phase 0 guard
  triggers. Review and apply separately; it is not applied by this work.
- `supabase/migrations/2026-11-24-admin-verification-review.sql` — optional
  `lsp_admin_review_verification(uuid, text)` function that makes a
  verification decision atomic and re-checks the admin role inside the database
  (SQLSTATE `42501` otherwise). The portal detects it and falls back to a direct,
  RLS-protected update when it is absent.

Neither file was executed. Apply them in the Supabase SQL editor.

## Provisioning an administrator

There is no public administrator registration and none was added. Promote an
existing account privately, after it has signed up normally:

```sql
update public.profiles
   set role = 'admin'
 where email = 'person@example.com';
```

No admin account was created by this work.

## Environment

`SUPABASE_URL` and `SUPABASE_ANON_KEY` must be set (Settings → Environment
variables, or Connect Supabase). Without them the app shows a configuration
notice instead of pretending to have data.

## Known limitations

- `provider_profiles` is readable by customers for browsing, so a provider's row
  is visible to signed-in users; the portal does not change that policy.
- The live `services` write policy is permissive (`using (true)`). The portal
  writes through it, and it should be tightened to the owning provider plus
  admins before production use.
- Provider document deletion is not exposed; the portal only reads documents and
  records a decision on them.
- Replacing a file behind an unchanged storage path is not detectable through
  row-level changes, so a document's content is not proven identical to what was
  reviewed.
- Complaints have no resolution-notes column, so only `status` is writable.
- Bookings are read-only here by design; the customer/provider lifecycle owns
  status transitions.
- Live authorization could not be exercised without Supabase credentials and a
  real admin account, so it is unverified in this environment.
