// Pure helpers used by the Admin module. No network, no browser globals, so the
// dashboard arithmetic, pagination and input rules can be unit tested directly.
// See tests/admin-validation.test.mjs.

export function isAdminRole(role) {
  return String(role || '').trim().toLowerCase() === 'admin';
}

/* ------------------------------------------------------- authorization model */
// Mirrors the database rules in
// supabase/migrations/2026-11-24-role-guard-and-services-scope.sql so the same
// decisions can be unit tested without a live database. The database remains
// the authority: these helpers only keep the UI from offering an action the
// server would refuse.

export const PROFILE_ROLES = ['customer', 'provider', 'admin'];

// Signed document URLs are an administrator-only capability.
export function canMintDocumentLink(role) {
  return isAdminRole(role);
}

// `trustedProcess` represents the SQL Editor / service_role path, the only one
// the guard trigger allows to change a role. No browser session can set it.
export function resolveProfileRoleChange({
  actorId,
  targetId,
  currentRole,
  nextRole,
  trustedProcess = false,
} = {}) {
  const current = String(currentRole || 'customer').trim().toLowerCase() || 'customer';
  const next =
    nextRole === undefined || nextRole === null || nextRole === ''
      ? current
      : String(nextRole).trim().toLowerCase();

  if (next === current) return { allowed: true, persistedRole: current, reason: '' };

  if (!PROFILE_ROLES.includes(next)) {
    return { allowed: false, persistedRole: current, reason: `Unknown role: ${next}.` };
  }

  const sameUser = String(actorId || '') !== '' && String(actorId) === String(targetId || '');
  if (sameUser && !trustedProcess) {
    return {
      allowed: false,
      persistedRole: current,
      reason: 'You cannot change your own role. Ask an administrator to provision it.',
    };
  }

  if (!trustedProcess) {
    return {
      allowed: false,
      persistedRole: current,
      reason: 'Roles can only be changed by a trusted administrative process.',
    };
  }

  return { allowed: true, persistedRole: next, reason: '' };
}

/* ------------------------------------------------- trusted-session model */
// Mirrors the trigger in
// supabase/migrations/2026-11-25-role-guard-trusted-session.sql.
//
// The database decides authority from the SESSION identity, never from the
// effective identity: `current_user` becomes the function owner inside a
// SECURITY DEFINER function, so trusting it let any definer function owned by
// postgres change a role on behalf of an ordinary caller. `session_user` is the
// login role and is not changed by SECURITY DEFINER or SET ROLE.
//
// Nothing here reads a JWT claim, a header, a custom GUC, localStorage or the
// frontend role. Those are user-controlled and are never proof of privilege.
// The API-request flag mirrors PostgREST setting request.jwt.claims /
// request.method, and it can only ever REMOVE trust.

export const API_ROLES = [
  'anon',
  'authenticated',
  'authenticator',
  'service_role',
  'supabase_storage_admin',
  'supabase_auth_admin',
];

export function isTrustedAdminSession({
  sessionUser,
  currentUser,
  apiRequest = false,
  isSuperuser = false,
  isProvisioner = false,
} = {}) {
  const session = String(sessionUser || '').trim();
  const current = String(currentUser || '').trim();

  // No elevation in effect: this is false inside every SECURITY DEFINER call
  // made by an application role, which is what closes the ownership bypass.
  if (session === '' || session !== current) return false;
  // An API request is never an administration session.
  if (apiRequest) return false;
  // An API role is never an administration session, even with membership.
  if (API_ROLES.includes(current)) return false;
  return isSuperuser === true || isProvisioner === true;
}

// The full decision the BEFORE trigger makes, as a pure function.
//   action 'allow' -> the write proceeds with persistedRole
//   action 'pin'   -> the write proceeds but the role is held at its old value
//   action 'deny'  -> the statement fails (code 42501, or 22023 for a bad value)
export function roleWriteDecision({
  sessionUser,
  currentUser,
  apiRequest = false,
  isSuperuser = false,
  isProvisioner = false,
  operation = 'update',
  oldRole = null,
  newRole = null,
} = {}) {
  const previous = oldRole === null || oldRole === undefined ? null : String(oldRole).trim().toLowerCase();
  const requested =
    newRole === null || newRole === undefined || newRole === ''
      ? previous || 'customer'
      : String(newRole).trim().toLowerCase();

  const trusted = isTrustedAdminSession({ sessionUser, currentUser, apiRequest, isSuperuser, isProvisioner });

  if (trusted) {
    if (!PROFILE_ROLES.includes(requested)) {
      return { action: 'deny', persistedRole: previous, code: '22023', reason: `Unknown role: ${requested}.` };
    }
    return { action: 'allow', persistedRole: requested, code: null, reason: '' };
  }

  // PostgREST's login role never runs DML itself.
  if (String(currentUser || '').trim() === 'authenticator') {
    return {
      action: 'deny',
      persistedRole: previous,
      code: '42501',
      reason: 'The API login role may not write public.profiles.',
    };
  }

  if (operation === 'insert') {
    if (!['customer', 'provider'].includes(requested)) {
      return {
        action: 'deny',
        persistedRole: previous,
        code: '42501',
        reason: 'A profile cannot be created with a privileged role.',
      };
    }
    return { action: 'allow', persistedRole: requested, code: null, reason: '' };
  }

  if (previous !== null && requested !== previous) {
    return {
      action: 'pin',
      persistedRole: previous,
      code: null,
      reason: 'Role changes are restricted to database administration sessions.',
    };
  }

  return { action: 'allow', persistedRole: previous === null ? requested : previous, code: null, reason: '' };
}

// Owner-or-admin, matching the lsp_services_write policy. When the catalogue has
// no owner column the policy is admin-only, so a provider row is refused there
// and provider catalogue work happens in provider_skills instead.
export function canWriteServiceRow({
  role,
  providerIds = [],
  row = {},
  hasOwnerColumn = true,
} = {}) {
  if (isAdminRole(role)) return true;
  if (!hasOwnerColumn) return false;
  if (String(role || '').trim().toLowerCase() !== 'provider') return false;

  const owner = String(row?.providerId ?? row?.provider_id ?? '').trim();
  if (!owner) return false; // an unowned catalogue row is admin-only

  return (Array.isArray(providerIds) ? providerIds : []).map((id) => String(id)).includes(owner);
}

/* ------------------------------------------------------------- validation */

export function validateCategoryInput({ name } = {}, existing = [], currentId = '') {
  const clean = String(name || '').trim().replace(/\s+/g, ' ');
  if (!clean) return { ok: false, error: 'Enter a category name.' };
  if (clean.length > 80) return { ok: false, error: 'Keep the category name to 80 characters or fewer.' };
  const clash = existing.find(
    (category) =>
      String(category?.name || '').trim().toLowerCase() === clean.toLowerCase() &&
      String(category?.id || '') !== String(currentId || ''),
  );
  if (clash) return { ok: false, error: `A category named “${clean}” already exists.` };
  return { ok: true, value: { name: clean } };
}

export function validateServiceInput({ title, price } = {}, existing = [], currentId = '') {
  const clean = String(title || '').trim().replace(/\s+/g, ' ');
  if (!clean) return { ok: false, error: 'Enter a service name.' };
  if (clean.length > 120) return { ok: false, error: 'Keep the service name to 120 characters or fewer.' };

  let amount = null;
  if (price !== '' && price !== null && price !== undefined) {
    amount = Number(price);
    if (!Number.isFinite(amount)) return { ok: false, error: 'Enter the standard rate as a number.' };
    if (amount < 0) return { ok: false, error: 'The standard rate cannot be negative.' };
  }

  const clash = existing.find(
    (service) =>
      String(service?.title || '').trim().toLowerCase() === clean.toLowerCase() &&
      String(service?.id || '') !== String(currentId || ''),
  );
  if (clash) return { ok: false, error: `A service named “${clean}” already exists in the catalogue.` };

  return { ok: true, value: { title: clean, price: amount } };
}

/* ------------------------------------------------------------- pagination */

export function pageCount(total, perPage) {
  const size = Math.max(1, Number(perPage) || 1);
  return Math.max(1, Math.ceil(Math.max(0, Number(total) || 0) / size));
}

export function paginate(items, page = 1, perPage = 10) {
  const list = Array.isArray(items) ? items : [];
  const size = Math.max(1, Number(perPage) || 10);
  const pages = pageCount(list.length, size);
  const current = Math.min(Math.max(1, Number(page) || 1), pages);
  const start = (current - 1) * size;
  return { rows: list.slice(start, start + size), page: current, pages, total: list.length };
}

/* --------------------------------------------------------------- statuses */

const COMPLAINT_FALLBACK = 'open';

// Only statuses already recorded in the database are offered, so the module
// never invents a workflow value the schema does not use.
export function complaintStatusOptions(rows = []) {
  const seen = new Set();
  for (const row of Array.isArray(rows) ? rows : []) {
    const value = String(row?.status || '')
      .trim()
      .toLowerCase()
      .replace(/[\s-]+/g, '_');
    if (value) seen.add(value);
  }
  seen.add(COMPLAINT_FALLBACK);
  return [...seen].sort();
}

export function bookingStatusOptions(rows = []) {
  const seen = new Set();
  for (const row of Array.isArray(rows) ? rows : []) {
    const value = String(row?.status || '')
      .trim()
      .toLowerCase()
      .replace(/[\s-]+/g, '_');
    if (value) seen.add(value);
  }
  return [...seen].sort();
}

/* --------------------------------------------------------------- payments */

const PAID_STATUSES = new Set(['paid', 'complete', 'completed', 'settled', 'captured', 'succeeded']);

export function isPaidStatus(status) {
  return PAID_STATUSES.has(String(status || '').trim().toLowerCase());
}

export function summarizePayments(rows = []) {
  const list = Array.isArray(rows) ? rows : [];
  const totals = { count: list.length, paidCount: 0, recorded: 0, methods: {} };
  for (const row of list) {
    if (isPaidStatus(row?.status)) {
      totals.paidCount += 1;
      const amount = Number(row?.amount);
      if (Number.isFinite(amount)) totals.recorded += amount;
    }
    const method = String(row?.method || '').trim().toLowerCase() || 'unspecified';
    totals.methods[method] = (totals.methods[method] || 0) + 1;
  }
  totals.recorded = Math.round(totals.recorded * 100) / 100;
  return totals;
}

/* -------------------------------------------------------------- dashboard */

const ACTIVE_BOOKING_STATUSES = new Set(['accepted', 'in_progress']);
const COMPLETED_BOOKING_STATUSES = new Set(['completed']);
const OPEN_COMPLAINT_STATUSES = new Set(['open', 'in_review', 'investigating', 'pending']);
const PENDING_VERIFICATION_STATUSES = new Set(['', 'pending', 'submitted', 'under_review', 'awaiting_review']);

export function isPendingVerification(status) {
  return PENDING_VERIFICATION_STATUSES.has(String(status || '').trim().toLowerCase());
}

// Every figure is a direct count of rows the admin can actually read. Nothing is
// estimated: a table that could not be read contributes 0 and is reported by the
// caller through its error list.
export function computeDashboardMetrics({
  profiles = [],
  providers = [],
  bookings = [],
  complaints = [],
  payments = [],
} = {}) {
  const profileList = Array.isArray(profiles) ? profiles : [];
  const providerList = Array.isArray(providers) ? providers : [];
  const bookingList = Array.isArray(bookings) ? bookings : [];
  const complaintList = Array.isArray(complaints) ? complaints : [];
  const paymentList = Array.isArray(payments) ? payments : [];

  const normalise = (value) =>
    String(value || '')
      .trim()
      .toLowerCase()
      .replace(/[\s-]+/g, '_');

  return {
    customers: profileList.filter((profile) => normalise(profile?.role) === 'customer').length,
    providers: providerList.length,
    pendingVerifications: providerList.filter((provider) => isPendingVerification(provider?.verificationStatus))
      .length,
    bookings: bookingList.length,
    activeBookings: bookingList.filter((booking) => ACTIVE_BOOKING_STATUSES.has(normalise(booking?.status))).length,
    completedBookings: bookingList.filter((booking) =>
      COMPLETED_BOOKING_STATUSES.has(normalise(booking?.status)),
    ).length,
    pendingComplaints: complaintList.filter((complaint) =>
      OPEN_COMPLAINT_STATUSES.has(normalise(complaint?.status) || 'open'),
    ).length,
    payments: paymentList.length,
    paymentsRecorded: summarizePayments(paymentList).recorded,
  };
}

export function uniqueById(rows = []) {
  const seen = new Set();
  const out = [];
  for (const row of Array.isArray(rows) ? rows : []) {
    const key = String(row?.id ?? '');
    if (!key || seen.has(key)) continue;
    seen.add(key);
    out.push(row);
  }
  return out;
}
