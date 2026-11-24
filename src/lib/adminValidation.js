// Pure helpers used by the Admin module. No network, no browser globals, so the
// dashboard arithmetic, pagination and input rules can be unit tested directly.
// See tests/admin-validation.test.mjs.

export function isAdminRole(role) {
  return String(role || '').trim().toLowerCase() === 'admin';
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
