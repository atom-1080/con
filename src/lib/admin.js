// Admin data layer for LSP Connect.
//
// Every read and write starts by verifying the signed-in user's role in the
// database. The role is never taken from localStorage, the URL or component
// state, and no service-role key exists in this code: the anon key plus the RLS
// policies in supabase/schema.sql (which call public.lsp_is_admin()) decide what
// an administrator may actually see or change.

import { supabase, isSupabaseConfigured } from './supabaseClient.js';
import { insertRow, updateRow, updateProviderProfile, DataError } from './api.js';
import {
  normalizeProfile,
  normalizeProvider,
  normalizeCategory,
  normalizeService,
  normalizeBooking,
  pick,
} from './rows.js';
import {
  computeDashboardMetrics,
  isPendingVerification,
  summarizePayments,
  uniqueById,
} from './adminValidation.js';

export class AdminAccessError extends Error {
  constructor(message = 'Administrator access is required.') {
    super(message);
    this.name = 'AdminAccessError';
    this.code = 'NOT_ADMIN';
  }
}

function client() {
  if (!isSupabaseConfigured || !supabase) {
    throw new Error('Supabase is not configured. Add SUPABASE_URL and SUPABASE_ANON_KEY.');
  }
  return supabase;
}

async function readTable(table, errors) {
  const { data, error } = await client().from(table).select('*');
  if (error) {
    if (errors) errors.push({ table, message: error.message, code: error.code });
    return [];
  }
  return Array.isArray(data) ? data : [];
}

/* ------------------------------------------------------------ authorization */

// Confirms the current session belongs to an administrator by reading the role
// column of the caller's own profile row. Throws AdminAccessError otherwise, so a
// stale or forged frontend state can never open the module.
export async function requireAdmin() {
  const { data: sessionData, error: sessionError } = await client().auth.getSession();
  if (sessionError) throw new AdminAccessError('Your session could not be read. Sign in again.');
  const session = sessionData?.session || null;
  if (!session?.user) throw new AdminAccessError('Sign in with an administrator account to continue.');

  const { data, error } = await client()
    .from('profiles')
    .select('id, role, full_name, email, phone, created_at')
    .eq('id', session.user.id)
    .maybeSingle();

  if (error) {
    throw new AdminAccessError(
      `Your administrator role could not be verified (${error.message}). Check the profiles policies.`,
    );
  }
  if (!data) throw new AdminAccessError('This account has no profile, so administrator access is refused.');
  if (String(data.role || '').trim().toLowerCase() !== 'admin') {
    throw new AdminAccessError('This account does not have the administrator role.');
  }

  return { session, profile: normalizeProfile(data), role: 'admin' };
}

/* -------------------------------------------------------------- normalizers */

function normalizeComplaint(row) {
  if (!row) return null;
  return {
    id: row.id,
    bookingId: pick(row, 'booking_id') ?? null,
    raisedBy: pick(row, 'raised_by', 'customer_id', 'user_id') ?? null,
    subject: pick(row, 'subject', 'title') || 'Complaint',
    details: pick(row, 'details', 'description', 'message', 'body') || '',
    status: String(pick(row, 'status', 'complaint_status') || 'open').toLowerCase(),
    createdAt: pick(row, 'created_at', 'inserted_at', 'created') || '',
    raw: row,
  };
}

function normalizeDocument(row) {
  if (!row) return null;
  return {
    id: row.id,
    providerId: pick(row, 'provider_id', 'user_id') ?? null,
    type: pick(row, 'document_type', 'type', 'title') || 'Document',
    fileUrl: pick(row, 'file_url', 'url', 'document_url', 'path') || '',
    status: String(pick(row, 'status', 'document_status') || 'pending').toLowerCase(),
    createdAt: pick(row, 'created_at', 'uploaded_at', 'created') || '',
    raw: row,
  };
}

function normalizePayment(row) {
  if (!row) return null;
  return {
    id: row.id,
    bookingId: pick(row, 'booking_id') ?? null,
    customerId: pick(row, 'customer_id', 'user_id') ?? null,
    amount: pick(row, 'amount', 'total_amount', 'price') ?? null,
    method: pick(row, 'method', 'payment_method', 'channel') || '',
    status: String(pick(row, 'status', 'payment_status') || 'pending').toLowerCase(),
    createdAt: pick(row, 'created_at', 'paid_at', 'inserted_at', 'created') || '',
    raw: row,
  };
}

const shortId = (value) => String(value || '').slice(0, 8).toUpperCase();

/* ---------------------------------------------------------------- dashboard */

export async function loadDashboard() {
  await requireAdmin();
  const errors = [];
  const [profileRows, providerRows, bookingRows, complaintRows, paymentRows, categoryRows] = await Promise.all([
    readTable('profiles', errors),
    readTable('provider_profiles', errors),
    readTable('bookings', errors),
    readTable('complaints', errors),
    readTable('payments', errors),
    readTable('service_categories', errors),
  ]);

  const profiles = profileRows.map(normalizeProfile).filter(Boolean);
  const providers = providerRows.map(normalizeProvider).filter(Boolean);
  const bookings = uniqueById(bookingRows.map(normalizeBooking).filter(Boolean));
  const complaints = uniqueById(complaintRows.map(normalizeComplaint).filter(Boolean));
  const payments = uniqueById(paymentRows.map(normalizePayment).filter(Boolean));
  const categories = categoryRows.map(normalizeCategory).filter(Boolean);

  const metrics = computeDashboardMetrics({ profiles, providers, bookings, complaints, payments });

  const activity = [
    ...bookings.map((booking) => ({
      id: `booking-${booking.id}`,
      at: booking.createdAt,
      kind: 'Booking',
      title: `Booking ${shortId(booking.id)}`,
      detail: booking.status,
      href: `/admin/bookings?id=${encodeURIComponent(booking.id)}`,
    })),
    ...complaints.map((complaint) => ({
      id: `complaint-${complaint.id}`,
      at: complaint.createdAt,
      kind: 'Complaint',
      title: complaint.subject,
      detail: complaint.status,
      href: `/admin/complaints?id=${encodeURIComponent(complaint.id)}`,
    })),
    ...payments.map((payment) => ({
      id: `payment-${payment.id}`,
      at: payment.createdAt,
      kind: 'Payment',
      title: `Payment ${shortId(payment.id)}`,
      detail: payment.status,
      href: `/admin/payments?id=${encodeURIComponent(payment.id)}`,
    })),
  ]
    .filter((entry) => entry.at)
    .sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime())
    .slice(0, 10);

  return { metrics, activity, categories, errors };
}

/* -------------------------------------------------------------------- users */

export async function loadUsers() {
  await requireAdmin();
  const errors = [];
  const [profileRows, providerRows, categoryRows, documentRows, bookingRows] = await Promise.all([
    readTable('profiles', errors),
    readTable('provider_profiles', errors),
    readTable('service_categories', errors),
    readTable('provider_documents', errors),
    readTable('bookings', errors),
  ]);

  const categories = categoryRows.map(normalizeCategory).filter(Boolean);
  const categoryById = new Map(categories.map((category) => [String(category.id), category]));
  const profileById = new Map(profileRows.map((row) => [String(row.id), normalizeProfile(row)]));
  const bookings = bookingRows.map(normalizeBooking).filter(Boolean);

  const customers = profilesOf(profileRows)
    .filter((profile) => String(profile.role || '').toLowerCase() !== 'admin')
    .filter((profile) => String(profile.role || '').toLowerCase() !== 'provider')
    .map((profile) => ({
      ...profile,
      createdAt: pick(profile.raw, 'created_at', 'inserted_at', 'created') || '',
      bookingCount: bookings.filter((booking) => String(booking.customerId) === String(profile.id)).length,
    }))
    .sort((a, b) => String(a.fullName || a.email).localeCompare(String(b.fullName || b.email)));

  const providers = providerRows
    .map(normalizeProvider)
    .filter(Boolean)
    .map((provider) => {
      const profile = profileById.get(String(provider.userId)) || null;
      const category = categoryById.get(String(provider.categoryId)) || null;
      const documents = documentRows
        .filter((row) => String(row.provider_id ?? row.user_id ?? '') === String(provider.userId))
        .map(normalizeDocument)
        .filter(Boolean);
      return {
        ...provider,
        profile,
        fullName: profile?.fullName || '',
        email: profile?.email || '',
        phone: profile?.phone || '',
        categoryName: category?.name || '',
        createdAt: pick(provider.raw, 'created_at', 'inserted_at', 'created') || '',
        documents,
        jobs: bookings.filter(
          (booking) =>
            String(booking.providerId || '') === String(provider.userId) ||
            String(booking.providerId || '') === String(provider.id),
        ).length,
        displayName: provider.businessName || profile?.fullName || 'Service provider',
      };
    })
    .sort((a, b) => String(a.displayName).localeCompare(String(b.displayName)));

  return { customers, providers, categories, errors };
}

function profilesOf(rows) {
  return rows
    .map((row) => {
      const profile = normalizeProfile(row);
      if (!profile) return null;
      return { ...profile, createdAt: pick(row, 'created_at', 'inserted_at', 'created') || '' };
    })
    .filter(Boolean);
}

/* ----------------------------------------------------------------- services */

export async function loadCatalogue() {
  await requireAdmin();
  const errors = [];
  const [categoryRows, serviceRows, providerRows] = await Promise.all([
    readTable('service_categories', errors),
    readTable('services', errors),
    readTable('provider_profiles', errors),
  ]);

  const categories = categoryRows
    .map(normalizeCategory)
    .filter(Boolean)
    .sort((a, b) => String(a.name).localeCompare(String(b.name)));
  const categoryById = new Map(categories.map((category) => [String(category.id), category]));

  const providers = providerRows
    .map(normalizeProvider)
    .filter(Boolean)
    .map((provider) => ({
      ...provider,
      displayName: provider.businessName || `Provider ${shortId(provider.userId || provider.id)}`,
    }))
    .sort((a, b) => String(a.displayName).localeCompare(String(b.displayName)));
  const providerById = new Map();
  for (const provider of providers) {
    providerById.set(String(provider.userId), provider);
    providerById.set(String(provider.id), provider);
  }

  const services = serviceRows
    .map(normalizeService)
    .filter(Boolean)
    .map((service) => ({
      ...service,
      categoryName: categoryById.get(String(service.categoryId))?.name || '',
      providerName: providerById.get(String(service.providerId))?.displayName || '',
    }))
    .sort((a, b) => String(a.title).localeCompare(String(b.title)));

  return { categories, services, providers, errors };
}

export async function saveCategory({ id, name, description } = {}) {
  await requireAdmin();
  const payload = {
    name: String(name || '').trim(),
    description: String(description || '').trim(),
  };
  const row = id
    ? await updateRow('service_categories', id, payload)
    : await insertRow('service_categories', payload);
  return normalizeCategory(row || payload);
}

export async function saveService({ id, title, description, price, categoryId, providerId, isActive } = {}) {
  await requireAdmin();
  const cleanTitle = String(title || '').trim();
  // `services` uses `name` in the live project and `title` in schema.sql; both are
  // sent and insertRow/updateRow drop whichever column the database does not have.
  const payload = {
    name: cleanTitle,
    title: cleanTitle,
    description: String(description || '').trim(),
    price: price === '' || price === null || price === undefined ? null : Number(price),
    category_id: categoryId || null,
    provider_id: providerId || null,
    is_active: isActive !== false,
  };
  const row = id ? await updateRow('services', id, payload) : await insertRow('services', payload);
  return normalizeService(row || payload);
}

/* ----------------------------------------------------------------- bookings */

export async function loadBookings() {
  await requireAdmin();
  const errors = [];
  const [bookingRows, profileRows, providerRows, serviceRows, categoryRows] = await Promise.all([
    readTable('bookings', errors),
    readTable('profiles', errors),
    readTable('provider_profiles', errors),
    readTable('services', errors),
    readTable('service_categories', errors),
  ]);

  const profileById = new Map(profileRows.map((row) => [String(row.id), normalizeProfile(row)]));
  const providers = providerRows.map(normalizeProvider).filter(Boolean);
  const providerById = new Map();
  for (const provider of providers) {
    providerById.set(String(provider.userId), provider);
    providerById.set(String(provider.id), provider);
  }
  const serviceById = new Map(serviceRows.map((row) => [String(row.id), normalizeService(row)]));
  const categoryById = new Map(categoryRows.map((row) => [String(row.id), normalizeCategory(row)]));

  const bookings = uniqueById(bookingRows.map(normalizeBooking).filter(Boolean))
    .map((booking) => {
      const provider = providerById.get(String(booking.providerId)) || null;
      const providerProfile = provider ? profileById.get(String(provider.userId)) : null;
      return {
        ...booking,
        customerName: profileById.get(String(booking.customerId))?.fullName || 'Customer',
        customerEmail: profileById.get(String(booking.customerId))?.email || '',
        providerName:
          provider?.businessName ||
          providerProfile?.fullName ||
          profileById.get(String(booking.providerId))?.fullName ||
          'Not assigned',
        serviceName: serviceById.get(String(booking.serviceId))?.title || '',
        categoryName: categoryById.get(String(booking.categoryId))?.name || '',
      };
    })
    .sort((a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime());

  return { bookings, errors };
}

/* ------------------------------------------------------------- verification */

export async function loadVerificationQueue() {
  await requireAdmin();
  const errors = [];
  const [providerRows, documentRows, profileRows, categoryRows] = await Promise.all([
    readTable('provider_profiles', errors),
    readTable('provider_documents', errors),
    readTable('profiles', errors),
    readTable('service_categories', errors),
  ]);

  const profileById = new Map(profileRows.map((row) => [String(row.id), normalizeProfile(row)]));
  const categoryById = new Map(categoryRows.map((row) => [String(row.id), normalizeCategory(row)]));

  const providers = providerRows
    .map(normalizeProvider)
    .filter(Boolean)
    .map((provider) => {
      const profile = profileById.get(String(provider.userId)) || null;
      const documents = documentRows
        .filter((row) => String(row.provider_id ?? row.user_id ?? '') === String(provider.userId))
        .map(normalizeDocument)
        .filter(Boolean)
        .sort((a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime());
      return {
        ...provider,
        profile,
        fullName: profile?.fullName || '',
        email: profile?.email || '',
        phone: profile?.phone || '',
        categoryName: categoryById.get(String(provider.categoryId))?.name || '',
        documents,
        displayName: provider.businessName || profile?.fullName || 'Service provider',
        isPending: isPendingVerification(provider.verificationStatus),
      };
    })
    .sort((a, b) => Number(b.isPending) - Number(a.isPending) || String(a.displayName).localeCompare(String(b.displayName)));

  return { providers, errors };
}

async function callRpc(name, args) {
  try {
    const { data, error } = await client().rpc(name, args);
    if (error) {
      const missing =
        error.code === 'PGRST202' || /could not find the function|function .* does not exist/i.test(error.message || '');
      return { ok: false, missing, error };
    }
    return { ok: true, data };
  } catch (error) {
    return { ok: false, missing: false, error };
  }
}

// Approve or reject a provider. Prefers the database function from the admin
// migration (single atomic statement that re-checks the caller's role); falls back
// to a direct update, which Row Level Security still restricts to administrators.
export async function reviewVerification(providerKey, decision, documentIds = []) {
  await requireAdmin();
  const status = decision === 'approve' ? 'approved' : decision === 'reject' ? 'rejected' : '';
  if (!status) throw new Error('Choose approve or reject.');
  if (!providerKey) throw new Error('Select a provider to review.');

  const rpc = await callRpc('lsp_admin_review_verification', { p_provider_id: providerKey, p_status: status });
  let provider = null;
  if (rpc.ok) {
    provider = normalizeProvider(rpc.data) || null;
  } else if (rpc.missing) {
    provider = await updateProviderProfile(providerKey, {
      verification_status: status,
      updated_at: new Date().toISOString(),
    });
  } else {
    throw new DataError('provider_profiles', rpc.error);
  }

  // The decision is also recorded on the audited documents, which is the only
  // place the schema keeps a per-document outcome.
  const documentStatus = status === 'approved' ? 'approved' : 'rejected';
  const results = await Promise.all(
    documentIds
      .filter(Boolean)
      .map((id) => updateRow('provider_documents', id, { status: documentStatus }).catch((error) => ({ error }))),
  );
  const failed = results.filter((result) => result && result.error).length;

  return { status, provider, documentsUpdated: documentIds.length - failed, documentsFailed: failed };
}

// Private documents live in Supabase Storage. A stored path is exchanged for a
// short-lived signed URL; a full http(s) URL is used unchanged.
export async function documentLink(fileUrl) {
  const value = String(fileUrl || '').trim();
  if (!value) return { url: '', error: 'This document has no file attached.' };
  if (/^https?:\/\//i.test(value)) return { url: value, error: '' };

  const path = value.replace(/^\/+/, '').replace(/^storage\/v1\/object\/sign\//, '');
  const buckets = ['provider-documents', 'provider_documents', 'documents'];
  for (const bucket of buckets) {
    const { data, error } = await client().storage.from(bucket).createSignedUrl(path, 600);
    if (!error && data?.signedUrl) return { url: data.signedUrl, error: '' };
  }
  return {
    url: '',
    error: 'The document file could not be opened. Confirm the storage bucket name and its access policies.',
  };
}

/* --------------------------------------------------------------- complaints */

export async function loadComplaints() {
  await requireAdmin();
  const errors = [];
  const [complaintRows, profileRows, bookingRows] = await Promise.all([
    readTable('complaints', errors),
    readTable('profiles', errors),
    readTable('bookings', errors),
  ]);

  const profileById = new Map(profileRows.map((row) => [String(row.id), normalizeProfile(row)]));
  const bookingById = new Map(bookingRows.map((row) => [String(row.id), normalizeBooking(row)]));

  const complaints = uniqueById(complaintRows.map(normalizeComplaint).filter(Boolean))
    .map((complaint) => {
      const booking = complaint.bookingId ? bookingById.get(String(complaint.bookingId)) : null;
      return {
        ...complaint,
        raisedByName: profileById.get(String(complaint.raisedBy))?.fullName || 'Account holder',
        raisedByEmail: profileById.get(String(complaint.raisedBy))?.email || '',
        bookingRef: complaint.bookingId ? shortId(complaint.bookingId) : '',
        bookingStatus: booking?.status || '',
      };
    })
    .sort((a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime());

  return { complaints, errors };
}

export async function setComplaintStatus(complaintId, status) {
  await requireAdmin();
  const clean = String(status || '')
    .trim()
    .toLowerCase()
    .replace(/[\s-]+/g, '_');
  if (!clean) throw new Error('Choose a status.');
  const row = await updateRow('complaints', complaintId, { status: clean });
  if (!row) throw new Error('The complaint status could not be saved.');
  return normalizeComplaint(row);
}

/* ----------------------------------------------------------------- payments */

export async function loadPayments() {
  await requireAdmin();
  const errors = [];
  const [paymentRows, bookingRows, profileRows] = await Promise.all([
    readTable('payments', errors),
    readTable('bookings', errors),
    readTable('profiles', errors),
  ]);

  const bookingById = new Map(bookingRows.map((row) => [String(row.id), normalizeBooking(row)]));
  const profileById = new Map(profileRows.map((row) => [String(row.id), normalizeProfile(row)]));

  const payments = uniqueById(paymentRows.map(normalizePayment).filter(Boolean))
    .map((payment) => {
      const booking = payment.bookingId ? bookingById.get(String(payment.bookingId)) : null;
      return {
        ...payment,
        bookingRef: payment.bookingId ? shortId(payment.bookingId) : '',
        bookingStatus: booking?.status || '',
        customerName: profileById.get(String(payment.customerId || booking?.customerId))?.fullName || 'Customer',
      };
    })
    .sort((a, b) => new Date(b.createdAt || 0).getTime() - new Date(a.createdAt || 0).getTime());

  return { payments, totals: summarizePayments(payments), errors };
}

/* ------------------------------------------------------------------- counts */

export async function loadAdminIdentity() {
  const { session, profile } = await requireAdmin();
  return {
    email: session.user.email || profile.email || '',
    fullName: profile.fullName || '',
    role: profile.role,
    userId: session.user.id,
    expiresAt: session.expires_at ? new Date(session.expires_at * 1000).toISOString() : '',
  };
}
