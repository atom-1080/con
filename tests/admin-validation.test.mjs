// Unit tests for the pure Admin helpers (no network, no browser).
// Run with: npm run test:unit

import test from 'node:test';
import assert from 'node:assert/strict';

import {
  isAdminRole,
  validateCategoryInput,
  validateServiceInput,
  paginate,
  pageCount,
  complaintStatusOptions,
  bookingStatusOptions,
  isPaidStatus,
  summarizePayments,
  isPendingVerification,
  computeDashboardMetrics,
  uniqueById,
} from '../src/lib/adminValidation.js';

test('role check is strict about the admin value', () => {
  assert.equal(isAdminRole('admin'), true);
  assert.equal(isAdminRole(' Admin '), true);
  assert.equal(isAdminRole('administrator'), false);
  assert.equal(isAdminRole('provider'), false);
  assert.equal(isAdminRole(undefined), false);
  assert.equal(isAdminRole(null), false);
});

test('category validation rejects empty, over-long and duplicate names', () => {
  assert.equal(validateCategoryInput({ name: '   ' }).ok, false);
  assert.equal(validateCategoryInput({ name: 'x'.repeat(81) }).ok, false);

  const existing = [{ id: 'a', name: 'Plumbing' }];
  assert.equal(validateCategoryInput({ name: 'plumbing' }, existing).ok, false);

  // Editing the record itself is not a duplicate.
  assert.equal(validateCategoryInput({ name: 'plumbing' }, existing, 'a').ok, true);
});

test('category validation trims and collapses whitespace', () => {
  const result = validateCategoryInput({ name: '  Home   Cleaning ' });
  assert.equal(result.ok, true);
  assert.equal(result.value.name, 'Home Cleaning');
});

test('service validation handles rates as numbers, blanks and negatives', () => {
  const blank = validateServiceInput({ title: 'Deep clean', price: '' });
  assert.equal(blank.ok, true);
  assert.equal(blank.value.price, null);

  const numeric = validateServiceInput({ title: 'Deep clean', price: '42.50' });
  assert.equal(numeric.value.price, 42.5);

  assert.equal(validateServiceInput({ title: 'Deep clean', price: '-1' }).ok, false);
  assert.equal(validateServiceInput({ title: 'Deep clean', price: 'abc' }).ok, false);
  assert.equal(validateServiceInput({ title: '', price: '10' }).ok, false);
});

test('service validation detects a duplicate catalogue title', () => {
  const existing = [{ id: 's1', title: 'Tap repair' }];
  assert.equal(validateServiceInput({ title: 'tap repair' }, existing).ok, false);
  assert.equal(validateServiceInput({ title: 'tap repair' }, existing, 's1').ok, true);
});

test('pagination clamps pages and slices rows', () => {
  const items = Array.from({ length: 25 }, (_, index) => index + 1);

  const first = paginate(items, 1, 10);
  assert.equal(first.rows.length, 10);
  assert.equal(first.pages, 3);
  assert.equal(first.total, 25);
  assert.equal(first.rows[0], 1);

  const last = paginate(items, 3, 10);
  assert.equal(last.rows.length, 5);
  assert.equal(last.rows[4], 25);

  // Out-of-range pages clamp instead of returning nothing.
  const clamped = paginate(items, 99, 10);
  assert.equal(clamped.page, 3);

  assert.equal(pageCount(0, 10), 1);
  assert.equal(pageCount(25, 10), 3);
});

test('pagination tolerates empty and non-array input', () => {
  assert.deepEqual(paginate([], 1, 10), { rows: [], page: 1, pages: 1, total: 0 });
  assert.equal(paginate(null, 1, 10).total, 0);
});

test('status options only surface values already in the data', () => {
  const options = complaintStatusOptions([{ status: 'Open' }, { status: 'in review' }]);
  assert.deepEqual(options, ['in_review', 'open']);

  // A fresh table with no rows still offers the schema default.
  assert.deepEqual(complaintStatusOptions([]), ['open']);

  assert.deepEqual(bookingStatusOptions([{ status: 'pending' }, { status: 'IN_PROGRESS' }]), [
    'in_progress',
    'pending',
  ]);
});

test('paid detection does not treat a pending payment as received', () => {
  assert.equal(isPaidStatus('paid'), true);
  assert.equal(isPaidStatus('Completed'), true);
  assert.equal(isPaidStatus('pending'), false);
  assert.equal(isPaidStatus('unpaid'), false);
  assert.equal(isPaidStatus(''), false);
});

test('payment totals count only paid rows and round the sum', () => {
  const totals = summarizePayments([
    { status: 'paid', amount: 10.005, method: 'card' },
    { status: 'completed', amount: 5, method: 'CARD' },
    { status: 'pending', amount: 99, method: 'cash' },
    { status: 'paid', amount: 'not-a-number', method: 'card' },
  ]);

  assert.equal(totals.count, 4);
  assert.equal(totals.paidCount, 3);
  assert.equal(totals.recorded, 15.01);
  assert.equal(totals.methods.card, 3);
  assert.equal(totals.methods.cash, 1);
});

test('verification pending states match the schema defaults', () => {
  assert.equal(isPendingVerification('pending'), true);
  assert.equal(isPendingVerification(''), true);
  assert.equal(isPendingVerification('under_review'), true);
  assert.equal(isPendingVerification('approved'), false);
  assert.equal(isPendingVerification('rejected'), false);
});

test('dashboard metrics are direct counts of readable rows', () => {
  const metrics = computeDashboardMetrics({
    profiles: [{ role: 'customer' }, { role: 'Customer' }, { role: 'provider' }, { role: 'admin' }],
    providers: [{ verificationStatus: 'pending' }, { verificationStatus: 'approved' }],
    bookings: [
      { status: 'pending' },
      { status: 'accepted' },
      { status: 'in progress' },
      { status: 'completed' },
      { status: 'completed' },
    ],
    complaints: [{ status: 'open' }, { status: 'resolved' }],
    payments: [{ status: 'paid', amount: 20 }, { status: 'pending', amount: 30 }],
  });

  assert.equal(metrics.customers, 2);
  assert.equal(metrics.providers, 2);
  assert.equal(metrics.pendingVerifications, 1);
  assert.equal(metrics.bookings, 5);
  assert.equal(metrics.activeBookings, 2);
  assert.equal(metrics.completedBookings, 2);
  assert.equal(metrics.pendingComplaints, 1);
  assert.equal(metrics.payments, 2);
  assert.equal(metrics.paymentsRecorded, 20);
});

test('dashboard metrics treat unreadable tables as zero, never estimated', () => {
  const metrics = computeDashboardMetrics();
  assert.equal(metrics.customers, 0);
  assert.equal(metrics.bookings, 0);
  assert.equal(metrics.paymentsRecorded, 0);
});

test('duplicate rows are collapsed by id', () => {
  const rows = uniqueById([{ id: 'a', v: 1 }, { id: 'a', v: 2 }, { id: 'b' }, { id: null }]);
  assert.equal(rows.length, 2);
  assert.equal(rows[0].v, 1);
  assert.equal(rows[1].id, 'b');
});
