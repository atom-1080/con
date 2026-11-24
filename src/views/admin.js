// Admin portal — screens 29 to 35 of LSP Connect.
//
// This module is the real administration surface: every figure and row comes from
// Supabase through src/lib/admin.js, which re-checks the caller's role in the
// database before each read or write. There are no demonstration values here.
//
// Layout is intentionally plain HTML strings plus delegated events, matching the
// rest of the project (no extra framework, no new design system).

import {
  loadDashboard,
  loadUsers,
  loadCatalogue,
  saveCategory,
  saveService,
  loadBookings,
  loadVerificationQueue,
  reviewVerification,
  documentLink,
  loadComplaints,
  setComplaintStatus,
  loadPayments,
  loadAdminIdentity,
  AdminAccessError,
} from '../lib/admin.js';
import {
  bookingStatusOptions,
  complaintStatusOptions,
  paginate,
  validateCategoryInput,
  validateServiceInput,
  isPaidStatus,
} from '../lib/adminValidation.js';
import {
  esc,
  icon,
  formatDate,
  formatDateTime,
  formatTime,
  formatMoney,
  statusBadge,
  alertBox,
  emptyState,
  skeletonRows,
  toast,
  confirmDialog,
  setBusy,
  initials,
} from '../ui.js';

/* ------------------------------------------------------------------ helpers */

const shortId = (value) => String(value || '').slice(0, 8).toUpperCase();

function money(value) {
  const amount = Number(value);
  return formatMoney(Number.isFinite(amount) ? amount : 0);
}

function table(headers, rows) {
  return `<div class="table-wrap"><table class="table"><thead><tr>${headers
    .map((heading) => `<th>${esc(heading)}</th>`)
    .join('')}</tr></thead><tbody>${rows.join('')}</tbody></table></div>`;
}

function pager(page, noun) {
  const label = `${page.total} ${noun}`;
  if (page.pages <= 1) return `<div class="admin-pager"><span class="muted">${esc(label)}</span></div>`;
  return `<div class="admin-pager">
      <span class="muted">${esc(label)} · page ${page.page} of ${page.pages}</span>
      <div class="btn-row">
        <button class="btn sm ghost" data-page="${page.page - 1}" ${page.page <= 1 ? 'disabled' : ''}>Previous</button>
        <button class="btn sm ghost" data-page="${page.page + 1}" ${page.page >= page.pages ? 'disabled' : ''}>Next</button>
      </div>
    </div>`;
}

function kpi(label, value, iconName, href) {
  return `<a class="card interactive stat" href="#${esc(href)}">
      <span class="value">${esc(value)}</span>
      <span class="label">${esc(label)}</span>
      <span class="muted tiny">${icon(iconName)} ${esc(label)}</span>
    </a>`;
}

// A permissions or session failure is shown as a gate, never as an empty table.
function gate(error) {
  const message = error?.message || 'The administrator data could not be loaded.';
  if (error instanceof AdminAccessError || error?.code === 'NOT_ADMIN') {
    return `${alertBox('error', message)}
      <div class="btn-row mt-2"><a class="btn primary" href="#/login/admin">${icon('login')} Administrator sign in</a></div>`;
  }
  return `${alertBox('error', message)}
    <p class="muted mt-2">Confirm the Row Level Security policies in <code>supabase/schema.sql</code> are applied and that your profile role is “admin”.</p>`;
}

function warn(errors) {
  if (!errors?.length) return '';
  const names = [...new Set(errors.map((entry) => entry.table))].join(', ');
  return alertBox('warn', `Some data could not be read (${names}). Those figures are shown as zero, never estimated.`);
}

function matches(term, values) {
  if (!term) return true;
  return values.filter(Boolean).some((value) => String(value).toLowerCase().includes(term));
}

/* ----------------------------------------------------------------- sections */

const SECTIONS = [
  {
    path: '/admin',
    label: 'Overview',
    title: 'Platform overview',
    lead: 'Live counts from every table this portal manages.',
    render: renderOverview,
  },
  {
    path: '/admin/users',
    label: 'Users',
    title: 'Customer and provider management',
    lead: 'Accounts from the profiles table, with provider details and verification state.',
    render: renderUsers,
  },
  {
    path: '/admin/services',
    label: 'Services',
    title: 'Service and category management',
    lead: 'Categories and the service catalogue, including standard rates.',
    render: renderServices,
  },
  {
    path: '/admin/bookings',
    label: 'Bookings',
    title: 'Booking oversight',
    lead: 'Read-only view of the booking lifecycle. Customer and provider workflow is unchanged.',
    render: renderBookings,
  },
  {
    path: '/admin/verification',
    label: 'Verifications',
    title: 'Provider verification and document audit',
    lead: 'Review submitted documents and record an approval or rejection.',
    render: renderVerification,
  },
  {
    path: '/admin/complaints',
    label: 'Complaints',
    title: 'Complaint and dispute handling',
    lead: 'Complaint records with their related booking and current status.',
    render: renderComplaints,
  },
  {
    path: '/admin/payments',
    label: 'Payments',
    title: 'Payment monitoring',
    lead: 'Recorded payments only. This screen never charges, captures or refunds money.',
    render: renderPayments,
  },
  {
    path: '/admin/settings',
    label: 'Settings',
    title: 'Administration overview',
    lead: 'Who you are signed in as and how this module is protected.',
    render: renderSettings,
  },
];

function tabs(path) {
  return `<nav class="admin-tabs" aria-label="Admin sections">${SECTIONS.map(
    (section) =>
      `<a href="#${section.path}" class="${section.path === path ? 'active' : ''}">${icon(section.icon)}${esc(
        section.label,
      )}</a>`,
  ).join('')}</nav>`;
}

export async function render(ctx) {
  const path = ctx?.path || '/admin';
  const section = SECTIONS.find((entry) => entry.path === path) || SECTIONS[0];

  return {
    title: section.title,
    html: `<div class="page-head">
        <div>
          <div class="eyebrow">Administrator</div>
          <h1>${esc(section.title)}</h1>
          <p>${esc(section.lead)}</p>
        </div>
        <div class="btn-row">
          <button class="btn ghost" data-admin-refresh>${icon('refresh')} Refresh</button>
        </div>
      </div>
      ${tabs(path)}
      <div id="admin-body">${skeletonRows(3)}</div>`,
    bind(root) {
      root.querySelector('[data-admin-refresh]')?.addEventListener('click', () => section.render(root, ctx));
      section.render(root, ctx);
    },
  };
}

/* ---------------------------------------------------------------- overview */

async function renderOverview(root) {
  const body = root.querySelector('#admin-body');
  if (!body) return;
  body.innerHTML = skeletonRows(4);

  let data;
  try {
    data = await loadDashboard();
  } catch (error) {
    body.innerHTML = gate(error);
    return;
  }

  const m = data.metrics;
  body.innerHTML = `
    ${warn(data.errors)}
    <div class="grid cols-4">
      ${kpi('Customers', m.customers, 'group', '/admin/users')}
      ${kpi('Providers', m.providers, 'handyman', '/admin/users')}
      ${kpi('Pending verifications', m.pendingVerifications, 'verified_user', '/admin/verification')}
      ${kpi('Total bookings', m.bookings, 'receipt_long', '/admin/bookings')}
      ${kpi('Active bookings', m.activeBookings, 'pending_actions', '/admin/bookings')}
      ${kpi('Completed bookings', m.completedBookings, 'task_alt', '/admin/bookings')}
      ${kpi('Open complaints', m.pendingComplaints, 'gavel', '/admin/complaints')}
      ${kpi('Recorded payments', m.payments, 'payments', '/admin/payments')}
    </div>

    <div class="grid cols-2 mt-2">
      <section class="card">
        <div class="card-head">
          <h3>Recent activity</h3>
          <span class="badge neutral">${data.activity.length}</span>
        </div>
        ${
          data.activity.length
            ? table(
                ['Event', 'Type', 'Status', 'When'],
                data.activity.map(
                  (entry) => `<tr>
                    <td><a href="#${esc(entry.href)}">${esc(entry.title)}</a></td>
                    <td class="muted">${esc(entry.kind)}</td>
                    <td>${statusBadge(entry.detail)}</td>
                    <td class="muted">${esc(formatDateTime(entry.at))}</td>
                  </tr>`,
                ),
              )
            : emptyState({
                icon: 'history',
                title: 'No activity recorded yet',
                message: 'Bookings, complaints and payments appear here as they are created.',
              })
        }
      </section>

      <section class="card">
        <div class="card-head"><h3>Money recorded</h3></div>
        <div class="stat">
          <span class="value">${esc(money(m.paymentsRecorded))}</span>
          <span class="label">Sum of payments marked paid</span>
        </div>
        <p class="muted mt-2">
          Read from the payments table. The portal never charges, captures or refunds money; a
          payment counts as recorded only when its stored status is a paid state.
        </p>
        <div class="btn-row">
          <a class="btn ghost sm" href="#/admin/payments">${icon('payments')} Payment overview</a>
        </div>
      </section>
    </div>`;
}

/* ------------------------------------------------------------------- users */

async function renderUsers(root, ctx) {
  const body = root.querySelector('#admin-body');
  if (!body) return;
  body.innerHTML = skeletonRows(4);

  let data;
  try {
    data = await loadUsers();
  } catch (error) {
    body.innerHTML = gate(error);
    return;
  }

  const state = { tab: 'customers', search: '', page: 1, focus: ctx?.query?.get?.('id') || '' };

  body.innerHTML = `
    <div class="card">
      <div class="card-head">
        <div class="btn-row">
          <button class="btn sm primary" data-tab="customers">Customers (${data.customers.length})</button>
          <button class="btn sm ghost" data-tab="providers">Providers (${data.providers.length})</button>
        </div>
        <input class="input admin-search" type="search" data-search placeholder="Search name, email, phone" />
      </div>
      <div id="admin-rows"></div>
    </div>
    <div id="admin-detail" class="mt-2"></div>`;

  const rowsBox = body.querySelector('#admin-rows');
  const detailBox = body.querySelector('#admin-detail');

  const paintDetail = () => {
    if (!state.focus) {
      detailBox.innerHTML = '';
      return;
    }
    if (state.tab === 'customers') {
      const customer = data.customers.find((row) => String(row.id) === String(state.focus));
      detailBox.innerHTML = customer
        ? `<section class="card">
            <div class="card-head"><h3>${esc(customer.fullName || 'Customer')}</h3><button class="btn sm ghost" data-close-detail>Close</button></div>
            <div class="grid cols-2">
              <div class="stat"><span class="label">Email</span><span>${esc(customer.email || 'Not recorded')}</span></div>
              <div class="stat"><span class="label">Phone</span><span>${esc(customer.phone || 'Not recorded')}</span></div>
              <div class="stat"><span class="label">City</span><span>${esc(customer.city || 'Not recorded')}</span></div>
              <div class="stat"><span class="label">Registered</span><span>${esc(
                customer.createdAt ? formatDate(customer.createdAt) : 'Not recorded',
              )}</span></div>
              <div class="stat"><span class="label">Role</span><span>${statusBadge(customer.role)}</span></div>
              <div class="stat"><span class="label">Bookings</span><span>${esc(customer.bookingCount)}</span></div>
            </div>
            <p class="muted mt-2">Authentication secrets, tokens and password hashes are never read or displayed here.</p>
          </section>`
        : '';
      return;
    }
    const provider = data.providers.find(
      (row) => String(row.userId) === String(state.focus) || String(row.id) === String(state.focus),
    );
    detailBox.innerHTML = provider
      ? `<section class="card">
          <div class="card-head"><h3>${esc(provider.displayName)}</h3><button class="btn sm ghost" data-close-detail>Close</button></div>
          <div class="grid cols-2">
            <div class="stat"><span class="label">Contact</span><span>${esc(provider.fullName || 'Not recorded')}</span></div>
            <div class="stat"><span class="label">Email</span><span>${esc(provider.email || 'Not recorded')}</span></div>
            <div class="stat"><span class="label">Phone</span><span>${esc(provider.phone || 'Not recorded')}</span></div>
            <div class="stat"><span class="label">Category</span><span>${esc(provider.categoryName || 'Not set')}</span></div>
            <div class="stat"><span class="label">Verification</span><span>${statusBadge(provider.verificationStatus)}</span></div>
            <div class="stat"><span class="label">Availability</span><span>${provider.isAvailable ? 'Available' : 'Unavailable'}</span></div>
            <div class="stat"><span class="label">Assigned jobs</span><span>${esc(provider.jobs)}</span></div>
            <div class="stat"><span class="label">Registered</span><span>${esc(
              provider.createdAt ? formatDate(provider.createdAt) : 'Not recorded',
            )}</span></div>
          </div>
          <div class="btn-row mt-2">
            <a class="btn sm ghost" href="#/admin/verification?id=${encodeURIComponent(provider.userId || provider.id)}">${icon(
              'verified_user',
            )} Review documents</a>
          </div>
        </section>`
      : '';
  };

  const paintRows = () => {
    const source = state.tab === 'customers' ? data.customers : data.providers;
    const term = state.search.trim().toLowerCase();
    const filtered = source.filter((row) =>
      state.tab === 'customers'
        ? matches(term, [row.fullName, row.email, row.phone, row.city])
        : matches(term, [row.displayName, row.fullName, row.email, row.phone, row.categoryName, row.verificationStatus]),
    );
    const page = paginate(filtered, state.page, 10);
    state.page = page.page;

    if (!page.rows.length) {
      rowsBox.innerHTML = emptyState({
        icon: 'group',
        title: term ? 'No matching accounts' : 'No accounts to show',
        message: term
          ? `No ${state.tab} match “${state.search}”.`
          : 'Accounts appear here once profiles exist in the database.',
      });
      return;
    }

    rowsBox.innerHTML =
      state.tab === 'customers'
        ? table(
            ['Customer', 'Contact', 'Role', 'Registered', 'Bookings', ''],
            page.rows.map(
              (row) => `<tr>
                <td>
                  <div class="row">
                    <span class="avatar sm">${esc(initials(row.fullName || row.email))}</span>
                    <span>${esc(row.fullName || 'Unnamed customer')}</span>
                  </div>
                </td>
                <td class="muted">${esc(row.email || '—')}<br />${esc(row.phone || '')}</td>
                <td>${statusBadge(row.role)}</td>
                <td class="muted">${esc(row.createdAt ? formatDate(row.createdAt) : '—')}</td>
                <td>${esc(row.bookingCount)}</td>
                <td><button class="btn sm ghost" data-focus="${esc(row.id)}">View</button></td>
              </tr>`,
            ),
          )
        : table(
            ['Provider', 'Contact', 'Category', 'Verification', 'Jobs', ''],
            page.rows.map(
              (row) => `<tr>
                <td>
                  <div class="row">
                    <span class="avatar sm">${esc(initials(row.displayName))}</span>
                    <span>${esc(row.displayName)}</span>
                  </div>
                </td>
                <td class="muted">${esc(row.email || '—')}<br />${esc(row.phone || '')}</td>
                <td class="muted">${esc(row.categoryName || '—')}</td>
                <td>${statusBadge(row.verificationStatus)}</td>
                <td>${esc(row.jobs)}</td>
                <td><button class="btn sm ghost" data-focus="${esc(row.userId || row.id)}">View</button></td>
              </tr>`,
            ),
          );
    rowsBox.innerHTML += pager(page, state.tab);
  };

  body.addEventListener('click', (event) => {
    const tab = event.target.closest('[data-tab]');
    if (tab) {
      state.tab = tab.dataset.tab;
      state.page = 1;
      state.focus = '';
      body.querySelectorAll('[data-tab]').forEach((button) => {
        const active = button.dataset.tab === state.tab;
        button.classList.toggle('primary', active);
        button.classList.toggle('ghost', !active);
      });
      paintRows();
      paintDetail();
      return;
    }
    const focus = event.target.closest('[data-focus]');
    if (focus) {
      state.focus = focus.dataset.focus;
      paintDetail();
      detailBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      return;
    }
    if (event.target.closest('[data-close-detail]')) {
      state.focus = '';
      paintDetail();
      return;
    }
    const page = event.target.closest('[data-page]');
    if (page) {
      state.page = Number(page.dataset.page) || 1;
      paintRows();
    }
  });

  body.querySelector('[data-search]')?.addEventListener('input', (event) => {
    state.search = event.target.value;
    state.page = 1;
    paintRows();
  });

  if (data.errors.length) rowsBox.insertAdjacentHTML('beforebegin', warn(data.errors));
  paintRows();
  paintDetail();
}

/* ---------------------------------------------------------------- services */

async function renderServices(root) {
  const body = root.querySelector('#admin-body');
  if (!body) return;
  body.innerHTML = skeletonRows(4);

  let current;
  try {
    current = await loadCatalogue();
  } catch (error) {
    body.innerHTML = gate(error);
    return;
  }

  const state = { tab: 'services', search: '', page: 1, editing: null };

  body.innerHTML = `
    <div class="card">
      <div class="card-head">
        <div class="btn-row">
          <button class="btn sm primary" data-tab="services">Services (${current.services.length})</button>
          <button class="btn sm ghost" data-tab="categories">Categories (${current.categories.length})</button>
        </div>
        <div class="btn-row">
          <input class="input admin-search" type="search" data-search placeholder="Search the catalogue" />
          <button class="btn sm primary" data-new>${icon('add')} New</button>
        </div>
      </div>
      <div id="admin-rows"></div>
    </div>
    <div id="admin-editor" class="mt-2"></div>`;

  const rowsBox = body.querySelector('#admin-rows');
  const editorBox = body.querySelector('#admin-editor');

  const paintEditor = () => {
    if (!state.editing) {
      editorBox.innerHTML = '';
      return;
    }
    const editing = state.editing;
    if (editing.kind === 'category') {
      const category = current.categories.find((row) => String(row.id) === String(editing.id)) || {};
      editorBox.innerHTML = `<section class="card">
        <div class="card-head"><h3>${editing.id ? 'Edit category' : 'New category'}</h3>
          <button class="btn sm ghost" data-cancel>Cancel</button></div>
        <form data-form="category" class="stack">
          <label class="field"><span>Name</span>
            <input class="input" name="name" required maxlength="80" value="${esc(category.name || '')}" /></label>
          <label class="field"><span>Description</span>
            <textarea class="input" name="description" rows="3">${esc(category.description || '')}</textarea></label>
          <div class="btn-row"><button class="btn primary" type="submit">Save category</button></div>
        </form>
      </section>`;
      return;
    }
    const service = current.services.find((row) => String(row.id) === String(editing.id)) || {};
    editorBox.innerHTML = `<section class="card">
      <div class="card-head"><h3>${editing.id ? 'Edit service' : 'New service'}</h3>
        <button class="btn sm ghost" data-cancel>Cancel</button></div>
      <form data-form="service" class="stack">
        <label class="field"><span>Service name</span>
          <input class="input" name="title" required maxlength="120" value="${esc(service.title || '')}" /></label>
        <div class="grid cols-2">
          <label class="field"><span>Standard rate</span>
            <input class="input" name="price" type="number" min="0" step="0.01" value="${esc(
              service.price ?? '',
            )}" placeholder="0.00" /></label>
          <label class="field"><span>Category</span>
            <select class="input" name="categoryId">
              <option value="">No category</option>
              ${current.categories
                .map(
                  (category) =>
                    `<option value="${esc(category.id)}" ${
                      String(category.id) === String(service.categoryId) ? 'selected' : ''
                    }>${esc(category.name)}</option>`,
                )
                .join('')}
            </select></label>
        </div>
        <label class="field"><span>Provider</span>
          <select class="input" name="providerId">
            <option value="">Unassigned catalogue entry</option>
            ${current.providers
              .map(
                (provider) =>
                  `<option value="${esc(provider.userId || provider.id)}" ${
                    String(provider.userId || provider.id) === String(service.providerId) ? 'selected' : ''
                  }>${esc(provider.displayName)}</option>`,
              )
              .join('')}
          </select></label>
        <label class="field"><span>Description</span>
          <textarea class="input" name="description" rows="3">${esc(service.description || '')}</textarea></label>
        <label class="row"><input type="checkbox" name="isActive" ${
          service.isActive === false ? '' : 'checked'
        } /> <span>Active in the customer catalogue</span></label>
        <div class="btn-row"><button class="btn primary" type="submit">Save service</button></div>
      </form>
    </section>`;
  };

  const paintRows = () => {
    const term = state.search.trim().toLowerCase();
    if (state.tab === 'services') {
      const filtered = current.services.filter((row) =>
        matches(term, [row.title, row.categoryName, row.providerName, row.description]),
      );
      const page = paginate(filtered, state.page, 12);
      state.page = page.page;
      if (!page.rows.length) {
        rowsBox.innerHTML = emptyState({
          icon: 'handyman',
          title: term ? 'No matching services' : 'No services yet',
          message: term
            ? `Nothing in the catalogue matches “${state.search}”.`
            : 'Create a service, or wait for providers to publish their own.',
        });
        return;
      }
      rowsBox.innerHTML =
        table(
          ['Service', 'Category', 'Provider', 'Rate', 'Active', ''],
          page.rows.map(
            (row) => `<tr>
              <td>${esc(row.title)}</td>
              <td class="muted">${esc(row.categoryName || '—')}</td>
              <td class="muted">${esc(row.providerName || 'Catalogue')}</td>
              <td>${esc(row.price === null || row.price === undefined ? '—' : money(row.price))}</td>
              <td>${row.isActive ? statusBadge('active') : statusBadge('inactive')}</td>
              <td><button class="btn sm ghost" data-edit="${esc(row.id)}" data-kind="service">Edit</button></td>
            </tr>`,
          ),
        ) + pager(page, 'services');
      return;
    }

    const filtered = current.categories.filter((row) => matches(term, [row.name, row.description]));
    const page = paginate(filtered, state.page, 12);
    state.page = page.page;
    if (!page.rows.length) {
      rowsBox.innerHTML = emptyState({
        icon: 'category',
        title: term ? 'No matching categories' : 'No categories yet',
        message: term ? `No category matches “${state.search}”.` : 'Create the first service category.',
      });
      return;
    }
    rowsBox.innerHTML =
      table(
        ['Category', 'Description', 'Services', ''],
        page.rows.map((row) => {
          const count = current.services.filter((service) => String(service.categoryId) === String(row.id)).length;
          return `<tr>
            <td>${esc(row.name)}</td>
            <td class="muted">${esc(row.description || '—')}</td>
            <td>${esc(count)}</td>
            <td><button class="btn sm ghost" data-edit="${esc(row.id)}" data-kind="category">Edit</button></td>
          </tr>`;
        }),
      ) + pager(page, 'categories');
  };

  const reload = async () => {
    try {
      current = await loadCatalogue();
    } catch (error) {
      rowsBox.innerHTML = gate(error);
      return;
    }
    paintRows();
    paintEditor();
  };

  body.addEventListener('click', (event) => {
    const tab = event.target.closest('[data-tab]');
    if (tab) {
      state.tab = tab.dataset.tab;
      state.page = 1;
      body.querySelectorAll('[data-tab]').forEach((button) => {
        const active = button.dataset.tab === state.tab;
        button.classList.toggle('primary', active);
        button.classList.toggle('ghost', !active);
      });
      paintRows();
      return;
    }
    if (event.target.closest('[data-new]')) {
      state.editing = { kind: state.tab === 'categories' ? 'category' : 'service', id: '' };
      paintEditor();
      editorBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      return;
    }
    const edit = event.target.closest('[data-edit]');
    if (edit) {
      state.editing = { kind: edit.dataset.kind, id: edit.dataset.edit };
      paintEditor();
      editorBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      return;
    }
    if (event.target.closest('[data-cancel]')) {
      state.editing = null;
      paintEditor();
      return;
    }
    const page = event.target.closest('[data-page]');
    if (page) {
      state.page = Number(page.dataset.page) || 1;
      paintRows();
    }
  });

  body.querySelector('[data-search]')?.addEventListener('input', (event) => {
    state.search = event.target.value;
    state.page = 1;
    paintRows();
  });

  editorBox.addEventListener('submit', async (event) => {
    event.preventDefault();
    const form = event.target;
    const submit = form.querySelector('[type="submit"]');
    setBusy(submit, true, 'Saving…');
    try {
      if (form.dataset.form === 'category') {
        const name = form.elements.name.value;
        const check = validateCategoryInput({ name }, current.categories, state.editing?.id || '');
        if (!check.ok) throw new Error(check.error);
        await saveCategory({
          id: state.editing?.id || undefined,
          name: check.value.name,
          description: form.elements.description.value,
        });
        toast('Category saved.');
      } else {
        const check = validateServiceInput(
          { title: form.elements.title.value, price: form.elements.price.value },
          current.services,
          state.editing?.id || '',
        );
        if (!check.ok) throw new Error(check.error);
        await saveService({
          id: state.editing?.id || undefined,
          title: check.value.title,
          price: check.value.price,
          description: form.elements.description.value,
          categoryId: form.elements.categoryId.value,
          providerId: form.elements.providerId.value,
          isActive: form.elements.isActive.checked,
        });
        toast('Service saved.');
      }
      state.editing = null;
      await reload();
    } catch (error) {
      toast(error.message || 'The record could not be saved.', 'error');
    } finally {
      setBusy(submit, false);
    }
  });

  if (current.errors.length) rowsBox.insertAdjacentHTML('beforebegin', warn(current.errors));
  paintRows();
}

/* ---------------------------------------------------------------- bookings */

async function renderBookings(root, ctx) {
  const body = root.querySelector('#admin-body');
  if (!body) return;
  body.innerHTML = skeletonRows(4);

  let data;
  try {
    data = await loadBookings();
  } catch (error) {
    body.innerHTML = gate(error);
    return;
  }

  const statuses = bookingStatusOptions(data.bookings);
  const state = { search: '', status: '', date: '', page: 1, focus: ctx?.query?.get?.('id') || '' };

  body.innerHTML = `
    <div class="card">
      <div class="card-head">
        <div class="btn-row">
          <input class="input admin-search" type="search" data-search placeholder="Search reference, customer, provider" />
          <select class="input" data-status>
            <option value="">All statuses</option>
            ${statuses.map((status) => `<option value="${esc(status)}">${esc(status.replace(/_/g, ' '))}</option>`).join('')}
          </select>
          <input class="input" type="date" data-date aria-label="Filter by scheduled date" />
        </div>
        <span class="badge neutral">${data.bookings.length} bookings</span>
      </div>
      <div id="admin-rows"></div>
    </div>
    <div id="admin-detail" class="mt-2"></div>`;

  const rowsBox = body.querySelector('#admin-rows');
  const detailBox = body.querySelector('#admin-detail');

  const paintDetail = () => {
    if (!state.focus) {
      detailBox.innerHTML = '';
      return;
    }
    const booking = data.bookings.find((row) => String(row.id) === String(state.focus));
    if (!booking) {
      detailBox.innerHTML = '';
      return;
    }
    detailBox.innerHTML = `<section class="card">
      <div class="card-head">
        <h3>Booking ${esc(shortId(booking.id))}</h3>
        <div class="btn-row">${statusBadge(booking.status)}<button class="btn sm ghost" data-close-detail>Close</button></div>
      </div>
      <div class="grid cols-2">
        <div class="stat"><span class="label">Customer</span><span>${esc(booking.customerName)}${
          booking.customerEmail ? ` · ${esc(booking.customerEmail)}` : ''
        }</span></div>
        <div class="stat"><span class="label">Provider</span><span>${esc(booking.providerName)}</span></div>
        <div class="stat"><span class="label">Service</span><span>${esc(booking.serviceName || '—')}</span></div>
        <div class="stat"><span class="label">Category</span><span>${esc(booking.categoryName || '—')}</span></div>
        <div class="stat"><span class="label">Scheduled</span><span>${esc(
          booking.scheduledDate ? formatDate(booking.scheduledDate) : 'Not scheduled',
        )} ${esc(booking.scheduledTime ? formatTime(booking.scheduledTime) : '')}</span></div>
        <div class="stat"><span class="label">Type</span><span>${esc(
          booking.bookingType || booking.raw?.booking_type || 'Regular',
        )}</span></div>
        <div class="stat"><span class="label">Address</span><span>${esc(
          [booking.address, booking.city].filter(Boolean).join(', ') || 'Not provided',
        )}</span></div>
        <div class="stat"><span class="label">Amount</span><span>${esc(
          booking.amount === null || booking.amount === undefined ? 'Not set' : money(booking.amount),
        )}</span></div>
      </div>
      ${
        booking.description
          ? `<p class="muted mt-2"><strong>Customer description</strong><br />${esc(booking.description)}</p>`
          : ''
      }
      <p class="muted mt-2">
        Read-only oversight. Booking status is advanced by the customer and provider workflows, so
        administration cannot bypass or corrupt them.
      </p>
    </section>`;
  };

  const paintRows = () => {
    const term = state.search.trim().toLowerCase();
    const filtered = data.bookings.filter((row) => {
      if (state.status && String(row.status).toLowerCase() !== state.status) return false;
      if (state.date && String(row.scheduledDate || '').slice(0, 10) !== state.date) return false;
      return matches(term, [row.id, shortId(row.id), row.customerName, row.customerEmail, row.providerName, row.serviceName]);
    });
    const page = paginate(filtered, state.page, 12);
    state.page = page.page;

    if (!page.rows.length) {
      rowsBox.innerHTML = emptyState({
        icon: 'receipt_long',
        title: 'No bookings match these filters',
        message: 'Adjust the search, status or date filter.',
      });
      return;
    }

    rowsBox.innerHTML =
      table(
        ['Ref', 'Customer', 'Provider', 'Service', 'Scheduled', 'Status', ''],
        page.rows.map(
          (row) => `<tr>
            <td class="mono">${esc(shortId(row.id))}</td>
            <td>${esc(row.customerName)}</td>
            <td class="muted">${esc(row.providerName)}</td>
            <td class="muted">${esc(row.serviceName || row.categoryName || '—')}</td>
            <td class="muted">${esc(row.scheduledDate ? formatDate(row.scheduledDate) : '—')}</td>
            <td>${statusBadge(row.status)}</td>
            <td><button class="btn sm ghost" data-focus="${esc(row.id)}">View</button></td>
          </tr>`,
        ),
      ) + pager(page, 'bookings');
  };

  body.addEventListener('click', (event) => {
    const focus = event.target.closest('[data-focus]');
    if (focus) {
      state.focus = focus.dataset.focus;
      paintDetail();
      detailBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      return;
    }
    if (event.target.closest('[data-close-detail]')) {
      state.focus = '';
      paintDetail();
      return;
    }
    const page = event.target.closest('[data-page]');
    if (page) {
      state.page = Number(page.dataset.page) || 1;
      paintRows();
    }
  });

  body.querySelector('[data-search]')?.addEventListener('input', (event) => {
    state.search = event.target.value;
    state.page = 1;
    paintRows();
  });
  body.querySelector('[data-status]')?.addEventListener('change', (event) => {
    state.status = event.target.value;
    state.page = 1;
    paintRows();
  });
  body.querySelector('[data-date]')?.addEventListener('change', (event) => {
    state.date = event.target.value;
    state.page = 1;
    paintRows();
  });

  if (data.errors.length) rowsBox.insertAdjacentHTML('beforebegin', warn(data.errors));
  paintRows();
  paintDetail();
}

/* ------------------------------------------------------------ verification */

async function renderVerification(root, ctx) {
  const body = root.querySelector('#admin-body');
  if (!body) return;
  body.innerHTML = skeletonRows(4);

  let current;
  try {
    current = await loadVerificationQueue();
  } catch (error) {
    body.innerHTML = gate(error);
    return;
  }

  const state = { filter: 'pending', search: '', page: 1 };

  body.innerHTML = `
    <div class="card">
      <div class="card-head">
        <div class="btn-row">
          <button class="btn sm primary" data-filter="pending">Pending (${current.providers.filter((p) => p.isPending).length})</button>
          <button class="btn sm ghost" data-filter="all">All providers (${current.providers.length})</button>
        </div>
        <input class="input admin-search" type="search" data-search placeholder="Search provider, category" />
      </div>
      <div id="admin-rows"></div>
    </div>`;

  const rowsBox = body.querySelector('#admin-rows');

  const paintRows = () => {
    const term = state.search.trim().toLowerCase();
    const filtered = current.providers
      .filter((provider) => (state.filter === 'pending' ? provider.isPending : true))
      .filter((provider) => matches(term, [provider.displayName, provider.fullName, provider.email, provider.categoryName]));
    const page = paginate(filtered, state.page, 6);
    state.page = page.page;

    if (!page.rows.length) {
      rowsBox.innerHTML = emptyState({
        icon: 'verified_user',
        title: state.filter === 'pending' ? 'No verifications waiting' : 'No providers found',
        message:
          state.filter === 'pending'
            ? 'Every provider has a recorded decision. Switch to “All providers” to review past decisions.'
            : 'Adjust the search to find a provider.',
      });
      return;
    }

    rowsBox.innerHTML =
      `<div class="stack">${page.rows
        .map((provider) => {
          const key = String(provider.userId || provider.id);
          return `<section class="card">
            <div class="card-head">
              <div class="row">
                <span class="avatar">${esc(initials(provider.displayName))}</span>
                <div>
                  <h3>${esc(provider.displayName)}</h3>
                  <p class="muted tiny">${esc(provider.fullName || 'No contact name')} · ${esc(
                    provider.email || 'no email',
                  )} · ${esc(provider.categoryName || 'no category')}</p>
                </div>
              </div>
              <div class="btn-row">
                ${statusBadge(provider.verificationStatus)}
                <a class="btn sm ghost" href="#/admin/users?id=${encodeURIComponent(key)}">${icon('person')} Profile</a>
              </div>
            </div>
            ${
              provider.documents.length
                ? table(
                    ['Document', 'Submitted', 'Status', ''],
                    provider.documents.map(
                      (document) => `<tr>
                        <td>${esc(document.type)}</td>
                        <td class="muted">${esc(document.createdAt ? formatDate(document.createdAt) : '—')}</td>
                        <td>${statusBadge(document.status)}</td>
                        <td><button class="btn sm ghost" data-doc="${esc(document.id)}">Open</button></td>
                      </tr>`,
                    ),
                  )
                : emptyState({
                    icon: 'description',
                    title: 'No documents submitted',
                    message: 'This provider has no document rows, so there is nothing to audit yet.',
                  })
            }
            <div class="btn-row mt-2">
              <button class="btn success sm" data-review="approve" data-provider="${esc(key)}">${icon('check')} Approve</button>
              <button class="btn danger sm" data-review="reject" data-provider="${esc(key)}">${icon('close')} Reject</button>
            </div>
          </section>`;
        })
        .join('')}</div>` + pager(page, 'providers');
  };

  const reload = async () => {
    try {
      current = await loadVerificationQueue();
    } catch (error) {
      rowsBox.innerHTML = gate(error);
      return;
    }
    paintRows();
  };

  body.addEventListener('click', async (event) => {
    const filter = event.target.closest('[data-filter]');
    if (filter) {
      state.filter = filter.dataset.filter;
      state.page = 1;
      body.querySelectorAll('[data-filter]').forEach((button) => {
        const active = button.dataset.filter === state.filter;
        button.classList.toggle('primary', active);
        button.classList.toggle('ghost', !active);
      });
      paintRows();
      return;
    }

    const page = event.target.closest('[data-page]');
    if (page) {
      state.page = Number(page.dataset.page) || 1;
      paintRows();
      return;
    }

    const doc = event.target.closest('[data-doc]');
    if (doc) {
      const documentId = doc.dataset.doc;
      const record = current.providers.flatMap((provider) => provider.documents).find((row) => String(row.id) === documentId);
      if (!record) return;
      setBusy(doc, true, 'Opening…');
      const link = await documentLink(record.fileUrl);
      setBusy(doc, false);
      if (link.url) window.open(link.url, '_blank', 'noopener');
      else toast(link.error, 'error');
      return;
    }

    const review = event.target.closest('[data-review]');
    if (review) {
      const key = review.dataset.provider;
      const decision = review.dataset.review;
      const provider = current.providers.find((row) => String(row.userId || row.id) === key);
      if (!provider) return;

      const confirmed = await confirmDialog({
        title: decision === 'approve' ? 'Approve this provider?' : 'Reject this provider?',
        message:
          decision === 'approve'
            ? `${provider.displayName} will be marked approved and their submitted documents recorded as approved.`
            : `${provider.displayName} will be marked rejected and their submitted documents recorded as rejected.`,
        confirmText: decision === 'approve' ? 'Approve' : 'Reject',
      });
      if (!confirmed) return;

      setBusy(review, true, 'Saving…');
      try {
        const result = await reviewVerification(
          key,
          decision,
          provider.documents.map((row) => row.id),
        );
        toast(
          `${provider.displayName} marked ${result.status}. ${result.documentsUpdated} document(s) updated.` +
            (result.documentsFailed ? ` ${result.documentsFailed} could not be updated.` : ''),
          result.documentsFailed ? 'error' : 'success',
        );
        await reload();
      } catch (error) {
        toast(error.message || 'The verification decision could not be saved.', 'error');
      } finally {
        setBusy(review, false);
      }
    }
  });

  body.querySelector('[data-search]')?.addEventListener('input', (event) => {
    state.search = event.target.value;
    state.page = 1;
    paintRows();
  });

  if (current.errors.length) rowsBox.insertAdjacentHTML('beforebegin', warn(current.errors));
  paintRows();

  const focus = ctx?.query?.get?.('id');
  if (focus) {
    state.filter = 'all';
    state.search = '';
    paintRows();
  }
}

/* -------------------------------------------------------------- complaints */

async function renderComplaints(root, ctx) {
  const body = root.querySelector('#admin-body');
  if (!body) return;
  body.innerHTML = skeletonRows(4);

  let current;
  try {
    current = await loadComplaints();
  } catch (error) {
    body.innerHTML = gate(error);
    return;
  }

  const statuses = complaintStatusOptions(current.complaints);
  const state = { search: '', status: '', page: 1, focus: ctx?.query?.get?.('id') || '' };

  body.innerHTML = `
    <div class="card">
      <div class="card-head">
        <div class="btn-row">
          <input class="input admin-search" type="search" data-search placeholder="Search subject or details" />
          <select class="input" data-status>
            <option value="">All statuses</option>
            ${statuses.map((status) => `<option value="${esc(status)}">${esc(status.replace(/_/g, ' '))}</option>`).join('')}
          </select>
        </div>
        <span class="badge neutral">${current.complaints.length} complaints</span>
      </div>
      <div id="admin-rows"></div>
    </div>
    <div id="admin-detail" class="mt-2"></div>`;

  const rowsBox = body.querySelector('#admin-rows');
  const detailBox = body.querySelector('#admin-detail');

  const paintDetail = () => {
    if (!state.focus) {
      detailBox.innerHTML = '';
      return;
    }
    const complaint = current.complaints.find((row) => String(row.id) === String(state.focus));
    if (!complaint) {
      detailBox.innerHTML = '';
      return;
    }
    detailBox.innerHTML = `<section class="card">
      <div class="card-head">
        <h3>${esc(complaint.subject)}</h3>
        <div class="btn-row">${statusBadge(complaint.status)}<button class="btn sm ghost" data-close-detail>Close</button></div>
      </div>
      <div class="grid cols-2">
        <div class="stat"><span class="label">Complaint</span><span class="mono">${esc(shortId(complaint.id))}</span></div>
        <div class="stat"><span class="label">Raised by</span><span>${esc(complaint.raisedByName)}${
          complaint.raisedByEmail ? ` · ${esc(complaint.raisedByEmail)}` : ''
        }</span></div>
        <div class="stat"><span class="label">Related booking</span><span>${esc(complaint.bookingRef || 'Not linked')}</span></div>
        <div class="stat"><span class="label">Submitted</span><span>${esc(
          complaint.createdAt ? formatDateTime(complaint.createdAt) : 'Not recorded',
        )}</span></div>
      </div>
      <div class="mt-2">
        <div class="label">Original complaint</div>
        <p class="muted">${esc(complaint.details || 'No details were recorded.')}</p>
        <p class="muted tiny">The original complaint text is never edited by the portal.</p>
      </div>
      <div class="btn-row mt-2">
        <select class="input" data-complaint-status>
          ${statuses
            .map(
              (status) =>
                `<option value="${esc(status)}" ${status === complaint.status ? 'selected' : ''}>${esc(
                  status.replace(/_/g, ' '),
                )}</option>`,
            )
            .join('')}
        </select>
        <button class="btn primary sm" data-save-status>${icon('save')} Save status</button>
      </div>
      <p class="muted tiny mt-2">
        Only status values already present in the complaints table are offered. The schema has no
        resolution-notes column, so no free-text resolution is stored.
      </p>
    </section>`;
  };

  const paintRows = () => {
    const term = state.search.trim().toLowerCase();
    const filtered = current.complaints.filter((row) => {
      if (state.status && String(row.status).toLowerCase() !== state.status) return false;
      return matches(term, [row.subject, row.details, row.raisedByName, row.bookingRef]);
    });
    const page = paginate(filtered, state.page, 10);
    state.page = page.page;

    if (!page.rows.length) {
      rowsBox.innerHTML = emptyState({
        icon: 'gavel',
        title: 'No complaints match these filters',
        message: 'Adjust the search or status filter.',
      });
      return;
    }

    rowsBox.innerHTML =
      table(
        ['Ref', 'Subject', 'Raised by', 'Booking', 'Submitted', 'Status', ''],
        page.rows.map(
          (row) => `<tr>
            <td class="mono">${esc(shortId(row.id))}</td>
            <td>${esc(row.subject)}</td>
            <td class="muted">${esc(row.raisedByName)}</td>
            <td class="muted">${esc(row.bookingRef || '—')}</td>
            <td class="muted">${esc(row.createdAt ? formatDate(row.createdAt) : '—')}</td>
            <td>${statusBadge(row.status)}</td>
            <td><button class="btn sm ghost" data-focus="${esc(row.id)}">View</button></td>
          </tr>`,
        ),
      ) + pager(page, 'complaints');
  };

  body.addEventListener('click', async (event) => {
    const focus = event.target.closest('[data-focus]');
    if (focus) {
      state.focus = focus.dataset.focus;
      paintDetail();
      detailBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      return;
    }
    if (event.target.closest('[data-close-detail]')) {
      state.focus = '';
      paintDetail();
      return;
    }
    const page = event.target.closest('[data-page]');
    if (page) {
      state.page = Number(page.dataset.page) || 1;
      paintRows();
      return;
    }
    const save = event.target.closest('[data-save-status]');
    if (save) {
      const select = detailBox.querySelector('[data-complaint-status]');
      const complaint = current.complaints.find((row) => String(row.id) === String(state.focus));
      if (!select || !complaint) return;
      if (select.value === complaint.status) {
        toast('That is already the recorded status.', 'info');
        return;
      }
      const confirmed = await confirmDialog({
        title: 'Update complaint status?',
        message: `${shortId(complaint.id)} will be recorded as “${select.value.replace(/_/g, ' ')}”. The original complaint text is unchanged.`,
        confirmText: 'Save status',
      });
      if (!confirmed) return;
      setBusy(save, true, 'Saving…');
      try {
        await setComplaintStatus(complaint.id, select.value);
        toast('Complaint status updated.');
        current = await loadComplaints();
        paintRows();
        paintDetail();
      } catch (error) {
        toast(error.message || 'The status could not be saved.', 'error');
      } finally {
        setBusy(save, false);
      }
    }
  });

  body.querySelector('[data-search]')?.addEventListener('input', (event) => {
    state.search = event.target.value;
    state.page = 1;
    paintRows();
  });
  body.querySelector('[data-status]')?.addEventListener('change', (event) => {
    state.status = event.target.value;
    state.page = 1;
    paintRows();
  });

  if (current.errors.length) rowsBox.insertAdjacentHTML('beforebegin', warn(current.errors));
  paintRows();
  paintDetail();
}

/* ---------------------------------------------------------------- payments */

async function renderPayments(root, ctx) {
  const body = root.querySelector('#admin-body');
  if (!body) return;
  body.innerHTML = skeletonRows(4);

  let data;
  try {
    data = await loadPayments();
  } catch (error) {
    body.innerHTML = gate(error);
    return;
  }

  const statuses = bookingStatusOptions(data.payments);
  const state = { search: '', status: '', page: 1, focus: ctx?.query?.get?.('id') || '' };

  body.innerHTML = `
    <div class="grid cols-4">
      ${kpi('Payments recorded', data.totals.count, 'payments', '/admin/payments')}
      ${kpi('Marked paid', data.totals.paidCount, 'check_circle', '/admin/payments')}
      ${kpi('Value marked paid', money(data.totals.recorded), 'paid', '/admin/payments')}
      ${kpi('Payment methods', Object.keys(data.totals.methods).length, 'credit_card', '/admin/payments')}
    </div>
    <div class="card mt-2">
      <div class="card-head">
        <div class="btn-row">
          <input class="input admin-search" type="search" data-search placeholder="Search booking, customer, method" />
          <select class="input" data-status>
            <option value="">All statuses</option>
            ${statuses.map((status) => `<option value="${esc(status)}">${esc(status.replace(/_/g, ' '))}</option>`).join('')}
          </select>
        </div>
        <span class="badge neutral">monitoring only</span>
      </div>
      <div id="admin-rows"></div>
    </div>
    <div id="admin-detail" class="mt-2"></div>`;

  const rowsBox = body.querySelector('#admin-rows');
  const detailBox = body.querySelector('#admin-detail');

  const paintDetail = () => {
    if (!state.focus) {
      detailBox.innerHTML = '';
      return;
    }
    const payment = data.payments.find((row) => String(row.id) === String(state.focus));
    if (!payment) {
      detailBox.innerHTML = '';
      return;
    }
    detailBox.innerHTML = `<section class="card">
      <div class="card-head">
        <h3>Payment ${esc(shortId(payment.id))}</h3>
        <div class="btn-row">${statusBadge(payment.status)}<button class="btn sm ghost" data-close-detail>Close</button></div>
      </div>
      <div class="grid cols-2">
        <div class="stat"><span class="label">Booking</span><span class="mono">${esc(payment.bookingRef || 'Not linked')}</span></div>
        <div class="stat"><span class="label">Customer</span><span>${esc(payment.customerName)}</span></div>
        <div class="stat"><span class="label">Method</span><span>${esc(payment.method || 'Not recorded')}</span></div>
        <div class="stat"><span class="label">Amount</span><span>${esc(
          payment.amount === null || payment.amount === undefined ? 'Not recorded' : money(payment.amount),
        )}</span></div>
        <div class="stat"><span class="label">Recorded</span><span>${esc(
          payment.createdAt ? formatDateTime(payment.createdAt) : 'Not recorded',
        )}</span></div>
        <div class="stat"><span class="label">Booking status</span><span>${esc(payment.bookingStatus || '—')}</span></div>
      </div>
      <p class="muted mt-2">
        This screen reads recorded rows only. It does not process, capture, refund or otherwise change
        a payment, and it never reports money as received unless the stored status says paid.
      </p>
    </section>`;
  };

  const paintRows = () => {
    const term = state.search.trim().toLowerCase();
    const filtered = data.payments.filter((row) => {
      if (state.status && String(row.status).toLowerCase() !== state.status) return false;
      return matches(term, [row.bookingRef, row.customerName, row.method, row.status]);
    });
    const page = paginate(filtered, state.page, 12);
    state.page = page.page;

    if (!page.rows.length) {
      rowsBox.innerHTML = emptyState({
        icon: 'payments',
        title: 'No payments match these filters',
        message: 'Payments appear here once they exist in the payments table.',
      });
      return;
    }

    rowsBox.innerHTML =
      table(
        ['Booking', 'Customer', 'Method', 'Amount', 'Recorded', 'Status', ''],
        page.rows.map(
          (row) => `<tr>
            <td class="mono">${esc(row.bookingRef || '—')}</td>
            <td>${esc(row.customerName)}</td>
            <td class="muted">${esc(row.method || '—')}</td>
            <td>${esc(row.amount === null || row.amount === undefined ? '—' : money(row.amount))}</td>
            <td class="muted">${esc(row.createdAt ? formatDate(row.createdAt) : '—')}</td>
            <td>${statusBadge(row.status)}${isPaidStatus(row.status) ? '' : ''}</td>
            <td><button class="btn sm ghost" data-focus="${esc(row.id)}">View</button></td>
          </tr>`,
        ),
      ) + pager(page, 'payments');
  };

  body.addEventListener('click', (event) => {
    const focus = event.target.closest('[data-focus]');
    if (focus) {
      state.focus = focus.dataset.focus;
      paintDetail();
      detailBox.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
      return;
    }
    if (event.target.closest('[data-close-detail]')) {
      state.focus = '';
      paintDetail();
      return;
    }
    const page = event.target.closest('[data-page]');
    if (page) {
      state.page = Number(page.dataset.page) || 1;
      paintRows();
    }
  });

  body.querySelector('[data-search]')?.addEventListener('input', (event) => {
    state.search = event.target.value;
    state.page = 1;
    paintRows();
  });
  body.querySelector('[data-status]')?.addEventListener('change', (event) => {
    state.status = event.target.value;
    state.page = 1;
    paintRows();
  });

  if (data.errors.length) rowsBox.insertAdjacentHTML('beforebegin', warn(data.errors));
  paintRows();
  paintDetail();
}

/* ---------------------------------------------------------------- settings */

async function renderSettings(root) {
  const body = root.querySelector('#admin-body');
  if (!body) return;
  body.innerHTML = skeletonRows(3);

  let identity;
  try {
    identity = await loadAdminIdentity();
  } catch (error) {
    body.innerHTML = gate(error);
    return;
  }

  body.innerHTML = `
    <div class="grid cols-2">
      <section class="card">
        <div class="card-head"><h3>Signed-in administrator</h3></div>
        <div class="grid cols-2">
          <div class="stat"><span class="label">Name</span><span>${esc(identity.fullName || 'Not recorded')}</span></div>
          <div class="stat"><span class="label">Email</span><span>${esc(identity.email || 'Not recorded')}</span></div>
          <div class="stat"><span class="label">Database role</span><span>${statusBadge(identity.role)}</span></div>
          <div class="stat"><span class="label">Session expires</span><span>${esc(
            identity.expiresAt ? formatDateTime(identity.expiresAt) : 'Not reported',
          )}</span></div>
        </div>
        <p class="muted mt-2">
          The role above is read from the profiles row for this account. Editing browser storage or
          the URL cannot change it.
        </p>
      </section>

      <section class="card">
        <div class="card-head"><h3>How access is enforced</h3></div>
        <ul class="admin-list">
          <li>Every query runs with your own Supabase session — no service-role key exists in the browser.</li>
          <li>Row Level Security decides what is returned, using <code>lsp_is_admin()</code> in the database.</li>
          <li>Verification and complaint changes are written through the database, which re-checks the role.</li>
          <li>Customer and provider policies are unchanged, so their workflows behave exactly as before.</li>
        </ul>
      </section>
    </div>

    <section class="card mt-2">
      <div class="card-head"><h3>Provisioning a new administrator</h3></div>
      <p class="muted">
        There is no public administrator registration. An existing owner promotes an account
        privately, after the person has signed up normally as a customer or provider:
      </p>
      <pre class="admin-code">update public.profiles
   set role = 'admin'
 where email = 'person@example.com';</pre>
      <p class="muted tiny">
        Run this in the Supabase SQL editor as the project owner. The portal never creates accounts and
        never promotes a role from the browser.
      </p>
    </section>

    <section class="card mt-2">
      <div class="card-head"><h3>Operational notes</h3></div>
      <ul class="admin-list">
        <li>Payments are monitoring only: no gateway, charge, capture or refund is wired in.</li>
        <li>Bookings are read-only here; the customer and provider screens own the lifecycle.</li>
        <li>Complaint records keep their original text; only the status is writable.</li>
        <li>Provider documents open through short-lived signed URLs from Supabase Storage.</li>
      </ul>
    </section>`;
}
