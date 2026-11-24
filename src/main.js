import './styles.css';
import { loadIdentity, signOut } from './lib/auth.js';
import { getProviderForUser, watchBookings } from './lib/api.js';
import { isSupabaseConfigured } from './lib/supabaseClient.js';
import { esc, icon, initials, toast, confirmDialog } from './ui.js';

import * as landingView from './views/landing.js';
import * as authView from './views/auth.js';
import * as customerView from './views/customer.js';
import * as providerView from './views/provider.js';
import * as adminView from './views/admin.js';

const mountNode = document.getElementById('app');

export const state = {
  identity: { session: null, profile: null, role: null },
  provider: null,
  identityReady: false,
};

const routes = [
  { pattern: /^\/$/, view: landingView.render, role: null },
  { pattern: /^\/login\/(customer|provider|admin)$/, view: authView.renderLogin, role: null },
  { pattern: /^\/register\/(customer|provider)$/, view: authView.renderRegister, role: null },
  { pattern: /^\/customer\/?$/, view: customerView.renderDashboard, role: 'customer' },
  { pattern: /^\/customer\/browse$/, view: customerView.renderBrowse, role: 'customer' },
  { pattern: /^\/customer\/providers$/, view: customerView.renderProviders, role: 'customer' },
  { pattern: /^\/customer\/providers\/([^/]+)$/, view: customerView.renderProviderDetail, role: 'customer' },
  { pattern: /^\/customer\/book\/([^/]+)$/, view: customerView.renderBookingForm, role: 'customer' },
  { pattern: /^\/customer\/bookings$/, view: customerView.renderBookings, role: 'customer' },
  { pattern: /^\/customer\/bookings\/([^/]+)$/, view: customerView.renderBookingDetail, role: 'customer' },
  { pattern: /^\/customer\/profile$/, view: customerView.renderProfile, role: 'customer' },
  { pattern: /^\/customer\/addresses$/, view: customerView.renderAddresses, role: 'customer' },
  { pattern: /^\/provider\/?$/, view: providerView.renderDashboard, role: 'provider' },
  { pattern: /^\/provider\/bookings$/, view: providerView.renderBookings, role: 'provider' },
  { pattern: /^\/provider\/bookings\/([^/]+)$/, view: providerView.renderBookingDetail, role: 'provider' },
  { pattern: /^\/provider\/services$/, view: providerView.renderServices, role: 'provider' },
  { pattern: /^\/provider\/profile$/, view: providerView.renderProfile, role: 'provider' },
  { pattern: /^\/provider\/availability$/, view: providerView.renderAvailability, role: 'provider' },
  { pattern: /^\/admin\/?$/, view: adminView.render, role: 'admin' },
  {
    pattern: /^\/admin\/(users|services|bookings|verification|complaints|payments|settings)$/,
    view: adminView.render,
    role: 'admin',
  },
];

function currentRoute() {
  const raw = location.hash.replace(/^#/, '') || '/';
  const [pathPart, queryPart] = raw.split('?');
  const path = pathPart.replace(/\/+$/, '') || '/';
  const query = new URLSearchParams(queryPart || '');
  for (const route of routes) {
    const match = route.pattern.exec(path);
    if (match) return { route, params: match.slice(1).map(decodeURIComponent), query, path };
  }
  return { route: null, params: [], query, path };
}

export function navigate(path, { replace = false } = {}) {
  const target = `#${path}`;
  if (location.hash === target) {
    render();
    return;
  }
  if (replace) {
    history.replaceState(null, '', target);
    render();
  } else {
    location.hash = path;
  }
}

export function dashboardFor(role) {
  if (role === 'provider') return '/provider';
  if (role === 'admin') return '/admin';
  return '/customer';
}

async function ensureIdentity(force = false) {
  if (state.identityReady && !force) return state.identity;
  try {
    state.identity = await loadIdentity();
  } catch (error) {
    console.warn('[LSP] identity load failed:', error.message);
    state.identity = { session: null, profile: null, role: null };
  }
  state.identityReady = true;

  if (state.identity.session && state.identity.role === 'provider') {
    try {
      state.provider = await getProviderForUser(state.identity.session.user.id);
    } catch (error) {
      console.warn('[LSP] provider profile load failed:', error.message);
      state.provider = null;
    }
  } else {
    state.provider = null;
  }
  return state.identity;
}

/* ------------------------------------------------------------------- shell */

function navFor(role) {
  if (role === 'customer') {
    return [
      ['/customer', 'Dashboard', 'space_dashboard'],
      ['/customer/browse', 'Browse services', 'grid_view'],
      ['/customer/bookings', 'My bookings', 'receipt_long'],
      ['/customer/addresses', 'Addresses', 'location_on'],
      ['/customer/profile', 'Profile', 'person'],
    ];
  }
  if (role === 'provider') {
    return [
      ['/provider', 'Dashboard', 'space_dashboard'],
      ['/provider/bookings', 'Bookings', 'work'],
      ['/provider/services', 'Services & skills', 'handyman'],
      ['/provider/availability', 'Availability', 'event_available'],
      ['/provider/profile', 'Profile', 'storefront'],
    ];
  }
  if (role === 'admin') {
    return [
      ['/admin', 'Overview', 'monitoring'],
      ['/admin/users', 'Users', 'group'],
      ['/admin/services', 'Services', 'handyman'],
      ['/admin/bookings', 'Bookings', 'receipt_long'],
      ['/admin/verification', 'Verifications', 'verified_user'],
      ['/admin/complaints', 'Complaints', 'gavel'],
      ['/admin/payments', 'Payments', 'payments'],
      ['/admin/settings', 'Settings', 'settings'],
    ];
  }
  return [
    ['/', 'Home', 'home'],
    ['/login/customer', 'Customer login', 'person'],
    ['/login/provider', 'Provider login', 'handyman'],
    ['/login/admin', 'Admin', 'shield_person'],
  ];
}

function shellHtml(path, role) {
  const profile = state.identity.profile;
  const name = profile?.fullName || state.identity.session?.user?.email || 'Guest';
  const links = navFor(role)
    .map(
      ([href, label, iconName]) =>
        `<a href="#${href}" class="${path === href || (href !== '/' && path.startsWith(href)) ? 'active' : ''}">${esc(
          label,
        )}</a>`,
    )
    .join('');

  const account = state.identity.session
    ? `<div class="user-chip">
         <span class="avatar">${esc(initials(name))}</span>
         <span class="who"><b>${esc(name.split('@')[0])}</b><span>${esc(role || 'user')}</span></span>
         <button class="btn ghost sm" data-action="logout" title="Log out">${icon('logout')}</button>
       </div>`
    : `<div class="btn-row">
         <a class="btn ghost sm" href="#/register/customer">Sign up</a>
         <a class="btn primary sm" href="#/login/customer">Sign in</a>
       </div>`;

  return `
    <div class="app-shell">
      <header class="topbar">
        <a class="brand" href="#${state.identity.session ? dashboardFor(role) : '/'}">
          <span class="brand-mark">LSP</span>
          <span>LSP Connect<small>Local service providers</small></span>
        </a>
        <nav class="topnav" aria-label="Main navigation">${links}</nav>
        ${account}
      </header>
      <main id="view" class="page"></main>
      <footer class="footer">
        <div class="inner">
          <span>© ${new Date().getFullYear()} LSP Connect · Final-year project demonstration</span>
          <span>Data stored in Supabase · Customer &amp; Provider modules</span>
        </div>
      </footer>
    </div>`;
}

/* ------------------------------------------------------------------ render */

let renderToken = 0;

async function render() {
  const token = ++renderToken;
  const { route, params, query, path } = currentRoute();
  const identity = await ensureIdentity();
  if (token !== renderToken) return;

  if (!route) {
    mountNode.innerHTML = shellHtml(path, identity.role);
    mountNode.querySelector('#view').innerHTML = `
      <div class="empty">${icon('explore')}<h3>Page not found</h3>
      <p>The page you tried to open does not exist.</p>
      <a class="btn primary" href="#${dashboardFor(identity.role)}">Go to dashboard</a></div>`;
    bindShell();
    return;
  }

  if (route.role && identity.role !== route.role) {
    if (!identity.session) {
      navigate(`/login/${route.role}`, { replace: true });
      return;
    }
    toast(`That area is for ${route.role} accounts.`, 'error');
    navigate(dashboardFor(identity.role), { replace: true });
    return;
  }

  mountNode.innerHTML = shellHtml(path, identity.role);
  bindShell();
  const view = mountNode.querySelector('#view');

  const ctx = {
    params,
    query,
    path,
    state,
    identity,
    navigate,
    refresh: async () => {
      await ensureIdentity(true);
      render();
    },
    reloadIdentity: async () => ensureIdentity(true),
    toast,
    confirmDialog,
    role: route.role,
  };

  try {
    const result = await route.view(ctx);
    if (token !== renderToken) return;
    if (!result) return;
    const html = typeof result === 'string' ? result : result.html;
    if (html) view.innerHTML = html;
    if (typeof result.bind === 'function') result.bind(view, ctx);
    document.title = `${result.title ? `${result.title} · ` : ''}LSP Connect`;
    window.scrollTo({ top: 0, behavior: 'auto' });
  } catch (error) {
    console.error('[LSP] view error:', error);
    if (token !== renderToken) return;
    view.innerHTML = `<div class="alert error">${icon('error')}<div>${esc(
      error.message || 'This page could not be loaded.',
    )}</div></div>
      <button class="btn primary" data-action="reload">Try again</button>`;
    view.querySelector('[data-action="reload"]')?.addEventListener('click', () => render());
  }
}

function bindShell() {
  mountNode.querySelector('[data-action="logout"]')?.addEventListener('click', async (event) => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      await signOut();
      state.identity = { session: null, profile: null, role: null };
      state.identityReady = false;
      state.provider = null;
      toast('You have been logged out.');
      navigate('/');
    } catch (error) {
      toast(error.message || 'Could not log out.', 'error');
      button.disabled = false;
    }
  });
}

/* ------------------------------------------------------------------- boot */

let realtimeStop = null;

function startRealtime() {
  if (realtimeStop) return;
  realtimeStop = watchBookings(() => {
    const { path } = currentRoute();
    const relevant =
      path.startsWith('/provider') || path.startsWith('/customer/bookings') || path.startsWith('/customer/');
    if (relevant) {
      clearTimeout(startRealtime.timer);
      startRealtime.timer = setTimeout(() => render(), 600);
    }
  });
}

if (!isSupabaseConfigured) {
  mountNode.innerHTML = `<main class="page narrow">
    <div class="card">
      <h1>Supabase is not configured</h1>
      <p class="muted">Add the project URL and anon key in Settings → Environment variables as
      <code>SUPABASE_URL</code> and <code>SUPABASE_ANON_KEY</code>, then redeploy.</p>
    </div></main>`;
} else {
  window.addEventListener('hashchange', () => render());
  render().then(() => startRealtime());
}

export { render };
