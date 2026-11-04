'use strict';
import { $, api, closeMenu, h, hooks, icon, setActions, setTheme, effectiveTheme, syncThemeIcon, media, spinner, state, store, isAdmin } from './core.js';
import { ROUTES, NAV_ORDER } from './pages/index.js';

function buildNav() {
  const nav = $('#nav');
  nav.replaceChildren();
  let section = '';
  for (const key of NAV_ORDER) {
    const r = ROUTES[key];
    if (!r || (r.admin && !isAdmin())) continue;
    if (r.section !== section) {
      section = r.section;
      if (section) nav.append(h('div', { class: 'nav-section', text: section }));
    }
    nav.append(h('a', { href: `#/${key}`, 'data-route': key }, icon(r.icon), r.nav || r.title));
  }
}

function route() {
  if (!state.user) return;
  const parts = location.hash.replace(/^#\/?/, '').split('/').filter(Boolean).map(decodeURIComponent);
  const name = parts[0] || 'overview';
  const r = ROUTES[name];
  if (!r || (r.admin && !isAdmin())) { location.hash = '#/overview'; return; }
  if (state.cleanup) { state.cleanup(); state.cleanup = null; }
  closeMenu();
  document.querySelectorAll('dialog[open]').forEach((d) => d.close());
  document.querySelectorAll('.nav a').forEach((a) => {
    if (a.dataset.route === name) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
  });
  $('#app').classList.remove('nav-open');
  $('#page-title').textContent = r.title;
  $('#page-sub').textContent = '';
  document.title = `${r.title} · CloudPanel`;
  setActions();
  const view = $('#view');
  view.replaceChildren();
  state.cleanup = r.render(view, parts.slice(1)) || null;
}

// ---------- Auth ----------

function showLogin() {
  state.user = null;
  if (state.cleanup) { state.cleanup(); state.cleanup = null; }
  document.querySelectorAll('dialog').forEach((d) => d.close());
  $('#app').hidden = true;
  $('#login').hidden = false;
  $('#login-form').hidden = false;
  $('#mfa-form').hidden = true;
  const insecure = location.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
  $('#login-insecure').hidden = !insecure;
  document.title = 'Sign in · CloudPanel';
  setTimeout(() => $('#login-username').focus(), 0);
}
hooks.unauthorized = showLogin;
hooks.showLogin = showLogin;

function showApp(user) {
  state.user = user;
  $('#login').hidden = true;
  $('#app').hidden = false;
  $('#user-name').textContent = user.username;
  $('#user-initial').textContent = (user.username || '?')[0];
  $('#user-role').textContent = user.role === 'admin' ? 'Administrator' : 'Site manager';
  buildNav();
  route();
}
hooks.refreshUser = async () => { state.user = await api('/auth/me'); };

let mfaToken = null;

function setBusy(btn, label, on) {
  btn.disabled = on;
  btn.replaceChildren(...(on ? [spinner(), label] : [label]));
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#login-error');
  const btn = $('#login-submit');
  const username = $('#login-username').value.trim();
  const password = $('#login-password').value;
  err.hidden = true;
  if (!username || !password) {
    err.textContent = 'Enter your username and password.';
    err.hidden = false;
    return;
  }
  setBusy(btn, 'Signing in', true);
  try {
    const r = await api('/auth/login', { method: 'POST', body: { username, password } });
    $('#login-password').value = '';
    if (r && r.mfa_required) {
      mfaToken = r.mfa_token;
      $('#login-form').hidden = true;
      $('#mfa-form').hidden = false;
      $('#mfa-error').hidden = true;
      $('#mfa-code').value = '';
      setTimeout(() => $('#mfa-code').focus(), 0);
      return;
    }
    showApp(await api('/auth/me'));
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
    $('#login-password').select();
  } finally {
    setBusy(btn, 'Sign in', false);
  }
});

$('#mfa-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const err = $('#mfa-error');
  const btn = $('#mfa-submit');
  const code = $('#mfa-code').value.trim();
  err.hidden = true;
  if (!code) { err.textContent = 'Enter the code from your authenticator app.'; err.hidden = false; return; }
  setBusy(btn, 'Verifying', true);
  try {
    await api('/auth/login/mfa', { method: 'POST', body: { mfa_token: mfaToken, code } });
    mfaToken = null;
    showApp(await api('/auth/me'));
  } catch (ex) {
    err.textContent = ex.message;
    err.hidden = false;
    $('#mfa-code').select();
  } finally {
    setBusy(btn, 'Verify', false);
  }
});
$('#mfa-back').addEventListener('click', showLogin);

$('#logout-btn').addEventListener('click', async () => {
  try { await api('/auth/logout', { method: 'POST' }); } catch { /* ignore */ }
  showLogin();
});

$('#menu-btn').addEventListener('click', () => $('#app').classList.add('nav-open'));
$('#backdrop').addEventListener('click', () => $('#app').classList.remove('nav-open'));
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') $('#app').classList.remove('nav-open'); });
window.addEventListener('hashchange', route);

// ---------- Theme ----------

$('#theme-btn').addEventListener('click', () => setTheme(effectiveTheme() === 'dark' ? 'light' : 'dark'));
media.addEventListener('change', syncThemeIcon);
setTheme(store.get('cp-theme') || 'system');

// ---------- Boot ----------

(async () => {
  try {
    showApp(await api('/auth/me'));
  } catch {
    showLogin();
  }
})();
