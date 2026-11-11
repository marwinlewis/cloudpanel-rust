'use strict';
// Shared helpers for the CloudPanel UI. All DOM is built with createElement /
// textContent; data from the server is never inserted as HTML.

export const $ = (sel, root = document) => root.querySelector(sel);
export const SVG_NS = 'http://www.w3.org/2000/svg';
export const PROPS = new Set(['value', 'checked', 'disabled', 'hidden', 'selected', 'required', 'readOnly', 'multiple']);

// ---------- DOM helpers ----------

export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'text') el.textContent = v;
    else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
    else if (PROPS.has(k)) el[k] = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  append(el, children);
  return el;
}

export function append(el, children) {
  for (const c of children.flat(Infinity)) {
    if (c == null || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

export function icon(name, cls = '') {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('class', `icon ${cls}`.trim());
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(SVG_NS, 'use');
  use.setAttribute('href', `#i-${name}`);
  svg.append(use);
  return svg;
}

export function svgEl(tag, attrs = {}) {
  const el = document.createElementNS(SVG_NS, tag);
  for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
  return el;
}

/** Draw a QR module matrix ('1' = dark) as an SVG element. */
export function qrSvg(width, modules) {
  const quiet = 2;
  const size = width + quiet * 2;
  const svg = svgEl('svg', { viewBox: `0 0 ${size} ${size}`, 'shape-rendering': 'crispEdges', role: 'img', 'aria-label': 'QR code' });
  let d = '';
  for (let y = 0; y < width; y++) {
    for (let x = 0; x < width; x++) {
      if (modules[y * width + x] === '1') d += `M${x + quiet},${y + quiet}h1v1h-1z`;
    }
  }
  svg.append(svgEl('path', { d, fill: '#000' }));
  return h('div', { class: 'qr' }, svg);
}

export const spinner = () => h('span', { class: 'spinner', 'aria-hidden': 'true' });

// ---------- Formatting ----------

export function fmtBytes(n, digits = 1) {
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** i).toFixed(i === 0 ? 0 : digits)} ${u[i]}`;
}
export const fmtRate = (n) => `${fmtBytes(n)}/s`;
export const fmtPct = (n) => `${Math.round(n ?? 0)}`;

export function fmtUptime(s) {
  const d = Math.floor(s / 86400), hr = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
  if (d) return `${d}d ${hr}h`;
  if (hr) return `${hr}h ${m}m`;
  return `${m}m`;
}

export const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
export function fmtAgo(iso) {
  const t = new Date(iso).getTime();
  if (!t) return '';
  const s = Math.round((t - Date.now()) / 1000);
  const steps = [[60, 'second'], [3600, 'minute'], [86400, 'hour'], [2592000, 'day'], [31536000, 'month'], [Infinity, 'year']];
  let div = 1;
  for (const [limit, unit] of steps) {
    if (Math.abs(s) < limit) return rtf.format(Math.round(s / div), unit);
    div = limit;
  }
  return '';
}
export const fmtDate = (iso) => new Date(iso).toLocaleString();

// ---------- Storage (best effort) ----------

export const store = {
  get(k) { try { return localStorage.getItem(k); } catch { return null; } },
  set(k, v) { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch { /* ignore */ } },
};

// ---------- API ----------

export class ApiError extends Error {
  constructor(message, status) { super(message); this.status = status; }
}

export async function api(path, { method = 'GET', body } = {}) {
  const headers = { 'X-Requested-With': 'cloudpanel', Accept: 'application/json' };
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  let res;
  try {
    res = await fetch(`/api${path}`, {
      method, headers, credentials: 'same-origin',
      body: body === undefined ? undefined : JSON.stringify(body),
    });
  } catch {
    throw new ApiError('Cannot reach the server. Check your connection.', 0);
  }
  let data = null;
  try { data = await res.json(); } catch { /* empty body */ }
  if (res.status === 401 && !path.startsWith('/auth/login')) {
    hooks.unauthorized();
    throw new ApiError('Your session has expired. Please sign in again.', 401);
  }
  if (!res.ok) throw new ApiError((data && data.error) || `Request failed (${res.status})`, res.status);
  return data;
}

// ---------- Toasts ----------

export function toast(message, type = 'success') {
  const el = h('div', { class: `toast ${type}`, role: type === 'error' ? 'alert' : 'status' },
    icon(type === 'error' ? 'alert' : 'check'),
    h('div', { class: 'grow', text: message }),
    h('button', { class: 'icon-btn', 'aria-label': 'Dismiss', onclick: () => el.remove() }, icon('x')));
  $('#toasts').append(el);
  setTimeout(() => el.remove(), type === 'error' ? 7000 : 3500);
}

// ---------- Dialogs ----------

export function openDialog({ title, description, body, footer, drawer = false, wide = false, onClose }) {
  const closeBtn = h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Close' }, icon('x'));
  const dlg = h('dialog', { class: [drawer && 'drawer', wide && 'wide'].filter(Boolean).join(' ') },
    h('div', { class: 'dialog-head' },
      h('div', { class: 'grow' }, h('h2', { text: title }), description && h('p', { text: description })),
      closeBtn),
    h('div', { class: 'dialog-body' }, body),
    footer && h('div', { class: 'dialog-foot' }, footer));
  const close = () => dlg.open && dlg.close();
  closeBtn.addEventListener('click', close);
  dlg.addEventListener('click', (e) => { if (e.target === dlg) close(); });
  dlg.addEventListener('close', () => { dlg.remove(); onClose && onClose(); });
  document.body.append(dlg);
  dlg.showModal();
  return { el: dlg, close };
}

export function confirmDialog({ title, message, confirmText = 'Confirm', danger = false }) {
  return new Promise((resolve) => {
    let result = false;
    const ok = h('button', { class: `btn ${danger ? 'danger solid' : 'primary'}`, type: 'button', text: confirmText });
    const cancel = h('button', { class: 'btn', type: 'button', text: 'Cancel' });
    const d = openDialog({ title, body: h('p', { class: 'muted', text: message }), footer: [cancel, ok], onClose: () => resolve(result) });
    cancel.addEventListener('click', d.close);
    ok.addEventListener('click', () => { result = true; d.close(); });
    ok.focus();
  });
}

/** Dialog wrapping a form with busy state and inline error reporting. */
export function formDialog({ title, description, content, submitText = 'Save', drawer = false, wide = false, onSubmit }) {
  const id = `f${Math.random().toString(36).slice(2)}`;
  const error = h('div', { class: 'alert error', role: 'alert', hidden: true });
  const form = h('form', { id, class: 'form', novalidate: true }, content, error);
  const submit = h('button', { class: 'btn primary', type: 'submit', form: id, text: submitText });
  const cancel = h('button', { class: 'btn', type: 'button', text: 'Cancel' });
  const d = openDialog({ title, description, body: form, footer: [cancel, submit], drawer, wide });
  cancel.addEventListener('click', d.close);

  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    error.hidden = true;
    if (!validateForm(form)) return;
    submit.disabled = true;
    submit.replaceChildren(spinner(), submitText);
    try {
      await onSubmit(formData(form), d);
      d.close();
    } catch (err) {
      error.replaceChildren(icon('alert'), h('div', { text: err.message }));
      error.hidden = false;
    } finally {
      submit.disabled = false;
      submit.replaceChildren(submitText);
    }
  });
  setTimeout(() => { const first = form.querySelector('input:not([type=hidden]):not([type=radio]), textarea, select'); first && first.focus(); }, 30);
  return d;
}

export function formData(form) {
  const out = {};
  for (const el of form.elements) {
    if (!el.name || el.disabled || el.closest('[hidden]')) continue;
    if (el.type === 'checkbox') out[el.name] = el.checked;
    else if (el.type === 'radio') { if (el.checked) out[el.name] = el.value; }
    else out[el.name] = el.value.trim();
  }
  return out;
}

/** Runs `data-validate` checks; shows the message under the field. */
export function validateForm(form) {
  let ok = true;
  for (const el of form.querySelectorAll('[data-validate]')) {
    if (el.closest('[hidden]')) continue;
    const msg = VALIDATORS[el.dataset.validate](el.value.trim(), form);
    const holder = el.closest('.field');
    let err = holder && holder.querySelector('.error-text');
    if (msg) {
      ok = false;
      el.setAttribute('aria-invalid', 'true');
      if (holder && !err) { err = h('div', { class: 'error-text' }); holder.append(err); }
      if (err) err.textContent = msg;
    } else {
      el.removeAttribute('aria-invalid');
      if (err) err.remove();
    }
  }
  const firstBad = form.querySelector('[aria-invalid="true"]');
  if (firstBad) firstBad.focus();
  return ok;
}

export const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;
export const VALIDATORS = {
  required: (v) => (v ? '' : 'This field is required'),
  domain: (v) => (DOMAIN_RE.test(v.toLowerCase().replace(/\.$/, '')) ? '' : 'Enter a valid domain, e.g. app.example.com'),
  port: (v) => (/^\d+$/.test(v) && +v >= 1 && +v <= 65535 ? '' : 'Enter a port between 1 and 65535'),
  email: (v) => (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? '' : 'Enter a valid email address'),
  password: (v) => (v.length >= 10 ? '' : 'Use at least 10 characters'),
  confirm: (v, form) => (v === form.elements.new_password.value ? '' : 'Passwords do not match'),
  cron: (v) => (/^(@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)|(\S+\s+){4}\S+)$/.test(v) ? '' : 'Use 5 fields (m h dom mon dow) or a macro like @daily'),
  optionalPath: (v) => (!v || /^\/[A-Za-z0-9._\-/]*$/.test(v) ? '' : 'Use an absolute path with letters, digits, . _ - /'),
};

export function field({ label, name, type = 'text', value = '', placeholder, hint, validate, attrs = {} }) {
  const id = `in-${name}-${Math.random().toString(36).slice(2, 7)}`;
  const input = type === 'textarea'
    ? h('textarea', { class: 'input', id, name, placeholder, 'data-validate': validate, spellcheck: 'false', ...attrs })
    : h('input', { class: 'input', id, name, type, placeholder, 'data-validate': validate, ...attrs });
  input.value = value;
  return h('div', { class: 'field' }, h('label', { for: id, text: label }), input, hint && h('div', { class: 'hint', text: hint }));
}

export function selectField({ label, name, options, value }) {
  const id = `sel-${name}-${Math.random().toString(36).slice(2, 7)}`;
  const sel = h('select', { class: 'input', id, name },
    options.map(([v, t]) => h('option', { value: v, text: t, selected: v === value })));
  return h('div', { class: 'field' }, h('label', { for: id, text: label }), sel);
}

// ---------- Popover menu ----------

export let openMenuEl = null;
export function closeMenu() { if (openMenuEl) { openMenuEl.remove(); openMenuEl = null; } }
export function openMenu(anchor, items) {
  closeMenu();
  const menu = h('div', { class: 'menu', role: 'menu' },
    items.map((it) => (it === '-' ? h('hr') : h('button', {
      type: 'button', role: 'menuitem', class: it.danger ? 'danger' : '',
      onclick: () => { closeMenu(); it.action(); },
    }, icon(it.icon), it.label))));
  document.body.append(menu);
  const r = anchor.getBoundingClientRect();
  const mw = menu.offsetWidth, mh = menu.offsetHeight;
  menu.style.left = `${Math.max(8, Math.min(r.right - mw, window.innerWidth - mw - 8))}px`;
  menu.style.top = `${r.bottom + mh + 8 > window.innerHeight ? r.top - mh - 4 : r.bottom + 4}px`;
  openMenuEl = menu;
  menu.querySelector('button').focus();
}
document.addEventListener('click', (e) => { if (openMenuEl && !openMenuEl.contains(e.target) && !e.target.closest('[data-menu]')) closeMenu(); });
document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeMenu(); });
window.addEventListener('scroll', closeMenu, true);
window.addEventListener('resize', closeMenu);

export const moreButton = (items) => {
  const b = h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'More actions', 'aria-haspopup': 'menu', 'data-menu': '' }, icon('more'));
  b.addEventListener('click', (e) => { e.stopPropagation(); openMenuEl ? closeMenu() : openMenu(b, items); });
  return b;
};

// ---------- Shared view pieces ----------

export function card({ title, sub, actions, body, flush = false }) {
  return h('section', { class: 'card' },
    title && h('div', { class: 'card-head' },
      h('div', { class: 'grow' }, h('h2', { text: title }), sub && h('div', { class: 'sub', text: sub })),
      actions),
    flush ? body : h('div', { class: 'card-body' }, body));
}

export function emptyState({ iconName, title, text, action }) {
  return h('div', { class: 'empty' },
    h('div', { class: 'empty-icon' }, icon(iconName, 'lg')),
    h('h3', { text: title }), text && h('p', { text }), action);
}

export function errorState(message, retry) {
  return emptyState({
    iconName: 'alert', title: 'Something went wrong', text: message,
    action: retry && h('button', { class: 'btn', onclick: retry }, icon('refresh'), 'Try again'),
  });
}

export function skeletonRows(cols, rows = 3) {
  return Array.from({ length: rows }, () => h('tr', null,
    Array.from({ length: cols }, () => h('td', null, h('div', { class: 'skeleton' })))));
}

export function table(headers, rows) {
  return h('div', { class: 'table-wrap' }, h('table', null,
    h('thead', null, h('tr', null, headers.map((x) => (typeof x === 'string'
      ? h('th', { text: x })
      : h('th', { class: x.class || '', text: x.label }))))),
    h('tbody', null, rows)));
}

export async function withBusy(btn, fn) {
  const old = [...btn.childNodes];
  btn.disabled = true;
  btn.replaceChildren(spinner());
  try { await fn(); } catch (e) { toast(e.message, 'error'); } finally { btn.disabled = false; btn.replaceChildren(...old); }
}

export function setActions(...nodes) { $('#page-actions').replaceChildren(...nodes.filter(Boolean)); }

// ---------- Shared app state ----------

export const state = { user: null, cleanup: null };
export const hooks = { unauthorized: () => {}, showLogin: () => {}, refreshUser: async () => {}, refreshPanelUpdate: async () => {} };
export const isAdmin = () => !!(state.user && state.user.role === 'admin');

export function setHost(name) {
  if (!name) return;
  $('#server-host').textContent = name;
  $('#server-chip').hidden = false;
}

export function setSub(text) { $('#page-sub').textContent = text || ''; }

// ---------- Theme ----------

export const media = window.matchMedia('(prefers-color-scheme: dark)');
export function effectiveTheme() {
  const t = document.documentElement.dataset.theme;
  return t || (media.matches ? 'dark' : 'light');
}
export function syncThemeIcon() {
  const use = $('#theme-btn use');
  use.setAttribute('href', effectiveTheme() === 'dark' ? '#i-sun' : '#i-moon');
}
export function setTheme(t) {
  if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
  store.set('cp-theme', t === 'system' ? null : t);
  syncThemeIcon();
}

// ---------- Jobs ----------

/** Show a drawer that follows a background job's output until it finishes. Resolves to the final job. */
export function jobDialog(jobId, title) {
  return new Promise((resolve) => {
    const pre = h('pre', { class: 'logs mono', text: 'Starting…' });
    const status = h('span', { class: 'badge', text: 'running' });
    let timer = null;
    let last = null;
    const d = openDialog({
      title, drawer: true,
      body: h('div', { class: 'form' }, h('div', { class: 'row' }, h('span', { class: 'muted small', text: `Job #${jobId}` }), status), pre),
      onClose: () => { clearTimeout(timer); resolve(last); },
    });
    async function poll() {
      try {
        const j = await api(`/jobs/${jobId}`);
        last = j;
        const atBottom = pre.scrollTop + pre.clientHeight >= pre.scrollHeight - 20;
        pre.textContent = j.output || '(no output yet)';
        if (atBottom) pre.scrollTop = pre.scrollHeight;
        status.textContent = j.status;
        status.className = `badge ${j.status === 'succeeded' ? 'ok' : j.status === 'failed' ? 'danger' : ''}`;
        if (j.status === 'running' && d.el.open) timer = setTimeout(poll, 1000);
      } catch (e) { pre.textContent = e.message; }
    }
    poll();
  });
}

/** Start an API call that returns {job_id} and follow it. */
export async function runJob(path, title, body) {
  const r = await api(path, { method: 'POST', body });
  return jobDialog(r.job_id, title);
}

// ---------- Downloads & uploads ----------

/** Trigger a browser download of an authenticated GET endpoint. */
export function download(path) {
  const a = h('a', { href: `/api${path}`, download: '' });
  document.body.append(a);
  a.click();
  a.remove();
}

/** POST a multipart form (file uploads). */
export async function upload(path, formDataObj, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `/api${path}`);
    xhr.setRequestHeader('X-Requested-With', 'cloudpanel');
    xhr.responseType = 'json';
    if (onProgress) xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total);
    xhr.onload = () => {
      if (xhr.status >= 200 && xhr.status < 300) resolve(xhr.response);
      else reject(new ApiError((xhr.response && xhr.response.error) || `Upload failed (${xhr.status})`, xhr.status));
    };
    xhr.onerror = () => reject(new ApiError('Upload failed. Check your connection.', 0));
    xhr.send(formDataObj);
  });
}

// ---------- Tabs ----------

/** Simple tab strip. `tabs` = [[key, label]]; returns the element. */
export function tabStrip(tabs, active, onSelect) {
  const el = h('div', { class: 'tabs', role: 'tablist' });
  for (const [k, label] of tabs) {
    const b = h('button', { type: 'button', role: 'tab', 'aria-selected': String(k === active), text: label });
    b.addEventListener('click', () => {
      el.querySelectorAll('button').forEach((x) => x.setAttribute('aria-selected', String(x === b)));
      onSelect(k);
    });
    el.append(b);
  }
  return el;
}

/** A labelled read-only key/value list. */
export function kv(rows) {
  return h('dl', { class: 'kv' }, rows.filter(Boolean).flatMap(([k, v]) => [h('dt', { text: k }), h('dd', { class: 'truncate' }, v instanceof Node ? v : String(v ?? '—'))]));
}

export function copyButton(text) {
  const b = h('button', { class: 'icon-btn', type: 'button', title: 'Copy', 'aria-label': 'Copy' }, icon('copy'));
  b.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(typeof text === 'function' ? text() : text); toast('Copied'); } catch { toast('Copy failed', 'error'); }
  });
  return b;
}

/** Show a secret (password) once with a copy button. */
export function secretDialog(title, message, secret) {
  const code = h('code', { class: 'mono secret', text: secret });
  const ok = h('button', { class: 'btn primary', type: 'button', text: 'Done' });
  const d = openDialog({ title, body: h('div', { class: 'form' }, h('p', { class: 'muted', text: message }), h('div', { class: 'row' }, code, copyButton(secret))), footer: [ok] });
  ok.addEventListener('click', d.close);
}

/** Confirm by typing a word (for destructive actions). */
export function typedConfirm({ title, message, word, confirmText = 'Delete' }) {
  return new Promise((resolve) => {
    let result = false;
    const input = h('input', { class: 'input', 'aria-label': `Type ${word} to confirm`, autocomplete: 'off', spellcheck: 'false' });
    const ok = h('button', { class: 'btn danger solid', type: 'button', text: confirmText, disabled: true });
    const cancel = h('button', { class: 'btn', type: 'button', text: 'Cancel' });
    input.addEventListener('input', () => { ok.disabled = input.value.trim() !== word; });
    const d = openDialog({
      title,
      body: h('div', { class: 'form' }, h('p', { class: 'muted', text: message }), h('label', { class: 'small', text: `Type ${word} to confirm` }), input),
      footer: [cancel, ok], onClose: () => resolve(result),
    });
    cancel.addEventListener('click', d.close);
    ok.addEventListener('click', () => { result = true; d.close(); });
    setTimeout(() => input.focus(), 30);
  });
}

/** Poll-style loader: renders into holder with error handling. */
export async function loadInto(holder, fn) {
  try { await fn(); } catch (e) { if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, () => loadInto(holder, fn)) })); }
}
