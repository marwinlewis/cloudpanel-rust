'use strict';
import {
  api, card, confirmDialog, errorState, field, fmtBytes, fmtDate, formData, h, hooks, icon, isAdmin, kv, download,
  runJob, setTheme, state, store, table, toast, validateForm, withBusy,
} from '../core.js';

// Extra cards registered by feature modules: { admin, order, render() -> Element }
export const SETTINGS_CARDS = [];

function passwordCard() {
  const pwForm = h('form', { class: 'form', novalidate: true },
    field({ label: 'Current password', name: 'current_password', type: 'password', validate: 'required', attrs: { autocomplete: 'current-password' } }),
    field({ label: 'New password', name: 'new_password', type: 'password', validate: 'password', hint: 'At least 10 characters.', attrs: { autocomplete: 'new-password' } }),
    field({ label: 'Confirm new password', name: 'confirm', type: 'password', validate: 'confirm', attrs: { autocomplete: 'new-password' } }),
    h('div', null, h('button', { class: 'btn primary', type: 'submit', text: 'Update password' })));
  pwForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (!validateForm(pwForm)) return;
    const btn = pwForm.querySelector('button[type=submit]');
    const d = formData(pwForm);
    await withBusy(btn, async () => {
      const r = await api('/auth/password', { method: 'POST', body: { current_password: d.current_password, new_password: d.new_password } });
      pwForm.reset();
      toast(r.message);
    });
  });
  return card({ title: 'Password', sub: `Signed in as ${state.user.username}`, body: pwForm });
}

function appearanceCard() {
  const current = store.get('cp-theme') || 'system';
  const themeTabs = h('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Theme' },
    [['system', 'System'], ['light', 'Light'], ['dark', 'Dark']].map(([v, t]) => {
      const b = h('button', { type: 'button', role: 'tab', 'aria-selected': String(v === current), text: t });
      b.addEventListener('click', () => {
        setTheme(v);
        themeTabs.querySelectorAll('button').forEach((x) => x.setAttribute('aria-selected', String(x === b)));
      });
      return b;
    }));
  return card({ title: 'Appearance', body: themeTabs });
}

function sessionsCard() {
  const signOutAll = h('button', { class: 'btn danger' }, icon('logout'), 'Sign out everywhere');
  signOutAll.addEventListener('click', async () => {
    if (!(await confirmDialog({ title: 'Sign out everywhere?', message: 'Every session, including this one, will be signed out.', confirmText: 'Sign out all', danger: true }))) return;
    await withBusy(signOutAll, async () => { await api('/auth/logout-all', { method: 'POST' }); hooks.showLogin(); });
  });
  return card({ title: 'Sessions', sub: 'Sessions expire after 12 hours.', body: h('div', { class: 'form' },
    h('p', { class: 'muted small', text: 'Revoke access on all browsers and devices, for example if you signed in on a shared computer.' }),
    h('div', null, signOutAll)) });
}

function remoteStorageCard() {
  const body = h('div', { class: 'form' }, h('div', { class: 'skeleton' }));
  async function load() {
    let cfg;
    try { cfg = await api('/backups/remote'); } catch (e) { body.replaceChildren(errorState(e.message, load)); return; }
    const c = cfg || {};
    const form = h('form', { class: 'form', novalidate: true },
      field({ label: 'Endpoint', name: 'endpoint', value: c.endpoint || '', placeholder: 'https://s3.eu-central-1.amazonaws.com', validate: 'required', hint: 'AWS S3, Cloudflare R2, Backblaze B2, Wasabi or MinIO.' }),
      h('div', { class: 'form-grid' },
        field({ label: 'Bucket', name: 'bucket', value: c.bucket || '', validate: 'required' }),
        field({ label: 'Region', name: 'region', value: c.region || '', placeholder: 'us-east-1 / auto' })),
      h('div', { class: 'form-grid' },
        field({ label: 'Access key', name: 'access_key', value: c.access_key || '', validate: 'required', attrs: { autocomplete: 'off', spellcheck: 'false' } }),
        field({ label: 'Secret key', name: 'secret_key', type: 'password', placeholder: c.has_secret ? '(unchanged)' : '', validate: c.has_secret ? undefined : 'required', attrs: { autocomplete: 'off' } })),
      field({ label: 'Path prefix (optional)', name: 'prefix', value: c.prefix || '', placeholder: 'server-1' }),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'path_style', checked: !!c.path_style }), 'Path-style URLs (MinIO and most self-hosted servers)'),
      h('div', { class: 'row' }, h('button', { class: 'btn primary', type: 'submit', text: 'Test & save' }), cfg && h('button', { class: 'btn danger', type: 'button', text: 'Remove', onclick: remove })));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!validateForm(form)) return;
      const d = formData(form);
      await withBusy(form.querySelector('button[type=submit]'), async () => {
        const r = await api('/backups/remote', { method: 'PUT', body: d });
        toast(r.message);
        load();
      });
    });
    body.replaceChildren(form);
  }
  async function remove() {
    if (!(await confirmDialog({ title: 'Remove remote storage?', message: 'Scheduled backups stay local only. Existing remote copies are not deleted.', confirmText: 'Remove', danger: true }))) return;
    try { await api('/backups/remote', { method: 'DELETE' }); toast('Remote storage removed'); load(); } catch (e) { toast(e.message, 'error'); }
  }
  load();
  return card({ title: 'Backup storage', sub: 'Copy site backups to S3-compatible object storage. Keys are stored encrypted.', body });
}

function panelBackupCard() {
  const list = h('div');
  const btn = h('button', { class: 'btn' }, icon('archive'), 'Back up panel now');
  btn.addEventListener('click', async () => { try { await runJob('/backups/panel', 'Panel backup'); } catch (e) { toast(e.message, 'error'); } load(); });
  async function load() {
    try {
      const rows = await api('/backups/panel');
      list.replaceChildren(rows.length ? table(['Backup', { label: 'Size', class: 'num' }, ''], rows.slice(0, 5).map((b) => h('tr', null,
        h('td', null, h('div', { text: fmtDate(b.created_at) }), h('div', { class: 'cell-sub mono', text: b.status === 'ok' ? b.file_name : (b.error || b.status) })),
        h('td', { class: 'num muted', text: fmtBytes(b.size) }),
        h('td', { class: 'actions' }, b.status === 'ok' && h('button', { class: 'icon-btn', title: 'Download', 'aria-label': 'Download', onclick: () => download(`/backups/${b.id}/download`) }, icon('download'))))))
        : h('p', { class: 'muted small', text: 'No panel backups yet.' }));
    } catch (e) { list.replaceChildren(errorState(e.message, load)); }
  }
  load();
  return card({ title: 'Panel backup', sub: 'Database, /etc/cloudpanel, nginx vhosts and the cron file.', body: h('div', { class: 'form' }, h('div', null, btn), list) });
}

function databaseEnginesCard() {
  const body = h('div', { class: 'skeleton' });
  api('/databases/engines').then((list) => {
    body.replaceWith(kv(list.map((e) => [e.label, h('span', { class: `badge ${e.available ? 'ok' : ''}`, text: e.available ? 'Enabled' : e.configured ? 'Not installed' : 'Not enabled' })])));
  }).catch((e) => body.replaceWith(h('p', { class: 'muted', text: e.message })));
  return card({ title: 'Database engines', sub: 'Chosen when installing. Re-run the installer with --with-mariadb, --with-mongodb or --with-sqlite to add one.', body: h('div', null, body) });
}

export function renderSettings(view) {
  const left = [passwordCard()];
  const right = [appearanceCard(), sessionsCard()];
  const extra = SETTINGS_CARDS.filter((c) => !c.admin || isAdmin()).sort((a, b) => (a.order || 0) - (b.order || 0));
  for (const c of extra) (c.column === 'right' ? right : left).push(c.render());
  const admin = isAdmin() ? [remoteStorageCard(), h('div', { class: 'grid' }, panelBackupCard(), databaseEnginesCard())] : [];
  view.replaceChildren(
    h('div', { class: 'grid two' }, h('div', { class: 'grid' }, left), h('div', { class: 'grid' }, right)),
    admin.length ? h('h2', { class: 'section-title', text: 'Server' }) : '',
    admin.length ? h('div', { class: 'grid two' }, admin) : '');
}
