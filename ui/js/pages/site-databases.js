'use strict';
import {
  api, card, confirmDialog, download, emptyState, errorState, field, fmtDate, formDialog, h, icon, moreButton, openDialog,
  secretDialog, selectField, skeletonRows, table, toast, upload, VALIDATORS,
} from '../core.js';
import { SITE_TABS } from './site-tabs.js';

VALIDATORS.dbident = (v) => (/^[a-z][a-z0-9_]{0,31}$/.test(v) ? '' : 'Lowercase letters, digits and _ (start with a letter, max 32)');
VALIDATORS.dbpassword = (v) => (!v || /^[A-Za-z0-9!#%+,\-./:=@^_~]{10,64}$/.test(v) ? '' : '10-64 characters; letters, digits and ! # % + , - . / : = @ ^ _ ~');

let enginesCache = null;
async function engines() {
  if (!enginesCache) enginesCache = await api('/databases/engines');
  return enginesCache;
}

function suggestName(site) {
  return site.system_user.replace(/-/g, '_').replace(/[^a-z0-9_]/g, '').slice(0, 24) || 'app';
}

function renderDatabases(el, { site }) {
  const holder = h('div', null, card({ flush: true, body: table(['Database', 'Engine', 'Users', ''], skeletonRows(4, 2)) }));
  const add = h('button', { class: 'btn primary' }, icon('plus'), 'Add database');
  const note = h('div');
  add.addEventListener('click', () => createDialog());
  el.append(note, h('div', { class: 'row end' }, add), holder);

  async function createDialog() {
    const list = (await engines()).filter((e) => e.available);
    if (!list.length) { toast('No database engine is available on this server', 'error'); return; }
    const userFields = h('div', { class: 'form' },
      field({ label: 'Username', name: 'username', placeholder: 'defaults to the database name', hint: 'A user with full access to this database.', attrs: { autocapitalize: 'off', spellcheck: 'false' } }),
      field({ label: 'Password (optional)', name: 'password', type: 'password', validate: 'dbpassword', hint: 'Leave empty to generate a strong password.', attrs: { autocomplete: 'new-password' } }));
    const engineSel = selectField({ label: 'Engine', name: 'engine', value: list[0].engine, options: list.map((e) => [e.engine, e.label]) });
    const sync = () => { const e = list.find((x) => x.engine === engineSel.querySelector('select').value); userFields.hidden = !e.has_users; };
    engineSel.querySelector('select').addEventListener('change', sync);
    sync();
    formDialog({
      title: 'Add database', submitText: 'Create database',
      content: [engineSel, field({ label: 'Database name', name: 'name', value: suggestName(site), validate: 'dbident', attrs: { autocapitalize: 'off', spellcheck: 'false' } }), userFields],
      async onSubmit(d) {
        const r = await api(`/sites/${site.id}/databases`, { method: 'POST', body: { engine: d.engine, name: d.name, username: d.username || null, password: d.password || null } });
        load();
        if (r.password) secretDialog('Database created', `Connect as ${r.username} to ${d.name}. The password is shown only once.`, r.password);
        else toast(r.path ? `Created ${r.path}` : 'Database created');
      },
    });
  }

  function userDialog(dbr) {
    formDialog({
      title: `Add user to ${dbr.name}`, submitText: 'Add user',
      content: [field({ label: 'Username', name: 'username', validate: 'dbident' }), field({ label: 'Password (optional)', name: 'password', type: 'password', validate: 'dbpassword', hint: 'Leave empty to generate one.' })],
      async onSubmit(d) {
        const r = await api(`/databases/${dbr.id}/users`, { method: 'POST', body: { username: d.username, password: d.password || null } });
        load();
        secretDialog('User added', `Password for ${r.username} (shown only once):`, r.password);
      },
    });
  }

  async function resetPassword(dbr, user) {
    if (!(await confirmDialog({ title: `Reset password for ${user}?`, message: 'A new random password is set. Update your app configuration afterwards.', confirmText: 'Reset password' }))) return;
    try {
      const r = await api(`/databases/${dbr.id}/users/${encodeURIComponent(user)}/password`, { method: 'POST', body: {} });
      secretDialog('Password reset', `New password for ${user}:`, r.password);
    } catch (e) { toast(e.message, 'error'); }
  }

  function importDialog(dbr) {
    const input = h('input', { type: 'file', class: 'input', 'aria-label': 'Dump file' });
    const bar = h('div', { class: 'progress' }, h('span'));
    const go = h('button', { class: 'btn primary', type: 'button', text: 'Import' });
    const d = openDialog({
        title: `Import into ${dbr.name}`,
        description: dbr.engine === 'mariadb' ? 'Upload a .sql or .sql.gz dump.' : dbr.engine === 'mongodb' ? 'Upload a mongodump --archive file (.archive or .archive.gz).' : 'Upload a SQLite database file. It replaces the current database.',
        body: h('div', { class: 'form' }, h('div', { class: 'alert warn' }, icon('alert'), h('div', { text: 'Existing data may be overwritten.' })), input, bar),
        footer: [go],
      });
    go.addEventListener('click', async () => {
      if (!input.files[0]) { toast('Choose a file first', 'error'); return; }
      const fd = new FormData();
      fd.append('file', input.files[0], input.files[0].name);
      go.disabled = true;
      try {
        await upload(`/databases/${dbr.id}/import`, fd, (p) => { bar.firstChild.style.width = `${Math.round(p * 100)}%`; });
        toast('Import complete');
        d.close();
      } catch (e) { toast(e.message, 'error'); } finally { go.disabled = false; }
    });
  }

  async function load() {
    try {
      const [list, eng] = await Promise.all([api(`/sites/${site.id}/databases`), engines()]);
      const avail = eng.filter((e) => e.available);
      note.replaceChildren(avail.length ? '' : h('div', { class: 'alert info' }, icon('database'), h('div', { text: 'No database engine is enabled on this server. Re-run the installer with --with-mariadb, --with-mongodb or --with-sqlite.' })));
      add.disabled = !avail.length;
      if (!list.length) {
        holder.replaceChildren(card({ body: emptyState({ iconName: 'database', title: 'No databases', text: `Available here: ${avail.map((e) => e.label).join(', ') || 'none'}.` }) }));
        return;
      }
      const label = (e) => (eng.find((x) => x.engine === e) || { label: e }).label;
      holder.replaceChildren(card({ flush: true, body: table(['Database', 'Engine', { label: 'Users', class: 'hide-sm' }, { label: 'Created', class: 'hide-sm' }, ''], list.map((d) => {
        const items = [
          { icon: 'download', label: 'Export / download', action: () => download(`/databases/${d.id}/export`) },
          { icon: 'upload', label: 'Import', action: () => importDialog(d) },
        ];
        if (d.engine !== 'sqlite') {
          items.push({ icon: 'user', label: 'Add user', action: () => userDialog(d) });
          for (const u of d.users) items.push({ icon: 'key', label: `Reset password · ${u}`, action: () => resetPassword(d, u) });
          for (const u of d.users) items.push({ icon: 'trash', label: `Remove user · ${u}`, danger: true, action: async () => {
            if (!(await confirmDialog({ title: `Remove ${u}?`, message: 'The user can no longer connect.', confirmText: 'Remove', danger: true }))) return;
            try { await api(`/databases/${d.id}/users/${encodeURIComponent(u)}`, { method: 'DELETE' }); toast('User removed'); load(); } catch (e) { toast(e.message, 'error'); }
          } });
        }
        items.push('-', { icon: 'trash', label: 'Delete database', danger: true, action: async () => {
          if (!(await confirmDialog({ title: `Delete ${d.name}?`, message: 'The database, its data and its users are deleted permanently.', confirmText: 'Delete database', danger: true }))) return;
          try { await api(`/databases/${d.id}`, { method: 'DELETE' }); toast('Database deleted'); load(); } catch (e) { toast(e.message, 'error'); }
        } });
        return h('tr', null,
          h('td', null, h('div', { class: 'cell-title mono', text: d.name })),
          h('td', null, h('span', { class: 'badge', text: label(d.engine) })),
          h('td', { class: 'hide-sm mono muted', text: d.engine === 'sqlite' ? '—' : (d.users.join(', ') || 'none') }),
          h('td', { class: 'hide-sm muted', text: fmtDate(d.created_at) }),
          h('td', { class: 'actions' }, moreButton(items)));
      })) }));
    } catch (e) { if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) })); }
  }
  load();
}

SITE_TABS.push({ key: 'databases', label: 'Databases', when: (s) => !!s.home_dir, render: renderDatabases });
