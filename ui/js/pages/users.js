'use strict';
import {
  api, card, confirmDialog, errorState, field, fmtAgo, formDialog, h, icon, moreButton, selectField, setActions,
  setSub, skeletonRows, state, table, toast,
} from '../core.js';

function siteChecklist(sites, selected) {
  const box = h('div', { class: 'field site-picker' }, h('span', { class: 'label', text: 'Sites this user can manage' }));
  if (!sites.length) box.append(h('p', { class: 'muted small', text: 'There are no sites yet.' }));
  for (const s of sites) {
    box.append(h('label', { class: 'check' }, h('input', { type: 'checkbox', name: `site_${s.id}`, checked: selected.includes(s.id) }), s.domain));
  }
  return box;
}
const pickedSites = (d, sites) => sites.filter((s) => d[`site_${s.id}`]).map((s) => s.id);

function userDialog(sites, user, done) {
  const roleSel = selectField({ label: 'Role', name: 'role', value: user ? user.role : 'site_manager', options: [['admin', 'Administrator (full access)'], ['site_manager', 'Site manager (assigned sites only)']] });
  const picker = siteChecklist(sites, user ? user.site_ids : []);
  const sync = () => { picker.hidden = roleSel.querySelector('select').value !== 'site_manager'; };
  roleSel.querySelector('select').addEventListener('change', sync);
  sync();
  formDialog({
    title: user ? `Edit ${user.username}` : 'Add user', submitText: user ? 'Save' : 'Create user', drawer: true,
    content: [
      !user && field({ label: 'Username', name: 'username', validate: 'username', attrs: { autocapitalize: 'off', spellcheck: 'false' } }),
      field({ label: 'Email', name: 'email', type: 'email', value: user ? user.email : '', validate: 'email' }),
      !user && field({ label: 'Password', name: 'password', type: 'password', validate: 'password', hint: 'At least 10 characters. The user can change it later.', attrs: { autocomplete: 'new-password' } }),
      roleSel, picker,
    ].filter(Boolean),
    async onSubmit(d) {
      const body = { email: d.email, role: d.role, site_ids: pickedSites(d, sites) };
      if (user) await api(`/users/${user.id}`, { method: 'PUT', body });
      else await api('/users', { method: 'POST', body: { ...body, username: d.username, password: d.password } });
      toast(user ? 'User updated' : `${d.username} created`);
      done();
    },
  });
}

export function renderUsers(view) {
  const holder = h('div', null, card({ flush: true, body: table(['User', 'Role', '2FA', ''], skeletonRows(4, 3)) }));
  view.replaceChildren(holder);
  let sites = [];
  setActions(h('button', { class: 'btn primary', onclick: () => userDialog(sites, null, load) }, icon('plus'), 'Add user'));

  async function load() {
    try {
      const [users, s] = await Promise.all([api('/users'), api('/sites')]);
      sites = s;
      setSub(`${users.length} user${users.length === 1 ? '' : 's'}`);
      holder.replaceChildren(card({ flush: true, body: table(['User', 'Role', { label: 'Sites', class: 'hide-sm' }, '2FA', { label: 'Updated', class: 'hide-sm' }, ''], users.map((u) => {
        const me = u.id === state.user.id;
        const items = [
          { icon: 'edit', label: 'Edit', action: () => userDialog(sites, u, load) },
          { icon: 'lock', label: 'Set password', action: () => formDialog({
            title: `New password for ${u.username}`, submitText: 'Set password',
            content: [field({ label: 'Password', name: 'password', type: 'password', validate: 'password', attrs: { autocomplete: 'new-password' } })],
            async onSubmit(d) { const r = await api(`/users/${u.id}/password`, { method: 'POST', body: { password: d.password } }); toast(r.message); },
          }) },
        ];
        if (u.totp_enabled && !me) items.push({ icon: 'key', label: 'Reset 2FA', action: async () => {
          if (!(await confirmDialog({ title: `Turn off 2FA for ${u.username}?`, message: 'Use this if they lost their authenticator and recovery codes. They should enable it again after signing in.', confirmText: 'Turn off 2FA', danger: true }))) return;
          try { const r = await api(`/users/${u.id}/2fa`, { method: 'DELETE' }); toast(r.message); load(); } catch (e) { toast(e.message, 'error'); }
        } });
        if (!me) items.push('-', { icon: 'trash', label: 'Delete user', danger: true, action: async () => {
          if (!(await confirmDialog({ title: `Delete ${u.username}?`, message: 'The user can no longer sign in. Sites are not affected.', confirmText: 'Delete', danger: true }))) return;
          try { await api(`/users/${u.id}`, { method: 'DELETE' }); toast('User deleted'); load(); } catch (e) { toast(e.message, 'error'); }
        } });
        const siteNames = u.role === 'admin' ? 'All sites' : (u.site_ids.map((id) => (sites.find((s) => s.id === id) || {}).domain).filter(Boolean).join(', ') || 'None');
        return h('tr', null,
          h('td', null, h('div', { class: 'cell-title', text: u.username + (me ? ' (you)' : '') }), h('div', { class: 'cell-sub', text: u.email })),
          h('td', null, h('span', { class: `badge ${u.role === 'admin' ? 'accent' : ''}`, text: u.role === 'admin' ? 'Administrator' : 'Site manager' })),
          h('td', { class: 'hide-sm muted truncate', text: siteNames }),
          h('td', null, u.totp_enabled ? h('span', { class: 'badge ok' }, icon('lock'), 'On') : h('span', { class: 'badge warn', text: 'Off' })),
          h('td', { class: 'hide-sm muted', text: fmtAgo(u.updated_at) }),
          h('td', { class: 'actions' }, moreButton(items)));
      })) }));
    } catch (e) { if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) })); }
  }
  load();
}
