'use strict';
import { api, card, download, emptyState, errorState, fmtDate, h, icon, setActions, setSub, skeletonRows, table } from '../core.js';

export function renderEvents(view) {
  const user = h('input', { class: 'input', placeholder: 'User', 'aria-label': 'Filter by user', autocapitalize: 'off' });
  const action = h('select', { class: 'input', 'aria-label': 'Filter by action' },
    [['', 'All actions'], ['auth', 'Sign-ins & account'], ['site', 'Sites'], ['app', 'Apps'], ['ssh', 'SSH users'], ['database', 'Databases'], ['files', 'Files'], ['backup', 'Backups'], ['firewall', 'Firewall'], ['fail2ban', 'fail2ban'], ['cron', 'Cron'], ['docker', 'Docker'], ['service', 'Services'], ['updates', 'Updates'], ['user', 'Users'], ['alerts', 'Alerts']].map(([v, t]) => h('option', { value: v, text: t })));
  const since = h('input', { class: 'input', type: 'date', 'aria-label': 'Since' });
  for (const el of [user, action, since]) el.style.width = 'auto';
  const tbody = h('tbody', null, skeletonRows(5, 6));
  const more = h('button', { class: 'btn', hidden: true }, 'Load more');
  const holder = h('div');
  const tableEl = h('div', { class: 'table-wrap' }, h('table', null,
    h('thead', null, h('tr', null, h('th', { text: 'Time' }), h('th', { text: 'User' }), h('th', { text: 'Action' }), h('th', { text: 'Target' }), h('th', { class: 'hide-sm', text: 'Details' }), h('th', { class: 'hide-sm', text: 'IP' }))),
    tbody));
  holder.append(tableEl);
  view.replaceChildren(card({
    flush: true,
    body: h('div', null, h('div', { class: 'card-head' }, h('div', { class: 'toolbar row wrap grow' }, user, action, since)), holder, h('div', { class: 'card-body row' }, more)),
  }));

  const query = (extra = {}) => {
    const q = new URLSearchParams();
    if (user.value.trim()) q.set('username', user.value.trim());
    if (action.value) q.set('action', action.value);
    if (since.value) q.set('since', new Date(`${since.value}T00:00:00`).toISOString());
    for (const [k, v] of Object.entries(extra)) q.set(k, v);
    return q.toString();
  };
  setActions(h('button', { class: 'btn', onclick: () => download(`/events?${query({ format: 'csv' })}`) }, icon('download'), h('span', { class: 'hide-sm', text: 'Export CSV' })));

  let lastId = null;
  const row = (e) => h('tr', null,
    h('td', { class: 'nowrap muted small', text: fmtDate(e.created_at) }),
    h('td', { class: 'mono', text: e.username || '—' }),
    h('td', null, h('span', { class: `badge ${/failed|delete|ban|disable/.test(e.action) ? 'warn' : ''}`, text: e.action })),
    h('td', { class: 'mono truncate', text: e.target || '' }),
    h('td', { class: 'hide-sm muted truncate', text: e.detail || '' }),
    h('td', { class: 'hide-sm mono muted', text: e.ip || '' }));

  async function load(append = false) {
    try {
      const list = await api(`/events?${query({ limit: 100, ...(append && lastId ? { before: lastId } : {}) })}`);
      if (!append) {
        if (!list.length) { holder.replaceChildren(emptyState({ iconName: 'activity', title: 'No events', text: 'Nothing matches these filters.' })); more.hidden = true; return; }
        holder.replaceChildren(tableEl);
        tbody.replaceChildren(...list.map(row));
      } else tbody.append(...list.map(row));
      lastId = list.length ? list[list.length - 1].id : lastId;
      more.hidden = list.length < 100;
      setSub('Kept for 90 days');
    } catch (e) { if (e.status !== 401) holder.replaceChildren(errorState(e.message, () => load())); }
  }
  let t = null;
  user.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => load(), 300); });
  action.addEventListener('change', () => load());
  since.addEventListener('change', () => load());
  more.addEventListener('click', () => load(true));
  load();
}

export { table };
