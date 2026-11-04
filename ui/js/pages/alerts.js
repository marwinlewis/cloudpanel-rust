'use strict';
import {
  api, card, confirmDialog, emptyState, errorState, field, fmtAgo, formDialog, h, icon, moreButton, selectField,
  setActions, setSub, table, toast, withBusy,
} from '../core.js';

const KINDS = { email: 'Email', webhook: 'Webhook (JSON)', slack: 'Slack', discord: 'Discord' };

function channelDialog(done) {
  const kindSel = selectField({ label: 'Type', name: 'kind', value: 'email', options: Object.entries(KINDS) });
  const email = h('div', { class: 'form' },
    h('div', { class: 'form-grid' },
      field({ label: 'SMTP host', name: 'host', placeholder: 'smtp.example.com', validate: 'required' }),
      field({ label: 'Port', name: 'port', type: 'number', value: '587', validate: 'port' }),
      selectField({ label: 'Security', name: 'security', value: 'starttls', options: [['starttls', 'STARTTLS'], ['tls', 'TLS (465)'], ['none', 'None']] })),
    h('div', { class: 'form-grid' },
      field({ label: 'Username', name: 'username', attrs: { autocomplete: 'off' } }),
      field({ label: 'Password', name: 'password', type: 'password', attrs: { autocomplete: 'off' } })),
    field({ label: 'From', name: 'from', type: 'email', placeholder: 'panel@example.com', validate: 'email' }),
    field({ label: 'To', name: 'to', placeholder: 'ops@example.com, me@example.com', validate: 'required', hint: 'Comma-separated.' }));
  const hook = h('div', { class: 'form', hidden: true }, field({ label: 'Webhook URL', name: 'url', placeholder: 'https://hooks.slack.com/services/…', validate: 'required' }));
  kindSel.querySelector('select').addEventListener('change', (e) => { const isEmail = e.target.value === 'email'; email.hidden = !isEmail; hook.hidden = isEmail; });
  formDialog({
    title: 'Add notification channel', submitText: 'Add channel', drawer: true,
    content: [field({ label: 'Name', name: 'name', placeholder: 'Ops team', validate: 'required' }), kindSel, email, hook],
    async onSubmit(d) {
      const body = d.kind === 'email'
        ? { name: d.name, kind: 'email', host: d.host, port: Number(d.port), security: d.security, username: d.username || '', password: d.password || '', from: d.from, to: d.to }
        : { name: d.name, kind: d.kind, url: d.url };
      await api('/alerts/channels', { method: 'POST', body });
      toast('Channel added. Send a test to check it.');
      done();
    },
  });
}

export function renderAlerts(view) {
  const holder = h('div', null, card({ body: h('div', { class: 'skeleton' }) }));
  view.replaceChildren(holder);
  setActions(h('button', { class: 'btn primary', onclick: () => channelDialog(load) }, icon('plus'), 'Add channel'));

  async function load() {
    let r;
    try { r = await api('/alerts'); } catch (e) { if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) })); return; }
    setSub(r.firing.length ? `${r.firing.length} active alert${r.firing.length === 1 ? '' : 's'}` : 'No active alerts');
    const channels = r.channels.length ? table(['Channel', 'Type', { label: 'Destination', class: 'hide-sm' }, ''], r.channels.map((c) => {
      const test = h('button', { class: 'btn sm', type: 'button', text: 'Send test' });
      test.addEventListener('click', () => withBusy(test, async () => { const x = await api(`/alerts/channels/${c.id}/test`, { method: 'POST' }); toast(x.message); }));
      return h('tr', null,
        h('td', null, h('div', { class: 'cell-title', text: c.name }), !c.enabled && h('div', { class: 'cell-sub', text: 'Paused' })),
        h('td', null, h('span', { class: 'badge', text: KINDS[c.kind] || c.kind })),
        h('td', { class: 'hide-sm muted mono truncate', text: c.summary }),
        h('td', { class: 'actions' }, test, moreButton([
          { icon: c.enabled ? 'stop' : 'play', label: c.enabled ? 'Pause' : 'Resume', action: async () => { await api(`/alerts/channels/${c.id}`, { method: 'PATCH', body: { enabled: !c.enabled } }); load(); } },
          '-',
          { icon: 'trash', label: 'Delete', danger: true, action: async () => {
            if (!(await confirmDialog({ title: `Delete ${c.name}?`, message: 'No more notifications are sent to this channel.', confirmText: 'Delete', danger: true }))) return;
            await api(`/alerts/channels/${c.id}`, { method: 'DELETE' }); toast('Channel deleted'); load();
          } },
        ])));
    })) : h('div', { class: 'card-body' }, emptyState({ iconName: 'bell', title: 'No channels yet', text: 'Add an email address or a Slack/Discord/webhook URL to receive alerts.' }));

    const rl = r.rules;
    const form = h('form', { class: 'form', novalidate: true },
      h('div', { class: 'form-grid' },
        field({ label: 'Disk usage above (%)', name: 'disk_pct', type: 'number', value: rl.disk_pct, attrs: { min: 1, max: 100 } }),
        field({ label: 'Memory above (%)', name: 'memory_pct', type: 'number', value: rl.memory_pct, attrs: { min: 1, max: 100 } }),
        field({ label: 'CPU above (%)', name: 'cpu_pct', type: 'number', value: rl.cpu_pct, attrs: { min: 1, max: 100 } })),
      h('div', { class: 'form-grid' },
        field({ label: 'For at least (minutes)', name: 'sustain_minutes', type: 'number', value: rl.sustain_minutes, hint: 'CPU and memory only.', attrs: { min: 1, max: 60 } }),
        field({ label: 'Certificate expires within (days)', name: 'cert_days', type: 'number', value: rl.cert_days, attrs: { min: 1, max: 90 } })),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'services', checked: rl.services }), 'A service or site app stops running'),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'backups', checked: rl.backups }), 'A backup fails'),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'security', checked: rl.security }), 'Security events (new administrator, 2FA turned off)'),
      h('div', null, h('button', { class: 'btn primary', type: 'submit', text: 'Save rules' })));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = form.elements;
      await withBusy(form.querySelector('button[type=submit]'), async () => {
        const x = await api('/alerts/rules', { method: 'PUT', body: {
          disk_pct: Number(f.disk_pct.value), memory_pct: Number(f.memory_pct.value), cpu_pct: Number(f.cpu_pct.value),
          sustain_minutes: Number(f.sustain_minutes.value), cert_days: Number(f.cert_days.value),
          services: f.services.checked, backups: f.backups.checked, security: f.security.checked,
        } });
        toast(x.message);
      });
    });

    holder.replaceChildren(
      r.firing.length ? card({ title: 'Active alerts', body: h('div', { class: 'form' }, ...r.firing.map((a) => h('div', { class: 'row' }, h('span', { class: 'dot danger' }), h('span', { class: 'grow mono', text: a.key }), h('span', { class: 'small muted', text: a.since ? `since ${fmtAgo(a.since)}` : '' })))) }) : '',
      card({ title: 'Notification channels', sub: 'Alerts are sent when a condition starts, every 6 hours while it lasts, and when it clears.', flush: true, body: channels }),
      card({ title: 'Rules', sub: 'Checked every minute.', body: form }));
  }
  load();
}
