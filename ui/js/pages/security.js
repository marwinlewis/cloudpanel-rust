'use strict';
import { api, card, confirmDialog, errorState, field, formDialog, h, icon, kv, setActions, setSub, toast, withBusy } from '../core.js';

export function renderSecurity(view) {
  const holder = h('div', null, card({ body: h('div', { class: 'skeleton' }) }));
  view.replaceChildren(holder);
  const ban = h('button', { class: 'btn' }, icon('shield'), 'Ban IP');
  ban.addEventListener('click', () => formDialog({
    title: 'Ban an IP address', submitText: 'Ban',
    content: [
      field({ label: 'IP address', name: 'ip', validate: 'required', placeholder: '203.0.113.9' }),
      h('div', { class: 'field' }, h('label', { text: 'Jail' }), h('select', { class: 'input', name: 'jail' }, h('option', { value: 'sshd', text: 'SSH' }), h('option', { value: 'cloudpanel', text: 'Control panel' }))),
    ],
    async onSubmit(d) { await api('/fail2ban/ban', { method: 'POST', body: d }); toast(`${d.ip} banned`); load(); },
  }));
  setActions(ban);

  async function load() {
    let r;
    try { r = await api('/fail2ban'); } catch (e) { if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) })); return; }
    const s = r.settings;
    setSub(r.installed ? 'fail2ban is protecting SSH and the panel login' : 'fail2ban is not installed');
    const jails = r.jails.map((j) => card({
      title: j.jail === 'sshd' ? 'SSH' : 'Control panel login', sub: j.active ? `${j.currently_banned} banned now · ${j.total_banned} total` : 'Jail not running',
      body: h('div', { class: 'form' },
        kv([['Failed attempts (current)', j.currently_failed], ['Failed attempts (total)', j.total_failed]]),
        j.banned.length ? h('div', { class: 'form' }, ...j.banned.map((ip) => {
          const b = h('button', { class: 'btn sm', type: 'button', text: 'Unban' });
          b.addEventListener('click', () => withBusy(b, async () => { await api('/fail2ban/unban', { method: 'POST', body: { jail: j.jail, ip } }); toast(`${ip} unbanned`); load(); }));
          return h('div', { class: 'row' }, h('span', { class: 'grow mono', text: ip }), b);
        })) : h('p', { class: 'muted small', text: 'No banned addresses.' })),
    }));

    const form = h('form', { class: 'form', novalidate: true },
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'sshd', checked: s.sshd }), 'Protect SSH'),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'panel', checked: s.panel }), 'Protect the control panel login'),
      h('div', { class: 'form-grid' },
        field({ label: 'Max retries', name: 'maxretry', type: 'number', value: s.maxretry, attrs: { min: 1, max: 100 } }),
        field({ label: 'Within (minutes)', name: 'findtime_minutes', type: 'number', value: s.findtime_minutes, attrs: { min: 1, max: 1440 } }),
        field({ label: 'Ban for (minutes)', name: 'bantime_minutes', type: 'number', value: s.bantime_minutes, attrs: { min: 1 } })),
      field({ label: 'Never ban (one IP or CIDR per line)', name: 'ignoreip', type: 'textarea', value: s.ignoreip.join('\n'), attrs: { class: 'input mono', rows: 3 } }),
      h('div', null, h('button', { class: 'btn primary', type: 'submit', text: 'Save & apply' })));
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const f = form.elements;
      await withBusy(form.querySelector('button[type=submit]'), async () => {
        const res = await api('/fail2ban', { method: 'PUT', body: {
          sshd: f.sshd.checked, panel: f.panel.checked, maxretry: Number(f.maxretry.value),
          findtime_minutes: Number(f.findtime_minutes.value), bantime_minutes: Number(f.bantime_minutes.value),
          ignoreip: f.ignoreip.value.split('\n').map((x) => x.trim()).filter(Boolean),
        } });
        toast(res.message);
        load();
      });
    });
    holder.replaceChildren(
      !r.installed ? h('div', { class: 'alert warn' }, icon('alert'), h('div', { text: 'fail2ban is not installed. Install it with: apt install fail2ban (or re-run the CloudPanel installer). Settings are saved and applied once it is available.' })) : '',
      h('div', { class: 'grid two' }, ...jails),
      card({ title: 'Settings', sub: 'Applies to both jails. The panel also locks out an IP after 5 failed sign-ins in 15 minutes.', body: form }));
  }
  load();
  return null;
}

export { confirmDialog };
