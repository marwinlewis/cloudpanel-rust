'use strict';
import {
  api, card, confirmDialog, emptyState, errorState, field, formDialog, h, icon, openDialog, selectField, setActions,
  setSub, skeletonRows, table, tabStrip, toast, withBusy, VALIDATORS,
} from '../core.js';

VALIDATORS.portrange = (v) => (/^\d{1,5}([:-]\d{1,5})?$/.test(v) ? '' : 'A port (443) or range (6000:6010)');
VALIDATORS.optionalCidr = (v) => (!v || /^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(v) ? '' : 'An IP address or CIDR, e.g. 203.0.113.0/24');
VALIDATORS.cidr = (v) => (/^[0-9a-fA-F:.]+(\/\d{1,3})?$/.test(v) ? '' : 'An IP address or CIDR, e.g. 203.0.113.9');

function describe(r) {
  if (r.port == null) return 'All traffic';
  const ports = r.port_end ? `${r.port}–${r.port_end}` : `${r.port}`;
  return r.protocol === 'any' ? ports : `${ports}/${r.protocol}`;
}

export function renderFirewall(view) {
  const holder = h('div', null, card({ flush: true, body: table(['Rule', 'Source', 'Action', 'Comment', ''], skeletonRows(5)) }));
  const status = h('div');
  view.replaceChildren(status, holder);
  setActions(
    h('button', { class: 'btn', onclick: () => blockDialog(load) }, icon('shield'), h('span', { class: 'hide-sm', text: 'Block IP' })),
    h('button', { class: 'btn primary', onclick: () => addRuleDialog(load) }, icon('plus'), 'Add rule'));

  async function loadStatus() {
    try {
      const s = await api('/firewall/status');
      const raw = h('button', { class: 'btn sm', type: 'button', text: 'View ufw status' });
      raw.addEventListener('click', () => openDialog({ title: 'ufw status verbose', drawer: true, body: h('pre', { class: 'logs mono', text: s.raw || '' }) }));
      status.replaceChildren(!s.installed
        ? h('div', { class: 'alert warn' }, icon('alert'), h('div', { text: 'UFW is not installed; rules are stored but not applied.' }))
        : h('div', { class: `alert ${s.active ? 'info' : 'warn'}` }, icon('shield'),
          h('div', { class: 'grow', text: s.active ? `UFW is active. SSH (${s.ssh_ports.join(', ')}) and the panel port cannot be blocked for your own address.` : 'UFW is installed but inactive, so these rules have no effect.' }), raw));
    } catch { /* shown by the table */ }
  }

  async function load() {
    loadStatus();
    try {
      const rules = await api('/firewall/rules');
      setSub(`${rules.length} custom rule${rules.length === 1 ? '' : 's'}`);
      if (!rules.length) {
        holder.replaceChildren(card({ body: emptyState({
          iconName: 'shield', title: 'No custom rules', text: 'Open ports, allow a port only from an address, or block an IP.',
          action: h('button', { class: 'btn primary', onclick: () => addRuleDialog(load) }, icon('plus'), 'Add rule'),
        }) }));
        return;
      }
      holder.replaceChildren(card({ flush: true, body: table(['Rule', 'Source', 'Action', { label: 'Comment', class: 'hide-sm' }, ''], rules.map((r) => {
        const del = h('button', { class: 'icon-btn danger', title: 'Delete rule', 'aria-label': 'Delete rule' }, icon('trash'));
        del.addEventListener('click', async () => {
          if (!(await confirmDialog({ title: 'Delete this rule?', message: `${r.action} ${describe(r)} from ${r.source || 'anywhere'} will be removed from UFW.`, confirmText: 'Delete', danger: true }))) return;
          await withBusy(del, async () => { await api(`/firewall/rules/${r.id}`, { method: 'DELETE' }); toast('Rule removed'); await load(); });
        });
        return h('tr', null,
          h('td', { class: 'mono' }, describe(r), r.port == null && h('span', { class: 'badge danger ml', text: 'Blocked IP' })),
          h('td', { class: 'mono muted', text: r.source || 'Anywhere' }),
          h('td', null, h('span', { class: `badge ${r.action === 'allow' ? 'ok' : 'danger'}`, text: r.action === 'allow' ? 'Allow' : 'Deny' })),
          h('td', { class: 'hide-sm muted', text: r.comment || '—' }),
          h('td', { class: 'actions' }, del));
      })) }));
    } catch (e) {
      if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) }));
    }
  }
  load();
}

function addRuleDialog(done) {
  formDialog({
    title: 'Add firewall rule',
    submitText: 'Add rule',
    content: [
      h('div', { class: 'form-grid' },
        field({ label: 'Port or range', name: 'port', placeholder: '3306 or 6000:6010', validate: 'portrange', attrs: { inputmode: 'numeric' } }),
        selectField({ label: 'Protocol', name: 'protocol', value: 'tcp', options: [['tcp', 'TCP'], ['udp', 'UDP'], ['any', 'Any']] }),
        selectField({ label: 'Action', name: 'action', value: 'allow', options: [['allow', 'Allow'], ['deny', 'Deny']] })),
      field({ label: 'From (optional)', name: 'source', placeholder: 'Anywhere, or 203.0.113.0/24', validate: 'optionalCidr', hint: 'Limit the rule to one IP address or network.' }),
      field({ label: 'Comment (optional)', name: 'comment', placeholder: 'e.g. MySQL for app server', attrs: { maxlength: 120 } }),
    ],
    async onSubmit(d) {
      await api('/firewall/rules', { method: 'POST', body: { kind: 'port', port: d.port, protocol: d.protocol, action: d.action, source: d.source || null, comment: d.comment || null } });
      toast(`Rule added for ${d.port}`);
      done();
    },
  });
}

function blockDialog(done) {
  formDialog({
    title: 'Block an IP address', description: 'All traffic from the address or network is dropped. The rule is placed first.',
    submitText: 'Block',
    content: [
      field({ label: 'IP or network', name: 'source', placeholder: '203.0.113.9', validate: 'cidr' }),
      field({ label: 'Comment (optional)', name: 'comment', attrs: { maxlength: 120 } }),
    ],
    async onSubmit(d) {
      await api('/firewall/rules', { method: 'POST', body: { kind: 'block', source: d.source, comment: d.comment || null } });
      toast(`${d.source} blocked`);
      done();
    },
  });
}

export { tabStrip };
