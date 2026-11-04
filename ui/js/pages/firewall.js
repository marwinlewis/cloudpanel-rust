'use strict';
import {
  $, ApiError, DOMAIN_RE, PROPS, SVG_NS, VALIDATORS, api, append, card, closeMenu, confirmDialog, effectiveTheme, emptyState, errorState, field, fmtAgo, fmtBytes, fmtDate, fmtPct, fmtRate, fmtUptime, formData, formDialog, h, hooks, icon, isAdmin, media, moreButton, openDialog, openMenu, openMenuEl, rtf, selectField, setActions, setHost, setSub, setTheme, skeletonRows, spinner, state, store, svgEl, syncThemeIcon, table, toast, validateForm, withBusy,
} from '../core.js';

// ---------- Firewall ----------

export function renderFirewall(view) {
  const holder = h('div', null, card({ flush: true, body: table(['Port', 'Protocol', 'Action', 'Comment', ''], skeletonRows(5)) }));
  view.replaceChildren(
    h('div', { class: 'alert info' }, icon('shield'),
      h('div', { text: 'Rules are applied with UFW. SSH (22) and the panel port cannot be denied from here, so you can’t lock yourself out.' })),
    holder);
  setActions(h('button', { class: 'btn primary', onclick: () => addRuleDialog(load) }, icon('plus'), 'Add rule'));

  async function load() {
    try {
      const rules = await api('/firewall/rules');
      setSub(`${rules.length} custom rule${rules.length === 1 ? '' : 's'}`);
      if (!rules.length) {
        holder.replaceChildren(card({ body: emptyState({
          iconName: 'shield', title: 'No custom rules', text: 'Open or block ports on this server.',
          action: h('button', { class: 'btn primary', onclick: () => addRuleDialog(load) }, icon('plus'), 'Add rule'),
        }) }));
        return;
      }
      holder.replaceChildren(card({ flush: true, body: table(['Port', 'Protocol', 'Action', { label: 'Comment', class: 'hide-sm' }, ''], rules.map((r) => {
        const del = h('button', { class: 'icon-btn danger', title: 'Delete rule', 'aria-label': `Delete rule for port ${r.port}` }, icon('trash'));
        del.addEventListener('click', async () => {
          if (!(await confirmDialog({ title: `Delete rule for port ${r.port}?`, message: `The UFW "${r.action} ${r.port}/${r.protocol}" rule will be removed.`, confirmText: 'Delete', danger: true }))) return;
          await withBusy(del, async () => { await api(`/firewall/rules/${r.id}`, { method: 'DELETE' }); toast('Rule removed'); await load(); });
        });
        return h('tr', null,
          h('td', { class: 'mono', text: r.port }),
          h('td', { class: 'muted', text: r.protocol.toUpperCase() }),
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
        field({ label: 'Port', name: 'port', type: 'number', placeholder: '3306', validate: 'port', attrs: { min: 1, max: 65535, inputmode: 'numeric' } }),
        selectField({ label: 'Protocol', name: 'protocol', value: 'tcp', options: [['tcp', 'TCP'], ['udp', 'UDP'], ['any', 'Any']] }),
        selectField({ label: 'Action', name: 'action', value: 'allow', options: [['allow', 'Allow'], ['deny', 'Deny']] })),
      field({ label: 'Comment (optional)', name: 'comment', placeholder: 'e.g. MySQL for app server', attrs: { maxlength: 120 } }),
    ],
    async onSubmit(d) {
      await api('/firewall/rules', { method: 'POST', body: { port: Number(d.port), protocol: d.protocol, action: d.action, comment: d.comment || null } });
      toast(`Port ${d.port} ${d.action === 'allow' ? 'allowed' : 'denied'}`);
      done();
    },
  });
}
