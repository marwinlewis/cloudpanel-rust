'use strict';
// Email: the email sending service on this server. Install it, then manage sending domains (and
// their DNS records), forwarding addresses, SMTP/API keys and webhooks, and follow the delivery log.
// Administrators only. Mail isn't stored or read here: addresses forward to another mailbox.
import {
  api, card, confirmDialog, copyButton, emptyState, errorState, field, fmtDate, formDialog, h, icon, jobDialog, kv, moreButton,
  openDialog, runJob, selectField, setActions, setSub, skeletonRows, table, tabStrip, toast, typedConfirm, withBusy,
  VALIDATORS,
} from '../core.js';

const BASE = '/mail';
const TABS = [['overview', 'Overview'], ['domains', 'Domains'], ['addresses', 'Addresses'], ['keys', 'API keys'], ['webhooks', 'Webhooks'], ['log', 'Log']];

VALIDATORS.localPart = (v) => (/^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}$/.test(v) && !v.startsWith('.') && !v.endsWith('.') ? '' : 'Letters, digits and . _ - + (no @)');
VALIDATORS.keyName = (v) => (v && v.length <= 64 ? '' : 'Use 1-64 characters');
VALIDATORS.hourly = (v) => (/^\d+$/.test(v) && +v >= 1 && +v <= 1000000 ? '' : 'A number from 1 to 1000000');
VALIDATORS.optionalEmail = (v) => (!v || /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? '' : 'Enter a valid email address');
VALIDATORS.webhookUrl = (v) => (/^https:\/\/\S+$/.test(v) || /^http:\/\/(localhost|127\.0\.0\.1|\[::1\])(:\d+)?(\/\S*)?$/.test(v) ? '' : 'Use an https:// URL (http only for localhost)');

const STATUS_BADGE = { delivered: 'ok', sent: 'accent', queued: '', delivery_delayed: 'warn', bounced: 'danger', failed: 'danger' };
const statusBadge = (s) => h('span', { class: `badge ${STATUS_BADGE[s] || ''}`, text: (s || '').replace('_', ' ') });
const yesNo = (ok, yes, no) => h('span', { class: `badge ${ok ? 'ok' : 'danger'}`, text: ok ? yes : no });

export function renderEmail(view, params) {
  let tab = TABS.some(([k]) => k === params[0]) ? params[0] : 'overview';
  let d = null;
  const body = h('div', { class: 'grid' });
  view.replaceChildren(card({ title: 'Email', body: skeletonRows(2) }));

  async function load() {
    try {
      d = await api(BASE);
    } catch (e) {
      if (e.status !== 401) view.replaceChildren(card({ body: errorState(e.message, load) }));
      return;
    }
    if (!d.installed) { renderNotInstalled(); return; }
    setSub(`${d.hostname} · ${d.domains.length} domain${d.domains.length === 1 ? '' : 's'}`);
    const strip = tabStrip(TABS, tab, (k) => { tab = k; history.replaceState(null, '', `#/email/${k}`); show(); });
    strip.classList.add('page-tabs');
    view.replaceChildren(strip, body);
    show();
  }

  function show() {
    setActions();
    body.replaceChildren();
    ({ overview, domains, addresses, keys, webhooks, log })[tab]();
  }

  function renderNotInstalled() {
    setSub('');
    setActions();
    const b = h('button', { class: 'btn primary', type: 'button' }, icon('download'), 'Install email service');
    b.addEventListener('click', () => installDialog(load));
    view.replaceChildren(card({ body: emptyState({
      iconName: 'mail', title: 'The email service is not installed',
      text: d.can_install
        ? 'Send mail from your own domains over SMTP (Gmail\'s "Send mail as" works) or an HTTP API, and forward mail sent to your addresses to another mailbox. It installs Postfix and runs as its own unprivileged user.'
        : 'This system can\'t install it from the panel. Run: cloudpanel mail-install --hostname mail.example.com',
      action: d.can_install && b,
    }) }));
  }

  // ---------- Overview ----------

  function overview() {
    const statusHolder = h('div', null, card({ title: 'Service', body: skeletonRows(2) }));
    const smtp = card({ title: 'Connecting apps', body: h('div', { class: 'form' },
      kv([
        ['SMTP server', h('span', { class: 'row' }, h('span', { class: 'mono', text: d.hostname }), copyButton(d.hostname))],
        ['Ports', '587 (STARTTLS) or 465 (SSL/TLS)'],
        ['Username', h('span', { class: 'mono', text: d.smtp_username })],
        ['Password', 'An API key (create one under API keys)'],
        ['HTTP API', h('span', { class: 'row' }, h('span', { class: 'mono', text: `https://${d.hostname}/emails` }), copyButton(`https://${d.hostname}/emails`))],
      ]),
      h('p', { class: 'hint', text: `Also set the reverse DNS (PTR) of this server's IP to ${d.hostname} at your hosting provider.` })) });
    const refresh = h('button', { class: 'btn', type: 'button' }, icon('refresh'), h('span', { class: 'hide-sm', text: 'Check again' }));
    refresh.addEventListener('click', () => withBusy(refresh, loadStatus));
    const remove = h('button', { class: 'btn danger', type: 'button' }, icon('trash'), h('span', { class: 'hide-sm', text: 'Uninstall' }));
    remove.addEventListener('click', uninstall);
    setActions(refresh, remove);
    body.replaceChildren(h('div', { class: 'grid two' }, statusHolder, smtp));

    async function loadStatus() {
      let r;
      try { r = await api(`${BASE}/status`); } catch (e) { statusHolder.replaceChildren(card({ title: 'Service', body: errorState(e.message, loadStatus) })); return; }
      const s = r.status;
      const nodes = [];
      if (!s.outbound_25) nodes.push(h('div', { class: 'alert warn' }, icon('alert'), h('div', { text: r.port_25_warning })));
      nodes.push(card({ title: 'Service', body: kv([
        ...s.units.map(([u, st]) => [u, yesNo(st === 'active', st, st)]),
        ...s.ports.map((p) => [p.name, yesNo(p.listening, 'listening', 'not listening')]),
        ['Outbound port 25', yesNo(s.outbound_25, 'open', 'blocked')],
        ['Domains', `${s.domains} (${s.verified_domains} verified)`],
        ['Addresses · keys', `${s.forwards} · ${s.keys}`],
      ]) }));
      statusHolder.replaceChildren(h('div', { class: 'stack' }, ...nodes));
    }
    loadStatus();
  }

  async function uninstall() {
    if (!(await typedConfirm({
      title: 'Uninstall the email service?',
      message: 'Sending through SMTP and the API stops and forwarding addresses stop receiving mail. Postfix, the domains, keys and logs are kept, so installing again brings them back.',
      word: 'uninstall', confirmText: 'Uninstall',
    }))) return;
    try {
      const job = await runJob(`${BASE}/uninstall`, 'Uninstalling the email service');
      if (job && job.status === 'succeeded') toast('The email service is uninstalled');
    } catch (e) { toast(e.message, 'error'); }
    load();
  }

  // ---------- Domains ----------

  function domains() {
    const add = h('button', { class: 'btn primary', type: 'button', onclick: () => domainDialog(load) }, icon('plus'), 'Add domain');
    setActions(add);
    if (!d.domains.length) {
      body.replaceChildren(card({ body: emptyState({
        iconName: 'globe', title: 'No sending domains yet',
        text: 'Add a domain you own, publish the DNS records it shows, then verify it. Mail can only be sent from verified domains.',
        action: h('button', { class: 'btn primary', type: 'button', onclick: () => domainDialog(load) }, icon('plus'), 'Add domain'),
      }) }));
      return;
    }
    body.replaceChildren(card({ title: 'Sending domains', flush: true, body: table(
      ['Domain', 'Status', { label: 'Added', class: 'hide-sm' }, ''],
      d.domains.map((dm) => h('tr', null,
        h('td', { class: 'strong mono', text: dm.name }),
        h('td', null, dm.verified ? h('span', { class: 'badge ok' }, icon('check'), 'Verified') : h('span', { class: 'badge warn', text: 'Pending DNS' })),
        h('td', { class: 'hide-sm muted', text: fmtDate(dm.created_at) }),
        h('td', { class: 'actions' },
          !dm.verified && h('button', { class: 'btn sm', type: 'button', onclick: () => verifyDialog(dm.name, load) }, 'Verify'),
          moreButton([
            { icon: 'globe', label: 'DNS records', action: () => recordsDialog(dm.name, dm.records) },
            { icon: 'check', label: 'Check DNS again', action: () => verifyDialog(dm.name, load) },
            '-',
            { icon: 'trash', label: 'Remove', danger: true, action: () => removeDomain(dm.name) },
          ])))),
    ) }));
  }

  async function removeDomain(name) {
    if (!(await confirmDialog({ title: `Remove ${name}?`, message: 'Its DKIM key, its forwarding addresses and the API keys limited to it are removed too. Mail from it can no longer be sent.', confirmText: 'Remove', danger: true }))) return;
    try { const r = await api(`${BASE}/domains/${encodeURIComponent(name)}`, { method: 'DELETE' }); toast(r.message); load(); } catch (e) { toast(e.message, 'error'); }
  }

  // ---------- Addresses ----------

  function addresses() {
    const names = d.domains.map((x) => x.name);
    const add = h('button', { class: 'btn primary', type: 'button', disabled: !names.length, onclick: () => forwardDialog(names, load) }, icon('plus'), 'Add address');
    setActions(add);
    const intro = h('div', { class: 'alert info' }, icon('mail'), h('div', { text: 'Mail sent to these addresses is forwarded to the mailbox you choose, such as Gmail. Nothing is stored on this server. The domain\'s MX record must point to ' + d.hostname + '.' }));
    if (!names.length) {
      body.replaceChildren(intro, card({ body: emptyState({ iconName: 'mail', title: 'Add a domain first', text: 'Addresses belong to one of your sending domains.' }) }));
      return;
    }
    if (!d.forwards.length) {
      body.replaceChildren(intro, card({ body: emptyState({
        iconName: 'mail', title: 'No addresses yet', text: 'Create an address like you@your-domain and forward it to your inbox.',
        action: h('button', { class: 'btn primary', type: 'button', onclick: () => forwardDialog(names, load) }, icon('plus'), 'Add address'),
      }) }));
      return;
    }
    body.replaceChildren(intro, card({ title: 'Addresses', flush: true, body: table(
      ['Address', 'Forwards to', { label: 'Added', class: 'hide-sm' }, ''],
      d.forwards.map((f) => h('tr', null,
        h('td', { class: 'strong mono', text: f.address }),
        h('td', { class: 'mono', text: f.forward_to }),
        h('td', { class: 'hide-sm muted', text: fmtDate(f.created_at) }),
        h('td', { class: 'actions' }, moreButton([
          { icon: 'edit', label: 'Change destination…', action: () => forwardDialog(names, load, f) },
          '-',
          { icon: 'trash', label: 'Remove', danger: true, action: () => removeForward(f.address) },
        ])))),
    ) }));
  }

  async function removeForward(address) {
    if (!(await confirmDialog({ title: `Remove ${address}?`, message: 'Mail sent to it will be refused. You can still send from it with an API key.', confirmText: 'Remove', danger: true }))) return;
    try { const r = await api(`${BASE}/forwards/${encodeURIComponent(address)}`, { method: 'DELETE' }); toast(r.message); load(); } catch (e) { toast(e.message, 'error'); }
  }

  // ---------- API keys ----------

  function keys() {
    setActions(h('button', { class: 'btn primary', type: 'button', onclick: () => keyDialog(d, load) }, icon('plus'), 'Create key'));
    if (!d.keys.length) {
      body.replaceChildren(card({ body: emptyState({
        iconName: 'key', title: 'No API keys yet',
        text: 'A key is the SMTP password (username ' + d.smtp_username + ') and the HTTP API\'s Bearer token. Create one per app or mailbox so you can revoke it alone.',
        action: h('button', { class: 'btn primary', type: 'button', onclick: () => keyDialog(d, load) }, icon('plus'), 'Create key'),
      }) }));
      return;
    }
    body.replaceChildren(card({ title: 'API keys', flush: true, body: table(
      ['Name', 'Sends from', { label: 'Permission', class: 'hide-sm' }, { label: 'Per hour', class: 'hide-sm' }, { label: 'Last used', class: 'hide-sm' }, ''],
      d.keys.map((k) => h('tr', null,
        h('td', null, h('div', { class: 'cell-title', text: k.name }), h('div', { class: 'cell-sub mono', text: k.id })),
        h('td', { class: 'muted', text: k.domain || 'Any domain' }),
        h('td', { class: 'hide-sm', text: k.permission }),
        h('td', { class: 'hide-sm', text: String(k.hourly_limit) }),
        h('td', { class: 'hide-sm muted', text: k.last_used_at ? fmtDate(k.last_used_at) : 'Never' }),
        h('td', { class: 'actions' }, moreButton([
          { icon: 'trash', label: 'Revoke', danger: true, action: () => revokeKey(k) },
        ])))),
    ) }));
  }

  async function revokeKey(k) {
    if (!(await confirmDialog({ title: `Revoke ${k.name}?`, message: 'Apps and mailboxes using this key can no longer send. This cannot be undone.', confirmText: 'Revoke', danger: true }))) return;
    try { const r = await api(`${BASE}/keys/${encodeURIComponent(k.id)}`, { method: 'DELETE' }); toast(r.message); load(); } catch (e) { toast(e.message, 'error'); }
  }

  // ---------- Webhooks ----------

  function webhooks() {
    setActions(h('button', { class: 'btn primary', type: 'button', onclick: () => webhookDialog(d, load) }, icon('plus'), 'Add webhook'));
    if (!d.webhooks.length) {
      body.replaceChildren(card({ body: emptyState({
        iconName: 'link', title: 'No webhooks',
        text: 'Call a URL when an email is sent, delivered, delayed or bounces. Requests are signed with svix-* headers, as Resend\'s are.',
        action: h('button', { class: 'btn primary', type: 'button', onclick: () => webhookDialog(d, load) }, icon('plus'), 'Add webhook'),
      }) }));
      return;
    }
    body.replaceChildren(card({ title: 'Webhooks', flush: true, body: table(
      ['URL', 'Events', { label: 'Added', class: 'hide-sm' }, ''],
      d.webhooks.map((w) => h('tr', null,
        h('td', { class: 'mono small truncate', text: w.url }),
        h('td', { class: 'small', text: w.events.length ? w.events.join(', ') : 'All events' }),
        h('td', { class: 'hide-sm muted', text: fmtDate(w.created_at) }),
        h('td', { class: 'actions' }, moreButton([
          { icon: 'trash', label: 'Remove', danger: true, action: () => removeWebhook(w) },
        ])))),
    ) }));
  }

  async function removeWebhook(w) {
    if (!(await confirmDialog({ title: 'Remove this webhook?', message: w.url, confirmText: 'Remove', danger: true }))) return;
    try { const r = await api(`${BASE}/webhooks/${encodeURIComponent(w.id)}`, { method: 'DELETE' }); toast(r.message); load(); } catch (e) { toast(e.message, 'error'); }
  }

  // ---------- Log ----------

  function log() {
    let status = '';
    const filter = h('select', { class: 'input', 'aria-label': 'Filter by status' },
      h('option', { value: '', text: 'All statuses' }),
      d.log_statuses.map((s) => h('option', { value: s, text: s.replace('_', ' ') })));
    filter.addEventListener('change', () => { status = filter.value; loadLog(); });
    const refresh = h('button', { class: 'btn', type: 'button' }, icon('refresh'), h('span', { class: 'hide-sm', text: 'Refresh' }));
    refresh.addEventListener('click', () => withBusy(refresh, loadLog));
    setActions(filter, refresh);
    const holder = h('div', null, card({ flush: true, body: table(['Sent', 'From', 'To', 'Subject', 'Status', ''], skeletonRows(6)) }));
    body.replaceChildren(holder);

    async function loadLog() {
      let r;
      try { r = await api(`${BASE}/log?limit=200${status ? `&status=${encodeURIComponent(status)}` : ''}`); } catch (e) { holder.replaceChildren(card({ body: errorState(e.message, loadLog) })); return; }
      if (!r.messages.length) {
        holder.replaceChildren(card({ body: emptyState({ iconName: 'mail', title: status ? 'No emails with this status' : 'No emails sent yet', text: 'Emails sent through SMTP or the API show up here for 30 days.' }) }));
        return;
      }
      holder.replaceChildren(card({ flush: true, body: table(
        ['Sent', 'From', { label: 'To', class: 'hide-sm' }, 'Subject', 'Status', ''],
        r.messages.map((m) => h('tr', null,
          h('td', { class: 'small muted', text: fmtDate(m.created_at) }),
          h('td', { class: 'small mono truncate', text: m.from }),
          h('td', { class: 'hide-sm small mono truncate', text: m.to.join(', ') }),
          h('td', { class: 'truncate', text: m.subject || '(no subject)' }),
          h('td', null, statusBadge(m.status)),
          h('td', { class: 'actions' }, h('button', { class: 'btn sm', type: 'button', onclick: () => messageDialog(m.id) }, 'Details')))),
      ) }));
    }
    loadLog();
  }

  load();
}

// ---------- Dialogs ----------

function installDialog(done) {
  formDialog({
    title: 'Install the email service',
    description: 'Point the mail hostname\'s A (and AAAA) record at this server first, so Let\'s Encrypt can issue its certificate. Ports 25, 465 and 587 are opened in the firewall.',
    submitText: 'Install',
    content: [
      field({ label: 'Mail hostname', name: 'hostname', placeholder: 'mail.example.com', validate: 'domain', hint: 'The SMTP server name and MX target. Not a hostname a site or the panel already uses.' }),
      field({ label: 'Email for Let\'s Encrypt', name: 'email', type: 'email', validate: 'optionalEmail', hint: 'Leave empty to start with a self-signed certificate (Gmail won\'t accept it until it is replaced).' }),
    ],
    async onSubmit(f, dlg) {
      const body = { hostname: f.hostname.toLowerCase(), email: f.email || null, self_signed: !f.email };
      const r = await api(`${BASE}/install`, { method: 'POST', body });
      dlg.close();
      const job = await jobDialog(r.job_id, 'Installing the email service');
      if (job && job.status === 'succeeded') toast('The email service is installed');
      done();
    },
  });
}

function recordRows(records) {
  return records.map((r) => h('div', { class: 'field' },
    h('div', { class: 'row between' },
      h('label', null, h('span', { class: 'badge', text: r.kind }), ' ', h('span', { class: 'mono', text: r.name }), r.priority != null ? h('span', { class: 'muted small', text: ` priority ${r.priority}` }) : null),
      h('span', { class: `badge ${r.required ? 'accent' : ''}`, text: r.required ? 'Required' : 'Recommended' })),
    h('div', { class: 'row' }, h('code', { class: 'mono secret', text: r.value }), copyButton(r.value)),
    h('div', { class: 'hint', text: r.purpose })));
}

function recordsDialog(domain, records) {
  const ok = h('button', { class: 'btn primary', type: 'button', text: 'Done' });
  const dlg = openDialog({
    title: `DNS records for ${domain}`,
    description: 'Add these at your DNS provider. If the domain already has a v=spf1 record, merge the mechanism into it instead of adding a second one.',
    wide: true,
    body: h('div', { class: 'form' }, recordRows(records)),
    footer: [ok],
  });
  ok.addEventListener('click', dlg.close);
}

function domainDialog(done) {
  formDialog({
    title: 'Add a sending domain',
    description: 'A DKIM key is created for it. You\'ll get the DNS records to publish next.',
    submitText: 'Add domain',
    content: [field({ label: 'Domain', name: 'domain', placeholder: 'example.com', validate: 'domain', attrs: { autocomplete: 'off', spellcheck: 'false' } })],
    async onSubmit(f, dlg) {
      const r = await api(`${BASE}/domains`, { method: 'POST', body: { domain: f.domain.toLowerCase() } });
      dlg.close();
      done();
      recordsDialog(r.name, r.records);
    },
  });
}

async function verifyDialog(domain, done) {
  const holder = h('div', { class: 'form' }, h('p', { class: 'muted', text: 'Looking up the DNS records…' }));
  const force = h('button', { class: 'btn', type: 'button', text: 'Mark verified anyway' });
  const close = h('button', { class: 'btn primary', type: 'button', text: 'Close' });
  const dlg = openDialog({ title: `Verify ${domain}`, wide: true, body: holder, footer: [force, close], onClose: done });
  close.addEventListener('click', dlg.close);
  force.addEventListener('click', async () => {
    if (!(await confirmDialog({ title: 'Skip the DNS check?', message: 'Use this only when this server can\'t see your public DNS (split-horizon DNS). Mail from a domain without DKIM and SPF is likely to be rejected or marked as spam.', confirmText: 'Mark verified' }))) return;
    try {
      await api(`${BASE}/domains/${encodeURIComponent(domain)}/verify`, { method: 'POST', body: { force: true } });
      toast(`${domain} marked verified`);
      dlg.close();
    } catch (e) { toast(e.message, 'error'); }
  });
  let v;
  try {
    v = await api(`${BASE}/domains/${encodeURIComponent(domain)}/verify`, { method: 'POST', body: { force: false } });
  } catch (e) { holder.replaceChildren(h('div', { class: 'alert error' }, icon('alert'), h('div', { text: e.message }))); return; }
  holder.replaceChildren(
    v.verified
      ? h('div', { class: 'alert info' }, icon('check'), h('div', { text: `${domain} is verified and can send.` }))
      : h('div', { class: 'alert warn' }, icon('alert'), h('div', { text: 'Not verified yet: DKIM and SPF are required. DNS changes can take a while to show up.' })),
    ...v.checks.map((c) => h('div', { class: 'field' },
      h('div', { class: 'row between' },
        h('label', null, h('span', { class: 'badge', text: c.record.kind }), ' ', h('span', { class: 'mono', text: c.record.name })),
        c.ok ? h('span', { class: 'badge ok', text: 'OK' }) : h('span', { class: `badge ${c.record.required ? 'danger' : 'warn'}`, text: c.record.required ? 'Missing' : 'Missing (optional)' })),
      !c.ok && h('div', { class: 'row' }, h('code', { class: 'mono secret', text: c.record.value }), copyButton(c.record.value)),
      !c.ok && h('div', { class: 'hint', text: c.found.length ? `Found: ${c.found.join(' | ')}` : 'Nothing published yet.' }))));
  if (v.verified) force.remove();
}

function forwardDialog(domains, done, existing) {
  let local = '', dom = domains[0];
  if (existing) [local, dom] = [existing.address.split('@')[0], existing.address.split('@')[1]];
  formDialog({
    title: existing ? `Forward ${existing.address}` : 'Add an address',
    description: 'Mail to this address is forwarded to the mailbox you give. Forwarded mail is rewritten with SRS so it passes SPF.',
    submitText: existing ? 'Save' : 'Add address',
    content: [
      h('div', { class: 'form-grid' },
        field({ label: 'Address', name: 'local', value: local, placeholder: 'you', validate: 'localPart', attrs: { autocomplete: 'off', spellcheck: 'false', ...(existing ? { readonly: true } : {}) } }),
        selectField({ label: 'Domain', name: 'domain', value: dom, options: domains.map((x) => [x, `@${x}`]) })),
      field({ label: 'Forward to', name: 'to', type: 'email', value: existing ? existing.forward_to : '', placeholder: 'you@gmail.com', validate: 'email' }),
    ],
    async onSubmit(f) {
      const r = await api(`${BASE}/forwards`, { method: 'POST', body: { address: `${f.local}@${f.domain}`, to: f.to } });
      toast(`Mail to ${r.address} now goes to ${r.forward_to}`);
      done();
    },
  });
}

function keyDialog(d, done) {
  formDialog({
    title: 'Create an API key',
    description: 'The key is the SMTP password and the API\'s Bearer token. It is shown once.',
    submitText: 'Create key',
    content: [
      field({ label: 'Name', name: 'name', placeholder: 'e.g. gmail or shop-backend', validate: 'keyName', attrs: { maxlength: 64 } }),
      selectField({ label: 'May send from', name: 'domain', value: '', options: [['', 'Any of my domains'], ...d.domains.map((x) => [x.name, x.name])] }),
      h('div', { class: 'form-grid' },
        selectField({ label: 'Permission', name: 'permission', value: 'sending', options: [['sending', 'Sending (reads its own emails)'], ['full', 'Full (reads every email\'s status)']] }),
        field({ label: 'Emails per hour', name: 'hourly_limit', value: String(d.default_hourly_limit), validate: 'hourly', attrs: { inputmode: 'numeric' } })),
    ],
    async onSubmit(f, dlg) {
      const r = await api(`${BASE}/keys`, { method: 'POST', body: { name: f.name, domain: f.domain || null, permission: f.permission, hourly_limit: Number(f.hourly_limit) } });
      dlg.close();
      done();
      keyCreatedDialog(r);
    },
  });
}

function keyCreatedDialog(r) {
  const row = (label, v) => h('div', { class: 'field' }, h('label', { text: label }), h('div', { class: 'row' }, h('code', { class: 'mono secret', text: v }), copyButton(v)));
  const from = r.key.domain || 'example.com';
  const curl = `curl -X POST ${r.api_url} \\\n  -H 'Authorization: Bearer ${r.secret}' -H 'Content-Type: application/json' \\\n  -d '{"from":"you@${from}","to":"someone@example.org","subject":"Hello","text":"Hi"}'`;
  const ok = h('button', { class: 'btn primary', type: 'button', text: 'Done' });
  const dlg = openDialog({
    title: `API key ${r.key.name}`,
    description: 'Copy the key now. Only a hash of it is stored, so it can\'t be shown again.',
    wide: true,
    body: h('div', { class: 'form' },
      row('API key', r.secret),
      h('h3', { class: 'small strong', text: 'Gmail: Settings → Accounts and Import → Send mail as → Add another email address' }),
      kv([
        ['SMTP server', h('span', { class: 'mono', text: r.smtp.host })],
        ['Port', '587 (TLS) or 465 (SSL)'],
        ['Username', h('span', { class: 'mono', text: r.smtp.username })],
        ['Password', 'The API key above'],
      ]),
      h('div', { class: 'row between' }, h('span', { class: 'small muted', text: 'Or send through the HTTP API' }), copyButton(curl)),
      h('pre', { class: 'logs mono small', text: curl })),
    footer: [ok],
  });
  ok.addEventListener('click', dlg.close);
}

function webhookDialog(d, done) {
  formDialog({
    title: 'Add a webhook',
    description: 'Pick no events to receive all of them.',
    submitText: 'Add webhook',
    content: [
      field({ label: 'URL', name: 'url', type: 'url', placeholder: 'https://example.com/hooks/email', validate: 'webhookUrl' }),
      h('div', { class: 'field' }, h('label', { text: 'Events' }),
        d.event_types.map((t) => h('label', { class: 'check' }, h('input', { type: 'checkbox', name: `ev:${t}` }), t))),
    ],
    async onSubmit(f, dlg) {
      const events = d.event_types.filter((t) => f[`ev:${t}`]);
      const r = await api(`${BASE}/webhooks`, { method: 'POST', body: { url: f.url, events } });
      dlg.close();
      done();
      const ok = h('button', { class: 'btn primary', type: 'button', text: 'Done' });
      const sd = openDialog({
        title: 'Webhook added',
        description: 'Copy the signing secret now; it isn\'t shown again. Check the svix-signature header with it.',
        body: h('div', { class: 'form' }, h('div', { class: 'row' }, h('code', { class: 'mono secret', text: r.secret }), copyButton(r.secret))),
        footer: [ok],
      });
      ok.addEventListener('click', sd.close);
    },
  });
}

async function messageDialog(id) {
  const holder = h('div', { class: 'form' }, h('div', { class: 'skeleton' }));
  const ok = h('button', { class: 'btn primary', type: 'button', text: 'Close' });
  const dlg = openDialog({ title: 'Email details', wide: true, body: holder, footer: [ok] });
  ok.addEventListener('click', dlg.close);
  let m;
  try { m = await api(`${BASE}/log/${encodeURIComponent(id)}`); } catch (e) { holder.replaceChildren(h('div', { class: 'alert error' }, icon('alert'), h('div', { text: e.message }))); return; }
  holder.replaceChildren(
    kv([
      ['Status', statusBadge(m.status)],
      ['From', m.from],
      ['To', m.to.join(', ')],
      ['Subject', m.subject || '(no subject)'],
      ['Sent', fmtDate(m.created_at)],
      ['Through', m.source],
      ['Message-ID', h('span', { class: 'mono small', text: m.message_id })],
      ['Email id', h('span', { class: 'mono small', text: m.id })],
    ]),
    m.events.length
      ? table(['Time', 'Event', 'Recipient', 'Detail'], m.events.map((e) => h('tr', null,
        h('td', { class: 'small muted', text: fmtDate(e.created_at) }),
        h('td', null, statusBadge(e.kind)),
        h('td', { class: 'small mono', text: e.recipient || '—' }),
        h('td', { class: 'small', text: e.detail || '' }))))
      : h('p', { class: 'muted', text: 'No delivery events yet.' }));
}
