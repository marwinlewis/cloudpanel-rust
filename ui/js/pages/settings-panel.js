'use strict';
import { api, card, confirmDialog, errorState, field, fmtDate, formDialog, h, icon, kv, toast } from '../core.js';
import { SETTINGS_CARDS } from './settings.js';

function panelCertCard() {
  const body = h('div', { class: 'form' }, h('div', { class: 'skeleton' }));
  async function load() {
    let r;
    try { r = await api('/settings/panel-cert'); } catch (e) { body.replaceChildren(errorState(e.message, load)); return; }
    const c = r.certificate;
    const issue = h('button', { class: 'btn primary', type: 'button' }, icon('lock'), r.managed ? 'Re-issue certificate' : 'Use a Let’s Encrypt certificate');
    issue.addEventListener('click', () => formDialog({
      title: 'Certificate for the panel', submitText: 'Issue certificate',
      description: 'The hostname must point to this server and ports 80 and 443 must be reachable. The panel will open at https://hostname with no port number. certbot renews the certificate automatically.',
      content: [
        field({ label: 'Panel hostname', name: 'hostname', value: r.hostname || (/[a-z]/i.test(location.hostname) && location.hostname !== 'localhost' ? location.hostname : ''), placeholder: 'panel.example.com', validate: 'domain' }),
        field({ label: 'Email for expiry notices', name: 'email', type: 'email', validate: 'email' }),
        h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'skip_dns_check' }), 'Skip the DNS check (server behind NAT)'),
      ],
      async onSubmit(d) {
        const x = await api('/settings/panel-cert', { method: 'POST', body: { hostname: d.hostname.toLowerCase(), email: d.email, skip_dns_check: !!d.skip_dns_check } });
        toast(x.message);
        load();
      },
    }));
    const revert = h('button', { class: 'btn', type: 'button', hidden: !r.managed, text: 'Use the default certificate' });
    revert.addEventListener('click', async () => {
      if (!(await confirmDialog({ title: 'Switch back to the default certificate?', message: 'Browsers will warn about the self-signed certificate again.', confirmText: 'Switch back' }))) return;
      try { const x = await api('/settings/panel-cert', { method: 'DELETE' }); toast(x.message); load(); } catch (e) { toast(e.message, 'error'); }
    });
    const cf = r.cloudflare;
    const cfText = cf.built_in
      ? 'Cloudflare address list: the built-in copy, because it could not be fetched yet. Visitors through newer Cloudflare addresses may share one address in the logs.'
      : `Cloudflare address list: updated ${fmtDate(cf.updated_at)}${cf.stale ? ', and it could not be refreshed since. See the panel log.' : '.'}`;
    body.replaceChildren(
      c ? kv([['Hostname', r.hostname || c.subject || '—'], r.url && ['Address', h('a', { href: r.url, text: r.url })], ['Issuer', c.issuer], ['Expires', `${fmtDate(c.not_after)} (${c.days_left} days)`]])
        : h('p', { class: 'muted small', text: r.tls ? 'Serving a certificate that could not be read.' : 'The panel is running without TLS.' }),
      h('p', { class: 'muted small', text: cfText }),
      h('div', { class: 'row wrap' }, issue, revert),
      r.managed && directAccess(r, load));
  }

  /** Open or close the panel's own port. The panel restarts, so wait until it answers again. */
  async function setDirect(open, btn, done) {
    btn.disabled = true;
    try {
      await api('/settings/panel-access', { method: 'PUT', body: { open } });
      toast('Restarting the panel…');
      for (let i = 0; i < 40; i += 1) {
        await new Promise((resolve) => { setTimeout(resolve, 1500); });
        try {
          const now = await api('/settings/panel-cert');
          if (now.direct.closed === !open) { toast(open ? 'The panel’s port is open' : 'The panel’s port is closed'); done(); return; }
        } catch (e) { /* Still restarting. */ }
      }
      toast('The panel didn’t come back in time. Refresh the page to check.', 'error');
    } catch (e) { toast(e.message, 'error'); }
    btn.disabled = false;
  }

  function directAccess(r, done) {
    const { port, closed, fell_back: fellBack, on_hostname: onHostname } = r.direct;
    const tunnel = `ssh -L ${port}:127.0.0.1:${port} you@this-server`;
    const parts = [h('h3', { class: 'small strong', text: `Direct access on port ${port}` })];
    if (fellBack) {
      parts.push(h('div', { class: 'alert warn' }, icon('alert'), h('div', { text: `Port ${port} is set to closed but is open right now, because the panel couldn’t serve ${r.hostname}. Check nginx and the certificate, then restart the panel.` })));
    }
    if (closed) {
      parts.push(h('p', { class: 'muted small', text: `Closed. The panel is only reachable at ${r.url}. If that ever stops working, connect with: ${tunnel}, then open https://localhost:${port}. Or run cloudpanel panel-access-open on the server.` }));
      const reopen = h('button', { class: 'btn', type: 'button', text: `Open port ${port}` });
      reopen.addEventListener('click', async () => {
        if (await confirmDialog({ title: `Open port ${port}?`, message: 'The panel restarts briefly and can be reached on this port from the internet again.', confirmText: 'Open port' })) await setDirect(true, reopen, done);
      });
      parts.push(h('div', { class: 'row wrap' }, reopen));
    } else if (!fellBack) {
      parts.push(h('p', { class: 'muted small', text: `Open. Anyone on the internet can reach the panel’s sign-in page on this port. Close it to use only ${r.url}.` }));
      const close = h('button', { class: 'btn', type: 'button', text: `Close port ${port}`, disabled: !onHostname });
      close.addEventListener('click', async () => {
        if (await confirmDialog({ title: `Close port ${port}?`, message: `The panel restarts briefly and will only answer at ${r.url}. If that hostname ever breaks, you can still get in over SSH: ${tunnel}, then open https://localhost:${port}.`, confirmText: 'Close port', danger: true })) await setDirect(false, close, done);
      });
      parts.push(h('div', { class: 'row wrap' }, close));
      if (!onHostname) parts.push(h('p', { class: 'small' }, 'To close it, first open the panel at ', h('a', { href: r.url, text: r.url }), ', so it’s clear the hostname works for you.'));
    }
    return h('div', { class: 'form' }, h('hr'), ...parts);
  }
  load();
  return card({ title: 'Panel certificate', sub: 'Replace the self-signed certificate of this control panel.', body });
}

SETTINGS_CARDS.push({ admin: true, order: 10, column: 'right', render: panelCertCard });
