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
    body.replaceChildren(
      c ? kv([['Hostname', r.hostname || c.subject || '—'], r.url && ['Address', h('a', { href: r.url, text: r.url })], ['Issuer', c.issuer], ['Expires', `${fmtDate(c.not_after)} (${c.days_left} days)`]])
        : h('p', { class: 'muted small', text: r.tls ? 'Serving a certificate that could not be read.' : 'The panel is running without TLS.' }),
      h('div', { class: 'row wrap' }, issue, revert));
  }
  load();
  return card({ title: 'Panel certificate', sub: 'Replace the self-signed certificate of this control panel.', body });
}

SETTINGS_CARDS.push({ admin: true, order: 10, column: 'right', render: panelCertCard });
