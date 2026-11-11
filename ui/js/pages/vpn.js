'use strict';
import {
  api, card, confirmDialog, copyButton, download, emptyState, errorState, field, fmtAgo, fmtBytes, formDialog, h, icon,
  kv, moreButton, openDialog, qrSvg, runJob, setActions, setSub, skeletonRows, table, toast, withBusy, VALIDATORS,
} from '../core.js';

const IPV4 = /^(25[0-5]|2[0-4]\d|1?\d?\d)(\.(25[0-5]|2[0-4]\d|1?\d?\d)){3}$/;
const CIDR = /^[0-9a-fA-F:.]+(\/\d{1,3})?$/;
const list = (v) => v.split(',').map((s) => s.trim()).filter(Boolean);

VALIDATORS.tunnel = (v) => {
  const [ip, p] = v.split('/');
  return IPV4.test(ip || '') && /^\d+$/.test(p || '') && +p >= 8 && +p <= 30 ? '' : 'The server\'s address with a prefix, e.g. 10.8.0.1/24';
};
VALIDATORS.cidrList = (v) => (list(v).length && list(v).every((c) => CIDR.test(c)) ? '' : 'Networks separated by commas, e.g. 0.0.0.0/0');
VALIDATORS.optionalCidrList = (v) => (!v || list(v).every((c) => CIDR.test(c)) ? '' : 'Networks separated by commas, e.g. 192.168.1.0/24');
VALIDATORS.ipList = (v) => (!v || list(v).every((c) => /^[0-9a-fA-F:.]+$/.test(c)) ? '' : 'IP addresses separated by commas');
VALIDATORS.clientName = (v) => (/^[A-Za-z0-9 ._-]{1,32}$/.test(v) ? '' : 'Up to 32 letters, digits, spaces, . _ -');
VALIDATORS.wgKey = (v) => (/^[A-Za-z0-9+/]{43}=$/.test(v) ? '' : 'A WireGuard key: 44 characters ending in =');

/** A peer that completed a handshake in the last 3 minutes is connected. */
function connection(c) {
  if (!c.enabled) return h('span', { class: 'badge', text: 'Disabled' });
  const hs = c.status && c.status.latest_handshake;
  if (!hs) return h('span', { class: 'badge', text: 'Never connected' });
  const when = new Date(hs * 1000).toISOString();
  const online = Date.now() / 1000 - hs < 180;
  return h('span', { class: `badge ${online ? 'ok' : ''}`, title: c.status.endpoint ? `From ${c.status.endpoint}` : '', text: online ? 'Connected' : `Seen ${fmtAgo(when)}` });
}

export function renderVpn(view) {
  const notice = h('div');
  const server = h('div', null, card({ title: 'Server', body: skeletonRows(2) }));
  const clients = h('div', null, card({ flush: true, body: table(['Client', 'Address', 'Status', 'Transfer', ''], skeletonRows(5)) }));
  view.replaceChildren(h('div', { class: 'grid' }, notice, server, clients));
  let data = null;
  let timer = null;

  async function load() {
    clearTimeout(timer);
    try {
      data = await api('/wireguard');
    } catch (e) {
      if (e.status !== 401) server.replaceChildren(card({ body: errorState(e.message, load) }));
      return;
    }
    render();
    // Live handshakes and transfer counters.
    if (data.running) timer = setTimeout(load, 10000);
  }

  function render() {
    const d = data;
    const s = d.server;
    setSub(s.configured ? `${d.clients.length} client${d.clients.length === 1 ? '' : 's'} · ${s.interface}` : '');
    setActions(s.configured && h('button', { class: 'btn primary', onclick: () => clientDialog(s, load) }, icon('plus'), 'Add client'));

    const notes = [];
    if (d.import_notes) notes.push(h('div', { class: 'alert info' }, icon('check'), h('div', null, ...d.import_notes.map((n) => h('div', { text: n })))));
    if (!d.installed) {
      const install = d.can_install && h('button', { class: 'btn primary sm', type: 'button' }, icon('download'), 'Install WireGuard');
      if (install) {
        install.addEventListener('click', () => withBusy(install, async () => {
          const job = await runJob('/wireguard/install', 'Install WireGuard');
          if (job && job.status === 'succeeded') toast('WireGuard installed');
          await load();
        }));
      }
      notes.push(h('div', { class: 'alert warn' }, icon('alert'),
        h('div', { class: 'grow', text: d.can_install ? 'WireGuard is not installed on this server.' : 'WireGuard is not installed. Install the wireguard-tools package, then reload this page.' }), install));
    }
    notice.replaceChildren(...notes);

    if (!s.configured) {
      server.replaceChildren(card({ body: emptyState({
        iconName: 'vpn', title: 'Set up the VPN server',
        text: 'Run a WireGuard VPN on this server and give phones and laptops a configuration to connect with.',
        action: d.installed && h('button', { class: 'btn primary', onclick: () => serverDialog(d, load) }, icon('settings'), 'Set up server'),
      }) }));
      clients.replaceChildren();
      return;
    }

    let state;
    if (!s.enabled) state = h('span', { class: 'badge', text: 'Disabled' });
    else if (d.running) state = h('span', { class: 'badge ok', text: 'Running' });
    else state = h('span', { class: 'badge danger', text: 'Not running' });
    const key = h('span', { class: 'row' }, h('code', { class: 'mono truncate', text: s.public_key }), copyButton(s.public_key));
    server.replaceChildren(card({
      title: 'Server',
      sub: s.imported ? 'Imported from the existing WireGuard configuration' : '',
      actions: h('button', { class: 'btn sm', onclick: () => serverDialog(d, load) }, icon('settings'), 'Settings'),
      body: kv([
        ['Status', state],
        ['Endpoint', s.endpoint ? `${s.endpoint}:${s.listen_port}` : h('span', { class: 'badge warn', text: 'Not set' })],
        ['Tunnel network', s.network || s.address || '—'],
        ['Server address', s.address || '—'],
        ['Client DNS', s.dns.length ? s.dns.join(', ') : 'None'],
        ['Internet access', s.nat ? `Through this server (${s.out_interface || d.detected_interface || 'auto'})` : 'Not routed by the panel'],
        ['Public key', key],
      ]),
    }));

    if (!d.clients.length) {
      clients.replaceChildren(card({ body: emptyState({
        iconName: 'users', title: 'No clients yet', text: 'Add a client for each device that connects to the VPN.',
        action: h('button', { class: 'btn primary', onclick: () => clientDialog(s, load) }, icon('plus'), 'Add client'),
      }) }));
      return;
    }
    clients.replaceChildren(card({
      flush: true,
      body: table(['Client', { label: 'Address', class: 'hide-sm' }, 'Status', { label: 'Transfer', class: 'hide-sm' }, ''], d.clients.map((c) => clientRow(c, s))),
    }));
  }

  function clientRow(c, s) {
    const show = h('button', { class: 'icon-btn', title: 'Show configuration', 'aria-label': `Show configuration for ${c.name}`, disabled: !c.has_config }, icon('eye'));
    show.addEventListener('click', () => withBusy(show, () => configDialog(c)));
    const items = [
      c.has_config && { icon: 'download', label: 'Download .conf', action: () => download(`/wireguard/clients/${c.id}/download`) },
      { icon: 'edit', label: 'Edit', action: () => editDialog(c, load) },
      !c.has_config && c.imported && { icon: 'key', label: 'Add private key', action: () => keyDialog(c, load) },
      { icon: c.enabled ? 'stop' : 'play', label: c.enabled ? 'Disable' : 'Enable', action: () => setEnabled(c, !c.enabled) },
      '-',
      { icon: 'trash', label: 'Delete', danger: true, action: () => remove(c) },
    ].filter(Boolean);
    const st = c.status || {};
    return h('tr', null,
      h('td', null, h('div', { class: 'strong', text: c.name }),
        c.imported && h('span', { class: 'badge ml', title: c.has_config ? '' : 'The panel has no private key for this client, so it cannot show its configuration', text: 'Imported' })),
      h('td', { class: 'mono muted hide-sm', text: c.address || '—' }),
      h('td', null, connection(c)),
      h('td', { class: 'muted small hide-sm', text: st.rx || st.tx ? `↓ ${fmtBytes(st.tx)} · ↑ ${fmtBytes(st.rx)}` : '—' }),
      h('td', { class: 'actions' }, show, moreButton(items)));
  }

  async function setEnabled(c, enabled) {
    try {
      await api(`/wireguard/clients/${c.id}`, { method: 'PATCH', body: { enabled } });
      toast(`${c.name} ${enabled ? 'enabled' : 'disabled'}`);
      await load();
    } catch (e) { toast(e.message, 'error'); }
  }

  async function remove(c) {
    if (!(await confirmDialog({ title: `Delete ${c.name}?`, message: 'The device is disconnected and its configuration stops working. This cannot be undone.', confirmText: 'Delete', danger: true }))) return;
    try {
      await api(`/wireguard/clients/${c.id}`, { method: 'DELETE' });
      toast(`${c.name} deleted`);
      await load();
    } catch (e) { toast(e.message, 'error'); }
  }

  load();
  return () => clearTimeout(timer);
}

function serverDialog(d, done) {
  const s = d.server;
  const restart = s.configured && d.running;
  formDialog({
    title: s.configured ? 'VPN server settings' : 'Set up the VPN server',
    description: !s.configured ? 'A key pair for the server is created when you save.'
      : restart ? 'Saving restarts WireGuard; connected clients reconnect within a few seconds.' : '',
    submitText: s.configured ? 'Save' : 'Create server',
    drawer: true,
    content: [
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'enabled', checked: s.configured ? s.enabled : true }), 'Run the VPN server (starts at boot)'),
      field({ label: 'Public hostname or IP', name: 'endpoint', value: s.endpoint || location.hostname, validate: 'required', hint: 'What clients connect to. Use a hostname if the IP address may change.' }),
      h('div', { class: 'form-grid' },
        field({ label: 'UDP port', name: 'listen_port', value: String(s.listen_port), validate: 'port', attrs: { inputmode: 'numeric' } }),
        field({ label: 'Server tunnel address', name: 'address', value: s.address || '10.8.0.1/24', validate: 'tunnel' })),
      field({ label: 'DNS servers for clients', name: 'dns', value: s.dns.join(', '), validate: 'ipList', hint: 'Optional, e.g. 1.1.1.1, 1.0.0.1' }),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'nat', checked: s.nat }), 'Route clients\' internet traffic through this server (NAT)'),
      field({ label: 'Outgoing interface (optional)', name: 'out_interface', value: s.out_interface || '', placeholder: d.detected_interface || 'eth0', hint: `Detected from the default route${d.detected_interface ? `: ${d.detected_interface}` : ''}.` }),
      s.extra && s.extra.length > 0 && h('div', { class: 'alert info' }, icon('alert'), h('div', null,
        h('div', { text: 'These lines from the imported configuration are kept as they are:' }),
        h('pre', { class: 'mono small', text: s.extra.join('\n') }))),
      h('p', { class: 'hint', text: 'The UDP port is opened in UFW while the server runs.' }),
    ],
    async onSubmit(f) {
      await api('/wireguard', { method: 'PUT', body: { ...f, listen_port: +f.listen_port } });
      toast(s.configured ? 'VPN settings applied' : 'VPN server created');
      done();
    },
  });
}

function clientDialog(s, done) {
  formDialog({
    title: 'Add VPN client',
    description: 'Creates keys and an address for one device. You can show its QR code afterwards.',
    submitText: 'Add client',
    content: [
      field({ label: 'Name', name: 'name', placeholder: 'e.g. Phone', validate: 'clientName', attrs: { maxlength: 32 } }),
      field({ label: 'Route through the VPN', name: 'allowed_ips', value: '0.0.0.0/0', validate: 'cidrList', hint: `0.0.0.0/0 sends all traffic through the server. Use ${s.network || 'the tunnel network'} for access to the VPN only.` }),
    ],
    async onSubmit(f, dlg) {
      const c = await api('/wireguard/clients', { method: 'POST', body: f });
      toast(`${c.name} added`);
      dlg.close();
      done();
      configDialog({ ...c, has_config: true });
    },
  });
}

function editDialog(c, done) {
  formDialog({
    title: `Edit ${c.name}`,
    submitText: 'Save',
    content: [
      field({ label: 'Name', name: 'name', value: c.name, validate: 'clientName', attrs: { maxlength: 32 } }),
      field({ label: 'Route through the VPN', name: 'allowed_ips', value: c.allowed_ips, validate: 'cidrList', hint: 'Used in the client\'s configuration; download it again after changing this.' }),
      field({ label: 'Networks behind this client (optional)', name: 'server_allowed_ips', value: c.server_allowed_ips, validate: 'optionalCidrList', hint: 'For site-to-site: networks the server routes to this client.' }),
    ],
    async onSubmit(f) {
      await api(`/wireguard/clients/${c.id}`, { method: 'PATCH', body: f });
      toast('Client saved');
      done();
    },
  });
}

function keyDialog(c, done) {
  formDialog({
    title: `Private key for ${c.name}`,
    description: 'This client was imported, so the panel has only its public key. Paste the private key from the device\'s configuration to show and download its configuration here.',
    submitText: 'Save key',
    content: [field({ label: 'Private key', name: 'private_key', validate: 'wgKey', attrs: { autocomplete: 'off', spellcheck: 'false' } })],
    async onSubmit(f) {
      await api(`/wireguard/clients/${c.id}`, { method: 'PATCH', body: f });
      toast('Private key saved');
      done();
    },
  });
}

async function configDialog(c) {
  let r;
  try { r = await api(`/wireguard/clients/${c.id}/config`); } catch (e) { toast(e.message, 'error'); return; }
  const pre = h('pre', { class: 'logs mono small', text: r.config });
  const dl = h('button', { class: 'btn', type: 'button' }, icon('download'), 'Download .conf');
  dl.addEventListener('click', () => download(`/wireguard/clients/${c.id}/download`));
  const ok = h('button', { class: 'btn primary', type: 'button', text: 'Done' });
  const d = openDialog({
    title: r.name,
    description: 'Scan the QR code in the WireGuard app, or import the file. It contains the device\'s private key: share it only with that device.',
    body: h('div', { class: 'form' }, qrSvg(r.qr.width, r.qr.modules), h('div', { class: 'row between' }, h('span', { class: 'small muted', text: 'Configuration' }), copyButton(r.config)), pre),
    footer: [dl, ok],
  });
  ok.addEventListener('click', d.close);
}
