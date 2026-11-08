'use strict';
import {
  api, card, confirmDialog, copyButton, emptyState, errorState, fmtAgo, fmtBytes, h, hooks, icon, kv, moreButton, openDialog,
  runJob, setActions, setSub, skeletonRows, table, tabStrip, toast, withBusy,
} from '../core.js';

function stateBadge(s) {
  const cls = s.active_state === 'active' ? 'ok' : s.active_state === 'failed' ? 'danger' : 'warn';
  return h('span', { class: `badge ${cls}`, text: s.active_state === 'active' ? 'Running' : s.active_state });
}

function logsDrawer(name) {
  const pre = h('pre', { class: 'logs mono', text: 'Loading…' });
  const refresh = h('button', { class: 'btn' }, icon('refresh'), 'Refresh');
  async function load() {
    try { const r = await api(`/services/${encodeURIComponent(name)}/logs?lines=500`); pre.textContent = r.logs || '(no output)'; pre.scrollTop = pre.scrollHeight; } catch (e) { pre.textContent = e.message; }
  }
  refresh.addEventListener('click', () => withBusy(refresh, load));
  openDialog({ title: name, description: 'journalctl', drawer: true, body: h('div', { class: 'form' }, h('div', null, refresh), pre) });
  load();
}

export function renderServices(view, params) {
  let tab = params[0] === 'updates' ? 'updates' : 'services';
  const body = h('div');
  const strip = tabStrip([['services', 'Services'], ['updates', 'Updates']], tab, (k) => { tab = k; history.replaceState(null, '', `#/services/${k}`); show(); });
  strip.classList.add('page-tabs');
  view.replaceChildren(strip, body);
  const reboot = h('button', { class: 'btn danger' }, icon('power'), h('span', { class: 'hide-sm', text: 'Reboot' }));
  reboot.addEventListener('click', async () => {
    if (!(await confirmDialog({ title: 'Reboot the server?', message: 'All sites and apps go offline for a minute or two while the server restarts.', confirmText: 'Reboot now', danger: true }))) return;
    await withBusy(reboot, async () => { const r = await api('/system/reboot', { method: 'POST' }); toast(r.message); });
  });
  setActions(reboot);
  const show = () => { body.replaceChildren(); (tab === 'updates' ? renderUpdates : renderServiceList)(body); };
  show();
}

function renderServiceList(el) {
  const holder = h('div', null, card({ flush: true, body: table(['Service', 'Status', 'Memory', ''], skeletonRows(4, 4)) }));
  el.append(holder);
  async function load() {
    try {
      const list = await api('/services');
      setSub(`${list.filter((s) => s.active_state === 'active').length} of ${list.length} running`);
      if (!list.length) { holder.replaceChildren(card({ body: emptyState({ iconName: 'server', title: 'No managed services found', text: 'systemd is not available on this system.' }) })); return; }
      holder.replaceChildren(card({ flush: true, body: table(['Service', 'Status', { label: 'Memory', class: 'num hide-sm' }, { label: 'Since', class: 'hide-sm' }, ''], list.map((s) => {
        const act = (a) => async () => {
          if (a === 'stop' && !(await confirmDialog({ title: `Stop ${s.name}?`, message: 'Anything that depends on this service stops working until it is started again.', confirmText: 'Stop', danger: true }))) return;
          try { await api(`/services/${encodeURIComponent(s.name)}/${a}`, { method: 'POST' }); toast(`${s.name}: ${a} done`); load(); } catch (e) { toast(e.message, 'error'); }
        };
        const up = s.active_state === 'active';
        return h('tr', null,
          h('td', null, h('div', { class: 'cell-title mono', text: s.name }), h('div', { class: 'cell-sub', text: s.description })),
          h('td', null, stateBadge(s), s.enabled && s.enabled !== 'enabled' && h('span', { class: 'small faint', text: ` ${s.enabled}` })),
          h('td', { class: 'num hide-sm muted', text: s.memory_bytes ? fmtBytes(s.memory_bytes) : '—' }),
          h('td', { class: 'hide-sm muted small', text: s.since || '—' }),
          h('td', { class: 'actions' }, moreButton([
            up ? { icon: 'refresh', label: 'Restart', action: act('restart') } : { icon: 'play', label: 'Start', action: act('start') },
            up && { icon: 'refresh', label: 'Reload', action: act('reload') },
            { icon: 'terminal', label: 'Logs', action: () => logsDrawer(s.name) },
            up && '-',
            up && { icon: 'stop', label: 'Stop', danger: true, action: act('stop') },
          ].filter(Boolean))));
      })) }));
    } catch (e) { if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) })); }
  }
  load();
}

// The panel's own version, which is separate from the server's packages below it.
function renderPanelUpdate(el) {
  const holder = h('div', null, card({ title: 'CloudPanel', body: h('div', { class: 'skeleton' }) }));
  el.append(holder);
  function draw(p) {
    const check = h('button', { class: 'btn' }, icon('refresh'), 'Check for new version');
    check.addEventListener('click', () => withBusy(check, async () => {
      const r = await api('/system/panel-update/check', { method: 'POST' });
      draw(r);
      hooks.refreshPanelUpdate();
      if (r.error) toast(`Could not check: ${r.error}`, 'error');
      else toast(r.update_available ? `CloudPanel v${r.latest} is available` : 'CloudPanel is up to date');
    }));
    const latest = p.latest ? `v${p.latest}` : p.checked_at ? 'No release published' : 'Not checked yet';
    holder.replaceChildren(card({
      title: 'CloudPanel', sub: 'The control panel itself. Checked daily against GitHub releases.',
      actions: check,
      body: h('div', { class: 'form' },
        p.update_available && h('div', { class: 'alert info' }, icon('download'), h('div', { class: 'grow form' },
          h('div', null,
            h('strong', { text: `CloudPanel v${p.latest} is available. ` }),
            p.release_url && h('a', { href: p.release_url, target: '_blank', rel: 'noopener noreferrer', text: 'Release notes' })),
          h('div', { text: 'To update, run this on the server. Your data, secrets and certificate are kept.' }),
          h('div', { class: 'row' }, h('code', { class: 'grow wrap-anywhere', text: p.upgrade_command }), copyButton(p.upgrade_command)))),
        p.error && h('div', { class: 'alert warn' }, icon('alert'), h('div', { text: `Could not check for a new version (${fmtAgo(p.failed_at)}): ${p.error}` })),
        kv([
          ['Installed', `v${p.current}`],
          ['Latest', latest],
          ['Last checked', p.checked_at ? fmtAgo(p.checked_at) : 'Never'],
        ])),
    }));
  }
  async function load() {
    try { draw(await api('/system/panel-update')); } catch (e) { if (e.status !== 401) holder.replaceChildren(card({ title: 'CloudPanel', body: errorState(e.message, load) })); }
  }
  load();
}

function renderUpdates(el) {
  const panel = h('div');
  const holder = h('div', { class: 'stack' });
  el.append(h('div', { class: 'stack' }, panel, holder));
  renderPanelUpdate(panel);
  async function load() {
    try {
      const u = await api('/system/updates');
      setSub(u.checked_at ? `${u.packages.length} package update${u.packages.length === 1 ? '' : 's'} · checked ${fmtAgo(u.checked_at)}` : 'Packages not checked yet');
      const check = h('button', { class: 'btn' }, icon('refresh'), 'Check for updates');
      check.addEventListener('click', async () => { try { await runJob('/system/updates/refresh', 'Checking for updates'); } catch (e) { toast(e.message, 'error'); } load(); });
      const upgrade = h('button', { class: 'btn primary', disabled: !u.packages.length }, icon('download'), 'Install all updates');
      upgrade.addEventListener('click', async () => {
        if (!(await confirmDialog({ title: 'Install all updates?', message: 'Runs apt-get upgrade. Services may restart briefly.', confirmText: 'Install updates' }))) return;
        try { await runJob('/system/updates/upgrade', 'Installing updates'); } catch (e) { toast(e.message, 'error'); }
        load();
      });
      holder.replaceChildren(
        u.reboot_required ? h('div', { class: 'alert warn' }, icon('alert'), h('div', { text: 'A reboot is required to finish installing updates.' })) : '',
        card({
          title: 'Package updates', sub: u.security_count ? `${u.security_count} security update${u.security_count === 1 ? '' : 's'}` : 'Debian / Ubuntu packages (apt)',
          actions: h('div', { class: 'row' }, check, upgrade),
          flush: true,
          body: u.packages.length ? table(['Package', { label: 'Installed', class: 'hide-sm' }, 'Available', ''], u.packages.map((p) => h('tr', null,
            h('td', { class: 'mono', text: p.name }),
            h('td', { class: 'hide-sm mono muted small', text: p.current }),
            h('td', { class: 'mono small', text: p.version }),
            h('td', null, p.security && h('span', { class: 'badge danger', text: 'Security' })))))
            : h('div', { class: 'card-body' }, emptyState({ iconName: 'check', title: u.checked_at ? 'Everything is up to date' : 'No update check yet', text: u.checked_at ? '' : 'Click “Check for updates”.' })),
        }));
    } catch (e) { if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) })); }
  }
  load();
}

export { kv };
