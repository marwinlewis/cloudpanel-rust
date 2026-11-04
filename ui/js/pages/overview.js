'use strict';
import {
  $, ApiError, DOMAIN_RE, PROPS, SVG_NS, VALIDATORS, api, append, card, closeMenu, confirmDialog, effectiveTheme, emptyState, errorState, field, fmtAgo, fmtBytes, fmtDate, fmtPct, fmtRate, fmtUptime, formData, formDialog, h, hooks, icon, isAdmin, media, moreButton, openDialog, openMenu, openMenuEl, rtf, selectField, setActions, setHost, setSub, setTheme, skeletonRows, spinner, state, store, svgEl, syncThemeIcon, table, toast, validateForm, withBusy,
} from '../core.js';

// ---------- Overview ----------

const HISTORY = 60;
const history = { cpu: [], mem: [], rx: [], tx: [] };

function sparkline(cls = '') {
  const svg = svgEl('svg', { class: `spark ${cls}`.trim(), viewBox: '0 0 100 36', preserveAspectRatio: 'none', 'aria-hidden': 'true' });
  const area = svgEl('path', { class: 'area' });
  const line = svgEl('path', { class: 'line' });
  svg.append(area, line);
  svg.update = (values, max) => {
    if (values.length < 2) return;
    const top = Math.max(max || Math.max(...values), 1);
    const step = 100 / (HISTORY - 1);
    const offset = (HISTORY - values.length) * step;
    const pts = values.map((v, i) => [offset + i * step, 34 - (Math.min(v, top) / top) * 32]);
    const d = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(2)},${y.toFixed(2)}`).join('');
    line.setAttribute('d', d);
    area.setAttribute('d', `${d}L${pts[pts.length - 1][0].toFixed(2)},36L${pts[0][0].toFixed(2)},36Z`);
  };
  return svg;
}

function statCard(label, iconName, sparkCls) {
  const value = h('div', { class: 'stat-value', text: '–' });
  const meta = h('div', { class: 'stat-meta', text: ' ' });
  const spark = sparkline(sparkCls);
  const el = h('section', { class: 'card stat' },
    h('div', { class: 'stat-label' }, h('span', { text: label }), icon(iconName)), value, meta, spark);
  return { el, value, meta, spark };
}

function barClass(p) { return p >= 90 ? 'bar danger' : p >= 75 ? 'bar warn' : 'bar'; }

export function renderOverview(view) {
  const cpu = statCard('CPU', 'cpu');
  const mem = statCard('Memory', 'memory');
  const disk = statCard('Disk', 'disk');
  const net = statCard('Network', 'network', 'alt');
  disk.spark.remove();
  const diskBar = h('div', { class: 'bar' }, h('span'));
  disk.el.append(diskBar);

  const info = h('dl', { class: 'kv' });
  const disks = h('div');
  const procBody = h('tbody', null, skeletonRows(4, 5));

  view.replaceChildren(
    h('div', { class: 'grid stats' }, cpu.el, mem.el, disk.el, net.el),
    h('div', { class: 'grid two' },
      card({ title: 'System', body: info }),
      card({ title: 'Storage', body: disks })),
    card({
      title: 'Top processes', sub: 'Sorted by CPU usage', flush: true,
      body: h('div', { class: 'table-wrap' }, h('table', null,
        h('thead', null, h('tr', null, h('th', { text: 'Process' }), h('th', { class: 'hide-sm', text: 'PID' }),
          h('th', { class: 'num', text: 'CPU' }), h('th', { class: 'num', text: 'Memory' }))),
        procBody)),
    }));

  let failed = false;
  async function tick() {
    if (document.hidden) return;
    let m;
    try {
      m = await api('/system/metrics');
      failed = false;
    } catch (e) {
      if (!failed && e.status !== 401) toast(e.message, 'error');
      failed = true;
      return;
    }
    const push = (arr, v) => { arr.push(v); if (arr.length > HISTORY) arr.shift(); };
    push(history.cpu, m.total_cpu_usage);
    push(history.mem, m.memory_usage_percentage);
    push(history.rx, m.network_rx_per_sec);
    push(history.tx, m.network_tx_per_sec);

    setHost(m.hostname);
    setSub(`${m.os_name} ${m.os_version}`.trim() + ` · up ${fmtUptime(m.uptime_seconds)}`);

    cpu.value.replaceChildren(fmtPct(m.total_cpu_usage), h('small', { text: '%' }));
    cpu.meta.textContent = `${m.cpu_count} cores · load ${m.load_average.map((x) => x.toFixed(2)).join(' ')}`;
    cpu.spark.update(history.cpu, 100);

    mem.value.replaceChildren(fmtPct(m.memory_usage_percentage), h('small', { text: '%' }));
    mem.meta.textContent = `${fmtBytes(m.used_memory_bytes)} of ${fmtBytes(m.total_memory_bytes)}`;
    mem.spark.update(history.mem, 100);

    const root = m.disks.find((d) => d.mount_point === '/') || [...m.disks].sort((a, b) => b.total_space_bytes - a.total_space_bytes)[0];
    if (root) {
      disk.value.replaceChildren(fmtPct(root.usage_percentage), h('small', { text: '%' }));
      disk.meta.textContent = `${fmtBytes(root.available_space_bytes)} free of ${fmtBytes(root.total_space_bytes)}`;
      diskBar.className = barClass(root.usage_percentage);
      diskBar.firstChild.style.width = `${root.usage_percentage}%`;
    }

    net.value.replaceChildren(fmtRate(m.network_rx_per_sec).split(' ')[0], h('small', { text: `${fmtRate(m.network_rx_per_sec).split(' ')[1]} in` }));
    net.meta.textContent = `${fmtRate(m.network_tx_per_sec)} out · ${fmtBytes(m.network_rx_bytes)} total in`;
    net.spark.update(history.rx);

    const rows = [
      ['Hostname', m.hostname], ['Operating system', `${m.os_name} ${m.os_version}`.trim()],
      ['Kernel', m.kernel_version], ['Uptime', fmtUptime(m.uptime_seconds)],
      ['Swap', m.total_swap_bytes ? `${fmtBytes(m.used_swap_bytes)} of ${fmtBytes(m.total_swap_bytes)}` : 'None'],
    ];
    if (sysInfo) {
      if (sysInfo.public_ipv4) rows.push(['Public IPv4', sysInfo.public_ipv4]);
      if (sysInfo.public_ipv6) rows.push(['Public IPv6', sysInfo.public_ipv6]);
      rows.push(['Updates', sysInfo.updates_checked_at ? `${sysInfo.pending_updates} pending (${sysInfo.security_updates} security)` : 'Not checked']);
      if (sysInfo.reboot_required) rows.push(['Reboot', 'Required to finish updates']);
      rows.push(['CloudPanel', `v${sysInfo.panel_version}`]);
    }
    info.replaceChildren(...rows.flatMap(([k, v]) => [h('dt', { text: k }), h('dd', { class: 'truncate', text: v })]));

    disks.replaceChildren(...(m.disks.length ? m.disks.map((d) => h('div', { class: 'disk' },
      h('div', { class: 'row' },
        h('span', { class: 'grow truncate mono', text: d.mount_point }),
        h('span', { class: 'small muted', text: `${fmtBytes(d.used_space_bytes)} / ${fmtBytes(d.total_space_bytes)}` })),
      (() => { const b = h('div', { class: barClass(d.usage_percentage) }, h('span')); b.firstChild.style.width = `${d.usage_percentage}%`; return b; })()))
      : [h('p', { class: 'muted', text: 'No disks reported.' })]));

    procBody.replaceChildren(...m.top_processes.map((p) => h('tr', null,
      h('td', null, h('span', { class: 'mono', text: p.name })),
      h('td', { class: 'hide-sm faint mono', text: p.pid }),
      h('td', { class: 'num', text: `${p.cpu_usage.toFixed(1)}%` }),
      h('td', { class: 'num', text: fmtBytes(p.memory_bytes) }))));
  }

  let sysInfo = null;
  api('/system/info').then((x) => { sysInfo = x; }).catch(() => {});
  tick();
  const timer = setInterval(tick, 3000);
  const onVisible = () => { if (!document.hidden) tick(); };
  document.addEventListener('visibilitychange', onVisible);
  return () => { clearInterval(timer); document.removeEventListener('visibilitychange', onVisible); };
}
