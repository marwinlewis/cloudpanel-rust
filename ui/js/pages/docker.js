'use strict';
import {
  $, ApiError, DOMAIN_RE, PROPS, SVG_NS, VALIDATORS, api, append, card, closeMenu, confirmDialog, effectiveTheme, emptyState, errorState, field, fmtAgo, fmtBytes, fmtDate, fmtPct, fmtRate, fmtUptime, formData, formDialog, h, hooks, icon, isAdmin, media, moreButton, openDialog, openMenu, openMenuEl, rtf, selectField, setActions, setHost, setSub, setTheme, skeletonRows, spinner, state, store, svgEl, syncThemeIcon, table, toast, validateForm, withBusy,
} from '../core.js';

// ---------- Docker ----------

export function renderDocker(view) {
  const holder = h('div', null, card({ flush: true, body: table(['Container', 'Image', 'Ports', 'Status', ''], skeletonRows(5)) }));
  view.replaceChildren(holder);
  const refresh = h('button', { class: 'btn', onclick: () => withBusy(refresh, load) }, icon('refresh'), h('span', { class: 'hide-sm', text: 'Refresh' }));
  setActions(refresh);

  async function load() {
    try {
      const status = await api('/docker/status');
      if (!status.available) {
        setSub('Docker not detected');
        holder.replaceChildren(card({ body: emptyState({
          iconName: 'box', title: 'Docker isn’t running',
          text: 'Install Docker (re-run the installer with --with-docker) or start the docker service, then refresh.',
        }) }));
        return;
      }
      const list = await api('/docker/containers');
      const running = list.filter((c) => c.state === 'running').length;
      setSub(`${running} running · ${list.length} total`);
      if (!list.length) {
        holder.replaceChildren(card({ body: emptyState({ iconName: 'box', title: 'No containers', text: 'Containers you start with docker or docker compose appear here.' }) }));
        return;
      }
      holder.replaceChildren(card({ flush: true, body: table(['Container', { label: 'Image', class: 'hide-sm' }, 'Ports', { label: 'Status', class: 'hide-sm' }, ''], list.map((c) => {
        const isUp = c.state === 'running';
        const act = (action) => async (btn) => {
          await api(`/docker/containers/${encodeURIComponent(c.id)}/${action}`, { method: 'POST' });
          toast(`${c.name}: ${action} done`);
          load();
        };
        const quick = h('button', { class: 'icon-btn', title: isUp ? 'Stop' : 'Start', 'aria-label': isUp ? 'Stop' : 'Start' }, icon(isUp ? 'stop' : 'play'));
        quick.addEventListener('click', () => withBusy(quick, act(isUp ? 'stop' : 'start')));
        return h('tr', null,
          h('td', null,
            h('div', { class: 'cell-title' }, h('span', { class: `dot ${isUp ? 'ok' : c.state === 'exited' ? '' : 'warn'}` }), h('span', { text: c.name })),
            h('div', { class: 'cell-sub mono', text: c.id.slice(0, 12) })),
          h('td', { class: 'hide-sm mono muted truncate', text: c.image }),
          h('td', null, c.ports.length ? c.ports.slice(0, 3).map((p) => h('div', { class: 'mono small', text: p })) : h('span', { class: 'faint', text: '—' })),
          h('td', { class: 'hide-sm muted', text: c.status }),
          h('td', { class: 'actions' }, quick, moreButton([
            { icon: 'terminal', label: 'View logs', action: () => logsDrawer(c) },
            { icon: 'refresh', label: 'Restart', action: () => act('restart')().catch((e) => toast(e.message, 'error')) },
            '-',
            { icon: 'link', label: 'Expose on a domain', action: () => exposeDialog(c) },
          ])));
      })) }));
    } catch (e) {
      if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) }));
    }
  }
  load();
}

function logsDrawer(c) {
  const pre = h('pre', { class: 'logs mono', text: 'Loading…' });
  const tail = h('select', { class: 'input', 'aria-label': 'Lines' }, [100, 500, 2000].map((n) => h('option', { value: n, text: `Last ${n} lines`, selected: n === 500 })));
  tail.style.width = 'auto';
  const refresh = h('button', { class: 'btn' }, icon('refresh'), 'Refresh');
  async function load() {
    try {
      const r = await api(`/docker/containers/${encodeURIComponent(c.id)}/logs?tail=${tail.value}`);
      pre.textContent = r.logs || '(no output)';
      pre.scrollTop = pre.scrollHeight;
    } catch (e) { pre.textContent = e.message; }
  }
  refresh.addEventListener('click', () => withBusy(refresh, load));
  tail.addEventListener('change', load);
  openDialog({ title: c.name, description: c.image, drawer: true, body: h('div', { class: 'form' }, h('div', { class: 'row' }, tail, refresh), pre) });
  load();
}

function exposeDialog(c) {
  const guess = (c.ports.join(',').match(/:(\d+)->/) || [])[1] || '';
  formDialog({
    title: `Expose ${c.name}`,
    description: 'Creates an nginx reverse proxy from the domain to the container’s published host port.',
    submitText: 'Create proxy',
    content: [
      field({ label: 'Domain', name: 'domain', placeholder: 'app.example.com', validate: 'domain', attrs: { autocapitalize: 'off', spellcheck: 'false' } }),
      field({ label: 'Host port', name: 'host_port', type: 'number', value: guess, validate: 'port', hint: 'The port published on the host (left side of host:container).' }),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'include_www' }), 'Also serve the www. subdomain'),
    ],
    async onSubmit(d) {
      await api(`/docker/containers/${encodeURIComponent(c.id)}/proxy-site`, {
        method: 'POST', body: { domain: d.domain.toLowerCase(), host_port: Number(d.host_port), include_www: !!d.include_www },
      });
      toast(`${d.domain} now proxies to ${c.name}`);
    },
  });
}
