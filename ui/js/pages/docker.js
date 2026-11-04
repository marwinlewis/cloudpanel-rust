'use strict';
import {
  api, card, confirmDialog, emptyState, errorState, field, formDialog, h, icon, jobDialog, moreButton, openDialog, runJob,
  selectField, setActions, setSub, skeletonRows, table, tabStrip, toast, withBusy, VALIDATORS,
} from '../core.js';

VALIDATORS.image = (v) => (/^[A-Za-z0-9][A-Za-z0-9._\-/:@]{0,254}$/.test(v) ? '' : 'e.g. nginx:1.27 or ghcr.io/org/app:latest');
VALIDATORS.cname = (v) => (/^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$/.test(v) ? '' : 'Letters, digits, _ . - (start with a letter or digit)');
VALIDATORS.stack = (v) => (/^[a-z0-9][a-z0-9_-]{0,39}$/.test(v) ? '' : 'Lowercase letters, digits, - and _ (max 40)');

export function renderDocker(view, params) {
  let tab = ['images', 'stacks'].includes(params[0]) ? params[0] : 'containers';
  const body = h('div');
  view.replaceChildren(card({ body: h('div', { class: 'skeleton' }) }));
  (async () => {
    let status;
    try { status = await api('/docker/status'); } catch (e) { if (e.status !== 401) view.replaceChildren(card({ body: errorState(e.message) })); return; }
    if (!status.available) {
      setSub('Docker not detected');
      view.replaceChildren(card({ body: emptyState({ iconName: 'box', title: 'Docker isn’t running', text: 'Install Docker (re-run the installer with --with-docker) or start the docker service, then refresh.' }) }));
      return;
    }
    const strip = tabStrip([['containers', 'Containers'], ['images', 'Images'], ['stacks', 'Compose stacks']], tab, (k) => { tab = k; history.replaceState(null, '', `#/docker/${k}`); show(); });
    strip.classList.add('page-tabs');
    view.replaceChildren(strip, body);
    const show = () => { body.replaceChildren(); setActions(); ({ containers: renderContainers, images: renderImages, stacks: renderStacks })[tab](body); };
    show();
  })();
}

// ---------- Containers ----------

function renderContainers(el) {
  const holder = h('div', null, card({ flush: true, body: table(['Container', 'Image', 'Ports', 'Status', ''], skeletonRows(5)) }));
  el.append(h('div', { class: 'alert info' }, icon('shield'), h('div', { text: 'Ports published on 0.0.0.0 bypass UFW. Bind to 127.0.0.1 (the default here) and expose the container through a site instead.' })), holder);
  const refresh = h('button', { class: 'btn', onclick: () => withBusy(refresh, load) }, icon('refresh'), h('span', { class: 'hide-sm', text: 'Refresh' }));
  setActions(refresh, h('button', { class: 'btn primary', onclick: () => runDialog(load) }, icon('plus'), 'Run container'));

  async function load() {
    try {
      const [list, stats] = await Promise.all([api('/docker/containers'), api('/docker/stats').catch(() => [])]);
      const running = list.filter((c) => c.state === 'running').length;
      setSub(`${running} running · ${list.length} total`);
      if (!list.length) {
        holder.replaceChildren(card({ body: emptyState({ iconName: 'box', title: 'No containers', text: 'Run one from an image, or deploy a compose stack.' }) }));
        return;
      }
      holder.replaceChildren(card({ flush: true, body: table(['Container', { label: 'Image', class: 'hide-sm' }, 'Ports', { label: 'CPU / memory', class: 'hide-sm' }, { label: 'Status', class: 'hide-sm' }, ''], list.map((c) => {
        const isUp = c.state === 'running';
        const st = stats.find((s) => c.id.startsWith(s.id) || s.name === c.name);
        const act = (action) => async () => {
          await api(`/docker/containers/${encodeURIComponent(c.id)}/${action}`, { method: 'POST' });
          toast(`${c.name}: ${action} done`);
          load();
        };
        const quick = h('button', { class: 'icon-btn', title: isUp ? 'Stop' : 'Start', 'aria-label': isUp ? 'Stop' : 'Start' }, icon(isUp ? 'stop' : 'play'));
        quick.addEventListener('click', () => withBusy(quick, act(isUp ? 'stop' : 'start')));
        const remove = async () => {
          if (!(await confirmDialog({ title: `Remove ${c.name}?`, message: isUp ? 'The container is running; it will be stopped and removed. Named volumes are kept.' : 'The container is removed. Named volumes are kept.', confirmText: 'Remove', danger: true }))) return;
          try { await api(`/docker/containers/${encodeURIComponent(c.id)}?force=${isUp}`, { method: 'DELETE' }); toast(`${c.name} removed`); load(); } catch (e) { toast(e.message, 'error'); }
        };
        return h('tr', null,
          h('td', null,
            h('div', { class: 'cell-title' }, h('span', { class: `dot ${isUp ? 'ok' : c.state === 'exited' ? '' : 'warn'}` }), h('span', { text: c.name })),
            h('div', { class: 'cell-sub mono', text: c.id.slice(0, 12) })),
          h('td', { class: 'hide-sm mono muted truncate', text: c.image }),
          h('td', null, c.ports.length ? c.ports.slice(0, 3).map((p) => h('div', { class: 'mono small', text: p })) : h('span', { class: 'faint', text: '—' })),
          h('td', { class: 'hide-sm mono small muted', text: st ? `${st.cpu} · ${st.mem_usage}` : '—' }),
          h('td', { class: 'hide-sm muted', text: c.status }),
          h('td', { class: 'actions' }, quick, moreButton([
            { icon: 'terminal', label: 'View logs', action: () => logsDrawer(c) },
            { icon: 'refresh', label: 'Restart', action: () => act('restart')().catch((e) => toast(e.message, 'error')) },
            { icon: 'link', label: 'Expose on a domain', action: () => exposeDialog(c) },
            '-',
            { icon: 'trash', label: 'Remove', danger: true, action: remove },
          ])));
      })) }));
    } catch (e) {
      if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) }));
    }
  }
  load();
}

function parseLines(text, re, map) {
  return text.split('\n').map((l) => l.trim()).filter(Boolean).map((l) => {
    const m = l.match(re);
    if (!m) throw new Error(`Cannot parse “${l}”`);
    return map(m);
  });
}

function runDialog(done) {
  formDialog({
    title: 'Run a container', description: 'Pulls the image if needed and starts it in the background.', submitText: 'Run', drawer: true,
    content: [
      field({ label: 'Image', name: 'image', placeholder: 'nginx:1.27', validate: 'image', attrs: { spellcheck: 'false', autocapitalize: 'off' } }),
      field({ label: 'Container name', name: 'name', placeholder: 'web', validate: 'cname', attrs: { spellcheck: 'false', autocapitalize: 'off' } }),
      selectField({ label: 'Restart policy', name: 'restart', value: 'unless-stopped', options: [['unless-stopped', 'Unless stopped'], ['always', 'Always'], ['on-failure', 'On failure'], ['no', 'Never']] }),
      field({ label: 'Ports (host:container, one per line)', name: 'ports', type: 'textarea', placeholder: '8080:80\n5353:53/udp', hint: 'Bound to 127.0.0.1 unless you tick the box below.', attrs: { class: 'input mono', rows: 3 } }),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'public' }), 'Publish ports on all interfaces (bypasses UFW)'),
      field({ label: 'Environment (KEY=value per line)', name: 'env', type: 'textarea', attrs: { class: 'input mono', rows: 3 } }),
      field({ label: 'Volumes (source:/container/path[:ro])', name: 'volumes', type: 'textarea', placeholder: 'appdata:/data\n/home/site/htdocs:/usr/share/nginx/html:ro', hint: 'Named volumes, or host paths under /home or the stacks folder.', attrs: { class: 'input mono', rows: 3 } }),
    ],
    async onSubmit(d) {
      const ports = parseLines(d.ports || '', /^(\d+):(\d+)(?:\/(tcp|udp))?$/, (m) => ({ host: +m[1], container: +m[2], protocol: m[3] || 'tcp', public: !!d.public }));
      const env = parseLines(d.env || '', /^([A-Za-z_][A-Za-z0-9_]*)=(.*)$/, (m) => [m[1], m[2]]);
      const volumes = parseLines(d.volumes || '', /^([^:]+):(\/[^:]*)(:ro)?$/, (m) => ({ source: m[1], target: m[2], read_only: !!m[3] }));
      const r = await api('/docker/containers', { method: 'POST', body: { image: d.image, name: d.name, restart: d.restart, ports, env, volumes } });
      jobDialog(r.job_id, `Run ${d.name}`).then(done);
    },
  });
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

// ---------- Images ----------

function renderImages(el) {
  const holder = h('div', null, card({ flush: true, body: table(['Image', 'Size', ''], skeletonRows(3)) }));
  el.append(holder);
  const pull = h('button', { class: 'btn primary' }, icon('download'), 'Pull image');
  pull.addEventListener('click', () => formDialog({
    title: 'Pull an image', submitText: 'Pull',
    content: [field({ label: 'Image', name: 'image', placeholder: 'postgres:16-alpine', validate: 'image', attrs: { spellcheck: 'false', autocapitalize: 'off' } })],
    async onSubmit(d) { const r = await api('/docker/images', { method: 'POST', body: { image: d.image } }); jobDialog(r.job_id, `Pull ${d.image}`).then(load); },
  }));
  const prune = h('button', { class: 'btn' }, icon('trash'), h('span', { class: 'hide-sm', text: 'Remove unused' }));
  prune.addEventListener('click', async () => {
    if (!(await confirmDialog({ title: 'Remove dangling images?', message: 'Untagged images not used by any container are deleted.', confirmText: 'Remove' }))) return;
    await withBusy(prune, async () => { await api('/docker/images/prune', { method: 'POST' }); toast('Unused images removed'); load(); });
  });
  setActions(prune, pull);

  async function load() {
    try {
      const list = await api('/docker/images');
      setSub(`${list.length} image${list.length === 1 ? '' : 's'}`);
      if (!list.length) { holder.replaceChildren(card({ body: emptyState({ iconName: 'layers', title: 'No images', text: 'Pull an image to get started.' }) })); return; }
      holder.replaceChildren(card({ flush: true, body: table(['Image', { label: 'Size', class: 'num' }, { label: 'Created', class: 'hide-sm' }, ''], list.map((i) => {
        const ref = i.repository === '<none>' ? i.id : `${i.repository}:${i.tag}`;
        const del = h('button', { class: 'icon-btn danger', title: 'Remove image', 'aria-label': `Remove ${ref}` }, icon('trash'));
        del.addEventListener('click', async () => {
          if (!(await confirmDialog({ title: `Remove ${ref}?`, message: 'Images used by a container cannot be removed.', confirmText: 'Remove', danger: true }))) return;
          await withBusy(del, async () => { await api(`/docker/images/${encodeURIComponent(ref)}`, { method: 'DELETE' }); toast('Image removed'); load(); });
        });
        return h('tr', null,
          h('td', null, h('div', { class: 'cell-title mono', text: ref }), h('div', { class: 'cell-sub mono', text: i.id.replace('sha256:', '').slice(0, 12) })),
          h('td', { class: 'num muted', text: i.size }),
          h('td', { class: 'hide-sm muted', text: i.created }),
          h('td', { class: 'actions' }, del));
      })) }));
    } catch (e) { if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) })); }
  }
  load();
}

// ---------- Compose stacks ----------

const SAMPLE = `services:
  app:
    image: nginx:1.27-alpine
    restart: unless-stopped
    ports:
      - "127.0.0.1:8080:80"
`;

function stackEditor(name, done) {
  (async () => {
    let compose = SAMPLE;
    let env = '';
    if (name) {
      try { const r = await api(`/docker/stacks/${encodeURIComponent(name)}`); compose = r.compose; env = r.env; } catch (e) { toast(e.message, 'error'); return; }
    }
    formDialog({
      title: name ? `Edit ${name}` : 'New compose stack', submitText: 'Save', wide: true,
      description: 'Validated with docker compose config before saving. Deploy it with “Up”.',
      content: [
        !name && field({ label: 'Stack name', name: 'name', validate: 'stack', attrs: { autocapitalize: 'off', spellcheck: 'false' } }),
        field({ label: 'compose.yaml', name: 'compose', type: 'textarea', value: compose, validate: 'required', attrs: { class: 'input mono editor', rows: 18 } }),
        field({ label: '.env (optional)', name: 'env', type: 'textarea', value: env, attrs: { class: 'input mono', rows: 4 } }),
      ].filter(Boolean),
      async onSubmit(d) {
        const n = name || d.name;
        await api(`/docker/stacks/${encodeURIComponent(n)}`, { method: 'PUT', body: { compose: d.compose, env: d.env || '' } });
        toast('Stack saved');
        done();
      },
    });
  })();
}

function renderStacks(el) {
  const holder = h('div', null, card({ flush: true, body: table(['Stack', 'Services', ''], skeletonRows(3)) }));
  el.append(holder);
  setActions(h('button', { class: 'btn primary', onclick: () => stackEditor(null, load) }, icon('plus'), 'New stack'));
  async function load() {
    try {
      const list = await api('/docker/stacks');
      setSub(`${list.length} stack${list.length === 1 ? '' : 's'}`);
      if (!list.length) { holder.replaceChildren(card({ body: emptyState({ iconName: 'layers', title: 'No compose stacks', text: 'Define multi-container apps with a compose.yaml file.' }) })); return; }
      holder.replaceChildren(card({ flush: true, body: table(['Stack', 'Services', ''], list.map((s) => {
        const run = (action, title) => async () => {
          try { await runJob(`/docker/stacks/${encodeURIComponent(s.name)}/${action}`, title); } catch (e) { toast(e.message, 'error'); }
          load();
        };
        const logs = async () => {
          const pre = h('pre', { class: 'logs mono', text: 'Loading…' });
          openDialog({ title: `${s.name} logs`, drawer: true, body: pre });
          try { const r = await api(`/docker/stacks/${encodeURIComponent(s.name)}/logs?tail=500`); pre.textContent = r.logs || '(no output)'; } catch (e) { pre.textContent = e.message; }
        };
        const remove = async () => {
          if (!(await confirmDialog({ title: `Delete ${s.name}?`, message: 'Runs docker compose down and deletes the stack files. Named volumes are kept.', confirmText: 'Delete', danger: true }))) return;
          run('delete', `Delete ${s.name}`)();
        };
        const running = s.services.filter((x) => (x.State || x.state) === 'running').length;
        return h('tr', null,
          h('td', { class: 'mono strong', text: s.name }),
          h('td', null, s.services.length ? `${running}/${s.services.length} running` : h('span', { class: 'faint', text: 'Not deployed' })),
          h('td', { class: 'actions' }, moreButton([
            { icon: 'play', label: 'Up (deploy)', action: run('up', `Deploy ${s.name}`) },
            { icon: 'refresh', label: 'Restart', action: run('restart', `Restart ${s.name}`) },
            { icon: 'download', label: 'Pull images', action: run('pull', `Pull ${s.name}`) },
            { icon: 'stop', label: 'Down', action: run('down', `Stop ${s.name}`) },
            { icon: 'terminal', label: 'Logs', action: logs },
            { icon: 'edit', label: 'Edit', action: () => stackEditor(s.name, load) },
            '-',
            { icon: 'trash', label: 'Delete', danger: true, action: remove },
          ])));
      })) }));
    } catch (e) { if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) })); }
  }
  load();
}

