'use strict';
import {
  api, card, confirmDialog, emptyState, errorState, field, jobDialog, fmtAgo, fmtBytes, fmtDate, formDialog, h, icon, isAdmin,
  kv, moreButton, openDialog, runJob, secretDialog, selectField, setActions, setSub, skeletonRows, table, tabStrip,
  toast, typedConfirm, withBusy, VALIDATORS,
} from '../core.js';
import { SITE_TABS } from './site-tabs.js';

export const SITE_TYPES = {
  nodejs: { label: 'Node.js', desc: 'Next.js, Express, Nuxt', cmd: 'npm start' },
  python: { label: 'Python', desc: 'FastAPI, Django, Flask', cmd: '.venv/bin/gunicorn -b 127.0.0.1:$PORT app:app' },
  static: { label: 'Static', desc: 'HTML, Vite, SPA builds' },
  reverse_proxy: { label: 'Reverse proxy', desc: 'Any local HTTP service' },
  docker_proxy: { label: 'Docker', desc: 'Container port' },
};
const HAS_APP = new Set(['nodejs', 'python', 'reverse_proxy']);

export const WWW_OPTIONS = [
  ['redirect', 'Redirect www to the naked domain (recommended)'],
  ['alias', 'Serve the site on both'],
  ['off', 'Don’t handle www'],
];
/** The API's two www fields for a choice from WWW_OPTIONS. */
export function wwwBody(mode) { return { include_www: mode !== 'off', www_redirect: mode === 'redirect' }; }
function wwwMode(site) { return !site.include_www ? 'off' : site.www_redirect ? 'redirect' : 'alias'; }
function wwwLabel(site) { return site.www_redirect ? `www.${site.domain} redirects here` : `www.${site.domain}`; }

VALIDATORS.sysuser = (v) => (!v || /^[a-z_][a-z0-9_-]{0,31}$/.test(v) ? '' : 'Lowercase letters, digits, - and _ (max 32)');
VALIDATORS.username = (v) => (/^[A-Za-z0-9._-]{3,32}$/.test(v) ? '' : '3-32 letters, digits, . _ -');
VALIDATORS.optionalPassword = (v) => (!v || v.length >= 10 ? '' : 'Use at least 10 characters');

function statusBadge(site) {
  if (!site.is_active) return h('span', { class: 'badge warn', text: 'Disabled' });
  return site.ssl_enabled ? h('span', { class: 'badge ok' }, icon('lock'), 'Secure') : h('span', { class: 'badge', text: 'HTTP' });
}

function appBadge(app) {
  if (!app || !app.installed) return h('span', { class: 'badge', text: 'Not configured' });
  const s = app.active_state;
  const cls = s === 'active' ? 'ok' : s === 'failed' ? 'danger' : 'warn';
  return h('span', { class: `badge ${cls}`, text: s === 'active' ? 'Running' : s });
}

// ======================================================================
// Site list
// ======================================================================

export function renderSites(view, params) {
  if (params && params[0]) return renderSiteDetail(view, Number(params[0]), params[1] || 'overview');
  let sites = [];
  let query = '';
  const search = h('input', { class: 'input', type: 'search', placeholder: 'Search sites', 'aria-label': 'Search sites' });
  const tbody = h('tbody', null, skeletonRows(5));
  const holder = h('div');
  const tableEl = h('div', { class: 'table-wrap' }, h('table', null,
    h('thead', null, h('tr', null,
      h('th', { text: 'Domain' }), h('th', { text: 'Type' }), h('th', { class: 'hide-sm', text: 'Target' }),
      h('th', { text: 'Status' }), h('th', { class: 'hide-sm', text: 'Created' }), h('th'))),
    tbody));
  holder.append(tableEl);
  view.replaceChildren(card({
    flush: true,
    body: h('div', null,
      h('div', { class: 'card-head' }, h('div', { class: 'toolbar grow' }, h('div', { class: 'search' }, icon('search'), search))),
      holder),
  }));
  if (isAdmin()) setActions(h('button', { class: 'btn primary', onclick: () => addSiteDialog(load) }, icon('plus'), 'Add site'));

  search.addEventListener('input', () => { query = search.value.trim().toLowerCase(); draw(); });

  function draw() {
    if (!sites.length) {
      holder.replaceChildren(emptyState({
        iconName: 'globe', title: 'No sites yet',
        text: isAdmin() ? 'Add a domain to serve a static site or run an app on this server.' : 'No sites have been assigned to you yet.',
        action: isAdmin() && h('button', { class: 'btn primary', onclick: () => addSiteDialog(load) }, icon('plus'), 'Add your first site'),
      }));
      return;
    }
    holder.replaceChildren(tableEl);
    const list = sites.filter((s) => s.domain.includes(query) || s.site_type.includes(query));
    if (!list.length) {
      tbody.replaceChildren(h('tr', null, h('td', { colspan: 6, class: 'muted', text: `No sites match “${query}”.` })));
      return;
    }
    tbody.replaceChildren(...list.map((s) => {
      const t = SITE_TYPES[s.site_type] || { label: s.site_type };
      const url = `${s.ssl_enabled ? 'https' : 'http'}://${s.domain}`;
      const items = [
        { icon: 'settings', label: 'Manage', action: () => { location.hash = `#/sites/${s.id}`; } },
        { icon: 'external', label: 'Open site', action: () => window.open(url, '_blank', 'noopener,noreferrer') },
      ];
      if (isAdmin()) items.push('-', { icon: 'trash', label: 'Delete site', danger: true, action: () => deleteSite(s, load) });
      return h('tr', null,
        h('td', null,
          h('div', { class: 'cell-title' }, h('a', { href: `#/sites/${s.id}`, text: s.domain })),
          s.include_www && h('div', { class: 'cell-sub', text: wwwLabel(s) })),
        h('td', null, h('span', { class: 'badge', text: t.label })),
        h('td', { class: 'hide-sm mono muted truncate', text: s.site_type === 'static' ? (s.document_root || '') : `127.0.0.1:${s.target_port}` }),
        h('td', null, statusBadge(s)),
        h('td', { class: 'hide-sm muted nowrap', title: fmtDate(s.created_at), text: fmtAgo(s.created_at) }),
        h('td', { class: 'actions' }, moreButton(items)));
    }));
  }

  async function load() {
    try {
      sites = await api('/sites');
      setSub(`${sites.length} site${sites.length === 1 ? '' : 's'}`);
      draw();
    } catch (e) {
      if (e.status !== 401) holder.replaceChildren(errorState(e.message, load));
    }
  }
  load();
}

function addSiteDialog(done) {
  const typeGroup = h('div', { class: 'segmented', role: 'radiogroup', 'aria-label': 'Site type' },
    ['nodejs', 'python', 'static', 'reverse_proxy'].map((k, i) => h('label', null,
      h('input', { type: 'radio', name: 'site_type', value: k, checked: i === 0 }),
      h('strong', { text: SITE_TYPES[k].label }), h('span', { text: SITE_TYPES[k].desc }))));
  const portField = field({ label: 'App port', name: 'target_port', type: 'number', placeholder: '3000', validate: 'port', hint: 'The port your app listens on at 127.0.0.1 (exposed to it as $PORT).', attrs: { min: 1, max: 65535, inputmode: 'numeric' } });
  const cmdField = field({ label: 'Start command (optional)', name: 'app_command', placeholder: SITE_TYPES.nodejs.cmd, hint: 'Run as the site user and restarted if it crashes (PM2 for Node.js, systemd for the rest). You can set this later.', attrs: { class: 'input mono', spellcheck: 'false' } });
  const userField = field({ label: 'Site user (optional)', name: 'system_user', validate: 'sysuser', hint: 'Linux user that owns the files and runs the app. Derived from the domain if empty.', attrs: { autocapitalize: 'off', spellcheck: 'false' } });

  typeGroup.addEventListener('change', () => {
    const t = typeGroup.querySelector('input:checked').value;
    portField.hidden = t === 'static';
    cmdField.hidden = !HAS_APP.has(t);
    cmdField.querySelector('input').placeholder = SITE_TYPES[t].cmd || 'e.g. ./server --port $PORT';
  });

  formDialog({
    title: 'Add site',
    description: 'Creates a Linux user, a home directory and an nginx virtual host. Point the domain’s DNS A record to this server.',
    submitText: 'Create site',
    drawer: true,
    content: [
      field({ label: 'Domain', name: 'domain', placeholder: 'app.example.com', validate: 'domain', attrs: { autocapitalize: 'off', spellcheck: 'false' } }),
      h('div', { class: 'field' }, h('span', { class: 'label', text: 'Type' }), typeGroup),
      portField, cmdField, userField,
      selectField({ label: 'www subdomain', name: 'www', options: WWW_OPTIONS, value: 'redirect' }),
    ],
    async onSubmit(d) {
      const body = { domain: d.domain.toLowerCase(), site_type: d.site_type, ...wwwBody(d.www) };
      if (d.site_type !== 'static') body.target_port = Number(d.target_port);
      if (d.app_command && HAS_APP.has(d.site_type)) body.app_command = d.app_command;
      if (d.system_user) body.system_user = d.system_user;
      const site = await api('/sites', { method: 'POST', body });
      toast(`${body.domain} created`);
      done();
      location.hash = `#/sites/${site.id}`;
      if (site.runtime_job_id) jobDialog(site.runtime_job_id, 'Installing the Node.js runtime');
    },
  });
}

async function deleteSite(site, done) {
  const keep = h('input', { type: 'checkbox', checked: true });
  const ok = await new Promise((resolve) => {
    let result = false;
    const confirmBtn = h('button', { class: 'btn danger solid', type: 'button', text: 'Delete site' });
    const cancel = h('button', { class: 'btn', type: 'button', text: 'Cancel' });
    const d = openDialog({
      title: `Delete ${site.domain}?`,
      body: h('div', { class: 'form' },
        h('p', { class: 'muted', text: 'The nginx configuration, app service and SSH users are removed and the site stops responding.' }),
        h('label', { class: 'check' }, keep, 'Keep the site’s files and Linux user home directory')),
      footer: [cancel, confirmBtn], onClose: () => resolve(result),
    });
    cancel.addEventListener('click', d.close);
    confirmBtn.addEventListener('click', () => { result = true; d.close(); });
  });
  if (!ok) return;
  if (!keep.checked && !(await typedConfirm({ title: 'Delete all files?', message: `Every file in the home directory of ${site.domain} will be permanently deleted.`, word: site.domain, confirmText: 'Delete everything' }))) return;
  try {
    const res = await api(`/sites/${site.id}?delete_files=${!keep.checked}`, { method: 'DELETE' });
    toast(res.warning ? `${site.domain} deleted (${res.warning})` : `${site.domain} deleted`, res.warning ? 'error' : 'success');
    done();
  } catch (e) { toast(e.message, 'error'); }
}

// ======================================================================
// Site detail
// ======================================================================

function renderSiteDetail(view, id, tab) {
  let site = null;
  const body = h('div');
  view.replaceChildren(card({ body: h('div', { class: 'skeleton' }) }));
  let cleanup = null;

  async function load(keepTab = tab) {
    try {
      site = await api(`/sites/${id}`);
    } catch (e) {
      if (e.status !== 401) view.replaceChildren(card({ body: errorState(e.message, () => load()) }));
      return;
    }
    document.title = `${site.domain} · CloudPanel`;
    document.querySelector('#page-title').textContent = site.domain;
    const t = SITE_TYPES[site.site_type] || { label: site.site_type };
    setSub(`${t.label} · ${site.is_active ? 'active' : 'disabled'}`);
    const url = `${site.ssl_enabled ? 'https' : 'http'}://${site.domain}`;
    const toggle = h('button', { class: 'btn' }, icon('power'), site.is_active ? 'Disable' : 'Enable');
    toggle.addEventListener('click', async () => {
      if (site.is_active && !(await confirmDialog({ title: `Disable ${site.domain}?`, message: 'Visitors will see a maintenance page (HTTP 503) and the app is stopped.', confirmText: 'Disable', danger: true }))) return;
      await withBusy(toggle, async () => {
        await api(`/sites/${id}/state`, { method: 'POST', body: { active: !site.is_active } });
        toast(site.is_active ? 'Site disabled' : 'Site enabled');
        await load(current);
      });
    });
    setActions(
      h('a', { class: 'btn ghost', href: '#/sites' }, icon('back'), h('span', { class: 'hide-sm', text: 'Sites' })),
      h('a', { class: 'btn', href: url, target: '_blank', rel: 'noopener noreferrer' }, icon('external'), h('span', { class: 'hide-sm', text: 'Open' })),
      toggle,
      isAdmin() && moreButton([{ icon: 'trash', label: 'Delete site', danger: true, action: () => deleteSite(site, () => { location.hash = '#/sites'; }) }]));

    const tabs = [['overview', 'Overview']];
    if (HAS_APP.has(site.site_type)) tabs.push(['app', 'Application']);
    for (const ext of SITE_TABS) if (!ext.when || ext.when(site)) tabs.push([ext.key, ext.label]);
    if (site.home_dir) tabs.push(['ssh', 'SSH / SFTP']);
    tabs.push(['ssl', 'SSL'], ['logs', 'Logs'], ['settings', 'Settings']);
    let current = tabs.some(([k]) => k === keepTab) ? keepTab : 'overview';

    const strip = tabStrip(tabs, current, (k) => {
      current = k;
      history.replaceState(null, '', `#/sites/${id}/${k}`);
      show();
    });
    strip.classList.add('page-tabs');
    view.replaceChildren(strip, body);

    function show() {
      if (cleanup) { cleanup(); cleanup = null; }
      body.replaceChildren();
      const ctx = { site, reload: () => load(current), body };
      const ext = SITE_TABS.find((x) => x.key === current);
      const fn = ext ? ext.render : { overview: tabOverview, app: tabApp, ssh: tabSsh, ssl: tabSsl, logs: tabLogs, settings: tabSettings }[current];
      cleanup = (fn || tabOverview)(body, ctx) || null;
    }
    show();
  }
  load();
  return () => { if (cleanup) cleanup(); };
}

// ---------- Overview ----------

function tabOverview(el, { site }) {
  const t = SITE_TYPES[site.site_type] || { label: site.site_type };
  const cert = site.certificate;
  el.append(h('div', { class: 'grid two' },
    card({
      title: 'Site', body: kv([
        ['Domain', site.domain], site.include_www && [site.www_redirect ? 'Redirect' : 'Alias', wwwLabel(site)], ['Type', t.label],
        site.target_port && ['App port', `127.0.0.1:${site.target_port}`],
        site.document_root && ['Document root', h('span', { class: 'mono', text: site.document_root })],
        ['Site user', h('span', { class: 'mono', text: site.system_user })],
        site.home_dir && ['Home', h('span', { class: 'mono', text: site.home_dir })],
        ['Created', fmtDate(site.created_at)],
      ]),
    }),
    h('div', { class: 'grid' },
      site.app && card({
        title: 'Application', sub: site.app.unit, body: kv([
          ['Status', appBadge(site.app)], ['Runs under', site.app_manager === 'pm2' ? 'PM2' : 'systemd'], site.app.main_pid && ['PID', site.app.main_pid],
          site.app.memory_bytes && ['Memory', fmtBytes(site.app.memory_bytes)],
          site.app.since && ['Since', site.app.since], ['Command', h('code', { class: 'truncate', text: site.app_command || '—' })],
        ]),
      }),
      card({
        title: 'Certificate', body: cert ? kv([
          ['Issuer', cert.issuer], ['Names', cert.names.join(', ') || cert.subject],
          ['Expires', h('span', { class: cert.days_left < 14 ? 'badge danger' : cert.days_left < 30 ? 'badge warn' : '', text: `${fmtDate(cert.not_after)} (${cert.days_left} days)` })],
        ]) : h('p', { class: 'muted', text: site.ssl_enabled ? 'Certificate file could not be read.' : 'HTTPS is not enabled for this site.' }),
      }))));
}

// ---------- Application ----------

function tabApp(el, { site, reload }) {
  const status = h('div');
  const logs = h('pre', { class: 'logs mono', text: 'Loading…' });
  const t = SITE_TYPES[site.site_type] || {};
  const isNode = site.site_type === 'nodejs';
  const options = site.pm2 || {};
  const project = site.project || {};

  // Environment: the box shows the site's .env file, so it can't disagree with the File Manager.
  const envField = field({ label: 'Environment variables', name: 'env', type: 'textarea', placeholder: 'NODE_ENV=production\nDATABASE_URL=…', hint: 'Loading…', attrs: { class: 'input mono', rows: 8, disabled: true } });
  const envInput = envField.querySelector('textarea');
  const envHint = envField.querySelector('.hint');
  const envNotes = h('div', { class: 'form' });
  let envLoaded = false;

  function notice(kind, text) { return h('div', { class: `alert ${kind}` }, icon('alert'), h('div', { text })); }

  async function loadEnv() {
    try {
      const r = await api(`/sites/${site.id}/app/env`);
      envInput.value = r.content;
      envInput.disabled = false;
      envLoaded = true;
      envHint.textContent = r.path
        ? `This is ${r.path}, the same file you see in the File Manager. Edit it in either place. Restart the app to apply changes.`
        : 'One KEY=value per line. Restart the app to apply changes.';
      const notes = [];
      if (r.pending) notes.push(notice('warn', 'This file has changes the running app hasn’t picked up. Restart the app to apply them.'));
      if (r.imported_keys.length) notes.push(notice('info', `${r.imported_keys.join(', ')} ${r.imported_keys.length === 1 ? 'is' : 'are'} only stored in the panel so far and ${r.imported_keys.length === 1 ? 'was' : 'were'} added below. Saving moves ${r.imported_keys.length === 1 ? 'it' : 'them'} to .env.`));
      if (r.port_conflict) notes.push(notice('warn', `PORT in this file is ${r.port_conflict}, but the site’s app port is ${site.target_port}. The app gets ${site.target_port}, because that is where nginx sends traffic. Change the app port in Settings if you want a different one.`));
      for (const w of r.warnings) notes.push(notice('warn', w));
      envNotes.replaceChildren(...notes);
    } catch (e) {
      envHint.textContent = '';
      envNotes.replaceChildren(notice('error', `The environment can’t be edited here: ${e.message}`));
    }
  }
  loadEnv();

  // Process manager
  const managerField = isNode && selectField({ label: 'Process manager', name: 'manager', value: site.app_manager, options: [['pm2', 'PM2'], ['systemd', 'systemd']] });
  const managerInput = managerField && managerField.querySelector('select');
  const usesPm2 = () => !!managerInput && managerInput.value === 'pm2';

  const ecoCheck = h('input', { type: 'checkbox', name: 'use_ecosystem', checked: options.use_ecosystem !== false });
  const ecoRow = site.ecosystem_file && h('label', { class: 'check' }, ecoCheck, `Use ${site.ecosystem_file.split('/').pop()} from the working directory`);
  const pm2Fields = h('div', { class: 'form' },
    field({ label: 'Instances', name: 'instances', value: options.instances || '1', hint: 'A number or max. More than 1 runs in cluster mode, which needs a JavaScript file such as server.js as the start command.', attrs: { class: 'input mono', spellcheck: 'false' } }),
    field({ label: 'Restart above this memory', name: 'max_memory', value: options.max_memory || '', placeholder: '512M', attrs: { class: 'input mono', spellcheck: 'false' } }),
    field({ label: 'Node.js arguments', name: 'node_args', value: options.node_args || '', placeholder: '--max-old-space-size=512', hint: 'For a JavaScript start command.', attrs: { class: 'input mono', spellcheck: 'false' } }),
    field({ label: 'Scheduled restart (cron)', name: 'cron_restart', value: options.cron_restart || '', placeholder: '0 4 * * *', attrs: { class: 'input mono', spellcheck: 'false' } }));
  const pm2Box = h('div', { class: 'form' }, ecoRow, pm2Fields);
  const commandField = field({ label: 'Start command', name: 'command', value: site.app_command || '', placeholder: t.cmd || './server', hint: '', attrs: { class: 'input mono', spellcheck: 'false' } });
  const commandHint = commandField.querySelector('.hint') || commandField.appendChild(h('div', { class: 'hint' }));
  function syncManager() {
    const pm2 = usesPm2();
    const eco = pm2 && !!site.ecosystem_file && ecoCheck.checked;
    pm2Box.hidden = !pm2;
    pm2Fields.hidden = eco;
    commandField.hidden = eco;
    commandHint.textContent = pm2
      ? 'A JavaScript file such as server.js runs directly and can use cluster mode. Anything else runs with /bin/sh -c. $PORT and your environment variables are available.'
      : 'Runs with /bin/sh -c as the site user. $PORT and your environment variables are available.';
  }
  if (managerInput) managerInput.addEventListener('change', syncManager);
  ecoCheck.addEventListener('change', syncManager);
  syncManager();

  const form = h('form', { class: 'form', novalidate: true },
    managerField,
    pm2Box,
    commandField,
    field({ label: 'Working directory', name: 'workdir', value: site.app_workdir || '', placeholder: site.app_workdir_default, validate: 'optionalPath', hint: 'Defaults to the site’s htdocs folder.', attrs: { class: 'input mono', spellcheck: 'false' } }),
    envField, envNotes,
    h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'enabled', checked: site.app_enabled }), 'Run this app (start now and on boot)'),
    h('div', { class: 'row' }, h('button', { class: 'btn primary', type: 'submit', text: 'Save & apply' })));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const btn = form.querySelector('button[type=submit]');
    const d = Object.fromEntries(new FormData(form));
    const body = { command: (d.command || '').trim() || null, workdir: d.workdir.trim() || null, enabled: form.elements.enabled.checked };
    if (envLoaded) body.env_text = envInput.value;
    if (isNode) {
      body.manager = managerInput.value;
      if (usesPm2()) {
        body.pm2 = { use_ecosystem: ecoCheck.checked, instances: d.instances.trim(), max_memory: d.max_memory.trim(), node_args: d.node_args.trim(), cron_restart: d.cron_restart.trim() };
        if (site.app && site.app.foreign_daemon) {
          const ok = await confirmDialog({ title: 'Take over the running PM2 daemon?', message: 'A PM2 daemon started by hand is running for this site. The panel will stop it and start it again under its own service, so it comes back after a reboot. Its apps restart briefly. The old process list is kept as ~/.pm2/dump.pm2.pre-cloudpanel.', confirmText: 'Take over' });
          if (!ok) return;
          body.adopt = true;
        }
      }
    }
    await withBusy(btn, async () => {
      const r = await api(`/sites/${site.id}/app`, { method: 'PUT', body });
      if (r.env_warnings && r.env_warnings.length) toast(`Saved. Some .env lines were skipped: ${r.env_warnings.join('; ')}`, 'error');
      else toast('Application saved');
      if (r.job_id) await jobDialog(r.job_id, 'Installing PM2');
      reload();
    });
  });

  // Actions
  const canStart = !!site.app_command || (site.app_manager === 'pm2' && !!site.ecosystem_file && options.use_ecosystem !== false);
  const pm2Active = site.app_manager === 'pm2';
  const act = (action) => {
    const label = action[0].toUpperCase() + action.slice(1);
    const b = h('button', { class: 'btn', disabled: !canStart }, icon({ start: 'play', stop: 'stop', restart: 'refresh', reload: 'refresh' }[action]), label);
    b.addEventListener('click', () => withBusy(b, async () => {
      const st = await api(`/sites/${site.id}/app/${action}`, { method: 'POST' });
      toast({ start: 'App started', stop: 'App stopped', restart: 'App restarted', reload: 'App reloaded' }[action]);
      drawStatus(st);
      loadEnv();
      setTimeout(loadLogs, 800);
    }));
    return b;
  };
  /** A button that runs a background job, then shows the result. */
  const jobButton = (label, iconName, path, title, before) => {
    const b = h('button', { class: 'btn' }, icon(iconName), label);
    b.addEventListener('click', async () => {
      try {
        const target = before ? await before() : path;
        if (!target) return;
        const j = await runJob(target, `${title} · ${site.domain}`);
        if (j && j.status === 'failed') toast(`${title} failed. The log has the details.`, 'error');
        reload();
      } catch (e) { toast(e.message, 'error'); }
    });
    return b;
  };
  const appPath = `/sites/${site.id}/app`;
  const hasDeps = isNode || site.site_type === 'python';
  const install = jobButton('Install dependencies', 'download', `${appPath}/install`, 'Install dependencies', async () => {
    if (!project.prebuilt) return `${appPath}/install`;
    const ok = await confirmDialog({ title: 'Install anyway?', message: `${project.note} Installing replaces its node_modules with a full install.`, confirmText: 'Install anyway', danger: true });
    return ok ? `${appPath}/install?force=true` : null;
  });
  install.hidden = !hasDeps;
  const build = jobButton('Build', 'terminal', `${appPath}/build`, 'Build');
  build.hidden = !isNode;
  if (project.prebuilt || !project.has_build_script) {
    build.disabled = true;
    build.title = project.prebuilt ? 'Prebuilt deploy: there is no source here to build' : 'package.json has no build script';
  }
  const deploy = jobButton('Deploy', 'play', `${appPath}/deploy`, 'Deploy');
  deploy.hidden = !hasDeps;
  deploy.title = 'Install dependencies, build, then restart the app';

  const processes = h('div');
  function drawStatus(app) {
    status.replaceChildren(kv([
      ['Status', appBadge(app)], ['Unit', h('code', { text: app ? app.unit : '—' })],
      app && app.main_pid && ['PID', app.main_pid], app && app.memory_bytes && ['Memory', fmtBytes(app.memory_bytes)],
      app && app.restarts != null && ['Restarts', app.restarts],
    ]));
    const list = (app && app.processes) || [];
    processes.replaceChildren(...(list.length ? [table(['App', 'Mode', 'Status', 'CPU', 'Memory', 'Restarts'], list.map((p) => h('tr', null,
      h('td', { class: 'mono truncate', text: `${p.name} #${p.id}` }),
      h('td', { text: p.exec_mode }),
      h('td', null, h('span', { class: `badge ${p.status === 'online' ? 'ok' : p.status === 'errored' ? 'danger' : 'warn'}`, text: p.status })),
      h('td', { text: `${p.cpu}%` }),
      h('td', { text: fmtBytes(p.memory_bytes) }),
      h('td', { text: p.restarts }))))] : []));
  }
  drawStatus(site.app);

  async function loadLogs() {
    try { const r = await api(`${appPath}/logs?lines=300`); logs.textContent = r.logs || '(no output)'; logs.scrollTop = logs.scrollHeight; } catch (e) { logs.textContent = e.message; }
  }
  const refresh = h('button', { class: 'icon-btn', title: 'Refresh', 'aria-label': 'Refresh logs' }, icon('refresh'));
  refresh.addEventListener('click', () => withBusy(refresh, loadLogs));
  const flush = h('button', { class: 'icon-btn', title: 'Clear log files', 'aria-label': 'Clear log files', hidden: !pm2Active }, icon('trash'));
  flush.addEventListener('click', async () => {
    if (!(await confirmDialog({ title: 'Clear the log files?', message: 'Everything in this app’s PM2 log files is deleted.', confirmText: 'Clear logs', danger: true }))) return;
    await withBusy(flush, async () => { await api(`${appPath}/flush`, { method: 'POST' }); toast('Logs cleared'); await loadLogs(); });
  });

  const processBanners = [];
  if (site.app && site.app.foreign_daemon) {
    processBanners.push(notice('warn', pm2Active
      ? 'A PM2 daemon started by hand is running for this site, and it won’t come back after a reboot. Save the settings to let the panel take it over.'
      : 'A PM2 daemon started by hand is running for this site, and it won’t come back after a reboot. Choose PM2 above and save to let the panel take it over.'));
  }
  if (project.note) processBanners.push(notice('info', project.note));

  el.append(h('div', { class: 'grid two' },
    card({ title: 'Configuration', body: form }),
    card({
      title: 'Process', sub: pm2Active ? 'Managed by PM2' : 'Managed by systemd',
      body: h('div', { class: 'form' }, ...processBanners, status, processes,
        h('div', { class: 'row wrap' }, act('start'), act('stop'), act('restart'), pm2Active && act('reload')),
        hasDeps && h('div', { class: 'row wrap' }, install, build, deploy)),
    })),
  card({ title: 'Output', sub: pm2Active ? '~/.pm2/logs' : 'journalctl', actions: h('div', { class: 'row' }, flush, refresh), body: logs }));
  loadLogs();
}

// ---------- SSH / SFTP ----------

function tabSsh(el, { site }) {
  const holder = h('div', null, card({ flush: true, body: table(['User', 'Access', 'Keys', ''], skeletonRows(4, 2)) }));
  const add = h('button', { class: 'btn primary' }, icon('plus'), 'Add user');
  add.addEventListener('click', () => addSshUser(site, load));
  el.append(
    h('div', { class: 'alert info' }, icon('terminal'), h('div', { text: `Connect with sftp or ssh to port 22 of this server. All users share the files in ${site.home_dir}.` })),
    h('div', { class: 'row end' }, add), holder);

  async function load() {
    try {
      const users = await api(`/sites/${site.id}/ssh-users`);
      const toggleSftp = async (u) => {
        try {
          await api(`/sites/${site.id}/ssh-users/${u.id}`, { method: 'PATCH', body: { sftp_only: !u.sftp_only } });
          toast('Access updated');
          load();
        } catch (e) { toast(e.message, 'error'); }
      };
      const remove = async (u) => {
        if (!(await confirmDialog({ title: `Delete ${u.username}?`, message: 'The account and its keys are removed. Files are kept.', confirmText: 'Delete', danger: true }))) return;
        try {
          await api(`/sites/${site.id}/ssh-users/${u.id}`, { method: 'DELETE' });
          toast('User deleted');
          load();
        } catch (e) { toast(e.message, 'error'); }
      };
      const rows = users.map((u) => {
        const items = [
          { icon: 'key', label: 'SSH keys', action: () => keysDialog(site, u, load) },
          { icon: 'lock', label: 'Set password', action: () => passwordDialog(site, u) },
        ];
        if (!u.is_owner) {
          items.push({ icon: 'terminal', label: u.sftp_only ? 'Allow shell (SSH)' : 'Restrict to SFTP', action: () => toggleSftp(u) });
          items.push('-', { icon: 'trash', label: 'Delete user', danger: true, action: () => remove(u) });
        }
        return h('tr', null,
          h('td', null, h('div', { class: 'cell-title mono', text: u.username }), u.is_owner && h('div', { class: 'cell-sub', text: 'Site owner' })),
          h('td', null, h('span', { class: `badge ${u.sftp_only ? '' : 'accent'}`, text: u.sftp_only ? 'SFTP only' : 'SSH + SFTP' })),
          h('td', { class: 'hide-sm muted', text: `${u.keys.length} key${u.keys.length === 1 ? '' : 's'}` }),
          h('td', { class: 'actions' }, moreButton(items)));
      });
      holder.replaceChildren(card({ flush: true, body: table(['User', 'Access', { label: 'Keys', class: 'hide-sm' }, ''], rows) }));
    } catch (e) { if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) })); }
  }
  load();
}

function addSshUser(site, done) {
  formDialog({
    title: 'Add SSH / SFTP user', description: 'The user shares the site’s group and home directory.', submitText: 'Create user',
    content: [
      field({ label: 'Username', name: 'username', validate: 'sysuser', placeholder: `${site.system_user}-deploy`, attrs: { autocapitalize: 'off', spellcheck: 'false' } }),
      field({ label: 'Password (optional)', name: 'password', type: 'password', validate: 'optionalPassword', hint: 'Leave empty to use SSH keys only.', attrs: { autocomplete: 'new-password' } }),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'sftp_only', checked: true }), 'SFTP only (no shell access)'),
    ],
    async onSubmit(d) {
      await api(`/sites/${site.id}/ssh-users`, { method: 'POST', body: { username: d.username, password: d.password || null, sftp_only: !!d.sftp_only } });
      toast(`${d.username} created`);
      done();
    },
  });
}

function passwordDialog(site, u) {
  formDialog({
    title: `Password for ${u.username}`, submitText: 'Set password',
    content: [field({ label: 'New password', name: 'password', type: 'password', validate: 'password', hint: 'At least 10 characters.', attrs: { autocomplete: 'new-password' } })],
    async onSubmit(d) { await api(`/sites/${site.id}/ssh-users/${u.id}/password`, { method: 'POST', body: { password: d.password } }); toast('Password updated'); },
  });
}

function keysDialog(site, u, done) {
  const list = h('div', { class: 'form' });
  const draw = (keys) => {
    list.replaceChildren(...(keys.length ? keys.map((k) => {
      const del = h('button', { class: 'icon-btn danger', title: 'Remove key', 'aria-label': `Remove key ${k.name}` }, icon('trash'));
      del.addEventListener('click', () => withBusy(del, async () => {
        await api(`/sites/${site.id}/ssh-users/${u.id}/keys/${k.id}`, { method: 'DELETE' });
        toast('Key removed'); await refresh();
      }));
      return h('div', { class: 'row' }, h('div', { class: 'grow' }, h('div', { class: 'strong', text: k.name }), h('div', { class: 'small mono muted truncate', text: k.fingerprint })), del);
    }) : [h('p', { class: 'muted', text: 'No keys yet.' })]));
  };
  async function refresh() {
    const users = await api(`/sites/${site.id}/ssh-users`);
    const me = users.find((x) => x.id === u.id);
    draw(me ? me.keys : []);
    done();
  }
  const keyInput = h('textarea', { class: 'input mono', rows: 3, placeholder: 'ssh-ed25519 AAAA… you@laptop', 'aria-label': 'Public key', spellcheck: 'false' });
  const nameInput = h('input', { class: 'input', placeholder: 'Name (optional)', 'aria-label': 'Key name' });
  const addBtn = h('button', { class: 'btn primary', type: 'button' }, icon('plus'), 'Add key');
  addBtn.addEventListener('click', () => withBusy(addBtn, async () => {
    await api(`/sites/${site.id}/ssh-users/${u.id}/keys`, { method: 'POST', body: { public_key: keyInput.value.trim(), name: nameInput.value.trim() || null } });
    keyInput.value = ''; nameInput.value = '';
    toast('Key added'); await refresh();
  }));
  draw(u.keys);
  openDialog({ title: `SSH keys · ${u.username}`, wide: true, body: h('div', { class: 'form' }, list, h('hr'), keyInput, h('div', { class: 'row' }, nameInput, addBtn)) });
}

// ---------- SSL ----------

function tabSsl(el, { site, reload }) {
  const cert = site.certificate;
  const install = h('button', { class: 'btn primary' }, icon('lock'), site.ssl_enabled ? 'Replace certificate' : 'Enable HTTPS');
  install.addEventListener('click', () => sslDialog(site, reload));
  const renew = h('button', { class: 'btn', hidden: !site.certificate_managed }, icon('refresh'), 'Renew now');
  renew.addEventListener('click', () => withBusy(renew, async () => { await api(`/sites/${site.id}/ssl/renew`, { method: 'POST' }); toast('Certificate renewed'); reload(); }));
  const remove = h('button', { class: 'btn danger', hidden: !site.ssl_enabled }, icon('unlock'), 'Disable HTTPS');
  remove.addEventListener('click', async () => {
    if (!(await confirmDialog({ title: 'Disable HTTPS?', message: 'The site will be served over plain HTTP. The certificate files are kept.', confirmText: 'Disable HTTPS', danger: true }))) return;
    await withBusy(remove, async () => { await api(`/sites/${site.id}/ssl`, { method: 'DELETE' }); toast('HTTPS disabled'); reload(); });
  });
  el.append(card({
    title: 'HTTPS', sub: site.certificate_managed ? 'Let’s Encrypt certificates renew automatically via certbot.' : '',
    body: h('div', { class: 'form' },
      cert ? kv([['Issuer', cert.issuer], ['Names', cert.names.join(', ') || cert.subject], ['Valid from', fmtDate(cert.not_before)], ['Expires', `${fmtDate(cert.not_after)} (${cert.days_left} days)`], ['Certificate', h('span', { class: 'mono small', text: site.ssl_cert_path })]])
        : h('p', { class: 'muted', text: 'No certificate is installed. Visitors connect over HTTP.' }),
      wwwCertWarning(site, reload),
      h('div', { class: 'row wrap' }, install, renew, remove)),
  }));
}

export function sslDialog(site, done) {
  let mode = 'le';
  const le = h('div', { class: 'form' },
    h('div', { class: 'alert info' }, icon('alert'),
      h('div', { text: `DNS for ${site.domain} must already point to this server, and port 80 must be open.${site.include_www ? ` www.${site.domain} is added too if it has a DNS record; if it can’t be validated, the certificate covers ${site.domain} only.` : ''}` })),
    field({ label: 'Email for expiry notices', name: 'email', type: 'email', placeholder: 'you@example.com', validate: 'email', attrs: { autocomplete: 'email' } }));
  const custom = h('div', { class: 'form', hidden: true },
    field({ label: 'Certificate (PEM, full chain)', name: 'custom_cert', type: 'textarea', placeholder: '-----BEGIN CERTIFICATE-----', validate: 'required' }),
    field({ label: 'Private key (PEM)', name: 'custom_key', type: 'textarea', placeholder: '-----BEGIN PRIVATE KEY-----', validate: 'required' }));
  const strip = tabStrip([['le', "Let's Encrypt"], ['custom', 'Custom certificate']], 'le', (m) => { mode = m; le.hidden = m !== 'le'; custom.hidden = m === 'le'; });
  formDialog({
    title: `SSL for ${site.domain}`,
    description: 'HTTP traffic will be redirected to HTTPS.',
    submitText: 'Install certificate',
    content: [strip, le, custom],
    async onSubmit(d) {
      const body = mode === 'le' ? { email: d.email } : { custom_cert: d.custom_cert, custom_key: d.custom_key };
      const r = await api(`/sites/${site.id}/ssl`, { method: 'POST', body });
      if (r.warning) toast(`SSL enabled for ${site.domain}. ${r.warning}`, 'error');
      else toast(`SSL enabled for ${site.domain}`);
      done();
    },
  });
}

// ---------- Logs ----------

function tabLogs(el, { site }) {
  const kinds = [['access', 'Access log'], ['error', 'Error log']];
  if (HAS_APP.has(site.site_type)) kinds.push(['app', 'App output']);
  const kind = h('select', { class: 'input', 'aria-label': 'Log' }, kinds.map(([v, t]) => h('option', { value: v, text: t })));
  const lines = h('select', { class: 'input', 'aria-label': 'Lines' }, [100, 500, 2000].map((n) => h('option', { value: n, text: `Last ${n} lines`, selected: n === 500 })));
  kind.style.width = 'auto'; lines.style.width = 'auto';
  const pre = h('pre', { class: 'logs mono tall', text: 'Loading…' });
  const refresh = h('button', { class: 'btn' }, icon('refresh'), 'Refresh');
  async function load() {
    try { const r = await api(`/sites/${site.id}/logs?kind=${kind.value}&lines=${lines.value}`); pre.textContent = r.logs || '(empty)'; pre.scrollTop = pre.scrollHeight; } catch (e) { pre.textContent = e.message; }
  }
  kind.addEventListener('change', load);
  lines.addEventListener('change', load);
  refresh.addEventListener('click', () => withBusy(refresh, load));
  el.append(card({ body: h('div', { class: 'form' }, h('div', { class: 'row' }, kind, lines, refresh), pre) }));
  load();
}

// ---------- Settings ----------

/** Warn when https://www can't work because the certificate doesn't cover it. */
function wwwCertWarning(site, reload) {
  if (!site.include_www || !site.ssl_enabled || site.certificate_covers_www) return null;
  const text = `The certificate doesn’t cover www.${site.domain}, so https://www.${site.domain} shows a certificate error. http://www still works.`;
  const add = h('button', { class: 'btn sm', type: 'button', text: site.certificate_managed ? 'Add www to certificate' : 'Replace certificate' });
  add.addEventListener('click', () => sslDialog(site, reload));
  return h('div', { class: 'alert warn' }, icon('alert'), h('div', { class: 'form' }, h('div', { text }), h('div', null, add)));
}

function tabSettings(el, { site, reload }) {
  const general = h('form', { class: 'form', novalidate: true },
    site.site_type !== 'static' && field({ label: 'App port', name: 'target_port', type: 'number', value: site.target_port, validate: 'port' }),
    site.site_type === 'static' && field({ label: 'Document root', name: 'document_root', value: site.document_root || '', validate: 'optionalPath', attrs: { class: 'input mono' } }),
    field({ label: 'Upload limit (MB)', name: 'max_body_mb', type: 'number', value: site.max_body_mb, hint: 'nginx client_max_body_size.', attrs: { min: 1, max: 10240 } }),
    !site.domain.startsWith('www.') && selectField({ label: `www.${site.domain}`, name: 'www', options: WWW_OPTIONS, value: wwwMode(site) }),
    wwwCertWarning(site, reload),
    site.site_type !== 'static' && h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'websocket', checked: site.websocket }), 'WebSocket support'),
    h('div', null, h('button', { class: 'btn primary', type: 'submit', text: 'Save' })));
  general.addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = general.elements;
    const body = { max_body_mb: Number(f.max_body_mb.value), ...(f.www ? wwwBody(f.www.value) : {}) };
    if (f.target_port) body.target_port = Number(f.target_port.value);
    if (f.websocket) body.websocket = f.websocket.checked;
    if (f.document_root && f.document_root.value.trim()) body.document_root = f.document_root.value.trim();
    await withBusy(general.querySelector('button[type=submit]'), async () => { await api(`/sites/${site.id}`, { method: 'PATCH', body }); toast('Settings saved'); reload(); });
  });

  // Basic auth
  const authUsers = h('div', { class: 'form' });
  const drawAuthUsers = () => authUsers.replaceChildren(...(site.basic_auth_users.length ? site.basic_auth_users.map((u) => {
    const del = h('button', { class: 'icon-btn danger', title: 'Remove', 'aria-label': `Remove ${u.username}` }, icon('trash'));
    del.addEventListener('click', () => withBusy(del, async () => { await api(`/sites/${site.id}/basic-auth/users/${u.id}`, { method: 'DELETE' }); toast('User removed'); reload(); }));
    return h('div', { class: 'row' }, icon('user'), h('span', { class: 'grow mono', text: u.username }), del);
  }) : [h('p', { class: 'muted small', text: 'No users yet.' })]));
  drawAuthUsers();
  const addAuth = h('button', { class: 'btn', type: 'button' }, icon('plus'), 'Add user');
  addAuth.addEventListener('click', () => formDialog({
    title: 'Add basic auth user', submitText: 'Add',
    content: [field({ label: 'Username', name: 'username', validate: 'username' }), field({ label: 'Password', name: 'password', type: 'password', validate: 'required', attrs: { autocomplete: 'new-password' } })],
    async onSubmit(d) { await api(`/sites/${site.id}/basic-auth/users`, { method: 'POST', body: d }); toast('User added'); reload(); },
  }));
  const authEnabled = h('input', { type: 'checkbox', checked: site.basic_auth_enabled });
  const allow = h('textarea', { class: 'input mono', rows: 3, placeholder: '203.0.113.10\n10.0.0.0/8', 'aria-label': 'Allow-list' });
  allow.value = site.basic_auth_allow || '';
  const saveAuth = h('button', { class: 'btn primary', type: 'button', text: 'Save' });
  saveAuth.addEventListener('click', () => withBusy(saveAuth, async () => {
    await api(`/sites/${site.id}/basic-auth`, { method: 'PUT', body: { enabled: authEnabled.checked, allow: allow.value.split('\n').map((x) => x.trim()).filter(Boolean) } });
    toast('Password protection saved'); reload();
  }));

  const cards = [
    card({ title: 'General', body: general }),
    card({
      title: 'Password protection', sub: 'HTTP basic authentication in front of the whole site.', body: h('div', { class: 'form' },
        h('label', { class: 'check' }, authEnabled, 'Require a username and password'),
        authUsers, h('div', null, addAuth),
        h('div', { class: 'field' }, h('label', { text: 'IPs that skip the password (optional)' }), allow, h('div', { class: 'hint', text: 'One IP or CIDR per line.' })),
        h('div', null, saveAuth)),
    }),
  ];

  // Vhost / custom directives (admin)
  const vhost = h('pre', { class: 'logs mono tall', text: 'Loading…' });
  const directives = h('textarea', { class: 'input mono', rows: 8, spellcheck: 'false', 'aria-label': 'Custom nginx directives', disabled: !isAdmin(), placeholder: 'location /api/ {\n    proxy_pass http://127.0.0.1:9000;\n}' });
  directives.value = site.custom_directives || '';
  const saveDir = h('button', { class: 'btn primary', type: 'button', text: 'Save & test', hidden: !isAdmin() });
  saveDir.addEventListener('click', () => withBusy(saveDir, async () => {
    await api(`/sites/${site.id}/directives`, { method: 'PUT', body: { custom_directives: directives.value } });
    toast('Directives applied (nginx -t passed)'); reload();
  }));
  api(`/sites/${site.id}/vhost`).then((r) => { vhost.textContent = r.vhost; }).catch((e) => { vhost.textContent = e.message; });
  cards.push(card({
    title: 'nginx', sub: isAdmin() ? 'Extra directives are inserted into the server block and checked with nginx -t before reload.' : 'Only administrators can add custom directives.',
    body: h('div', { class: 'form' }, h('label', { class: 'small strong', text: 'Custom directives' }), directives, h('div', null, saveDir), h('label', { class: 'small strong', text: 'Generated vhost' }), vhost),
  }));
  el.append(h('div', { class: 'grid two' }, cards[0], cards[1]), cards[2]);
}

export { secretDialog };
