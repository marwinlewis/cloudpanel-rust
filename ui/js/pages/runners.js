'use strict';
// GitHub Actions self-hosted runners. Each runs as its site's Linux user and deploys that site
// through the panel. Site managers see the runners of their sites; administrators see all, keep
// GitHub tokens, install the runner release and adopt runners that were installed by hand.
import {
  api, card, confirmDialog, copyButton, emptyState, errorState, field, fmtAgo, formDialog, h, icon, jobDialog,
  moreButton, openDialog, runJob, selectField, setActions, setSub, skeletonRows, table, toast, withBusy,
} from '../core.js';

const BASE = '/runners';

function stateBadge(r) {
  const s = r.status || {};
  if (s.missing) return h('span', { class: 'badge danger', text: 'Files missing' });
  if (s.active_state === 'active') return h('span', { class: 'badge ok', text: 'Running' });
  if (s.active_state === 'activating') return h('span', { class: 'badge warn', text: 'Starting' });
  if (s.active_state === 'failed') return h('span', { class: 'badge danger', text: 'Failed' });
  if (s.active_state === 'not-installed') return h('span', { class: 'badge warn', text: 'No service' });
  return h('span', { class: 'badge', text: s.active_state || 'Stopped' });
}

function githubBadge(r) {
  if (!r.github) return null;
  if (r.github.busy) return h('span', { class: 'badge accent', text: 'Running a job' });
  if (r.github.status === 'online') return h('span', { class: 'badge ok', text: 'Online on GitHub' });
  return h('span', { class: 'badge warn', text: r.github.status === 'offline' ? 'Offline on GitHub' : 'Not on GitHub' });
}

/** The workflow step that deploys the runner's site. */
function workflowSnippet() {
  return [
    'jobs:',
    '  deploy:',
    '    runs-on: [self-hosted]',
    '    steps:',
    '      - uses: actions/checkout@v4',
    '      # Copy the build into the site, e.g.:',
    '      # - run: rsync -a --delete ./ "$HOME/htdocs/app.example.com/"',
    '      - name: Deploy with CloudPanel',
    '        run: |',
    '          curl -fsSk -X POST "$CLOUDPANEL_DEPLOY_URL" \\',
    '            -H "Authorization: Bearer $CLOUDPANEL_DEPLOY_TOKEN" \\',
    '            -H "Content-Type: application/json" \\',
    '            -d \'{"action":"deploy","wait":true}\'',
  ].join('\n');
}

function logsDrawer(r) {
  const pre = h('pre', { class: 'logs mono', text: 'Loading…' });
  const load = async () => {
    try { const x = await api(`${BASE}/${r.id}/logs?lines=500`); pre.textContent = x.logs || '(no output)'; pre.scrollTop = pre.scrollHeight; } catch (e) { pre.textContent = e.message; }
  };
  openDialog({ title: `Runner ${r.name}`, description: 'Recent log lines of its service', drawer: true, body: pre });
  load();
}

export function renderRunners(view) {
  const notice = h('div');
  const main = h('div', null, card({ title: 'GitHub runners', body: skeletonRows(3) }));
  const extra = h('div');
  view.replaceChildren(h('div', { class: 'grid' }, notice, main, extra));
  let d = null;

  async function load() {
    try {
      d = await api(BASE);
    } catch (e) {
      if (e.status !== 401) main.replaceChildren(card({ body: errorState(e.message, load) }));
      return;
    }
    render();
  }

  function installButton(label) {
    const b = h('button', { class: 'btn primary sm', type: 'button' }, icon('download'), label);
    b.addEventListener('click', () => withBusy(b, async () => {
      const job = await runJob(`${BASE}/install`, label);
      if (job && job.status === 'succeeded') toast('GitHub runners are ready');
      await load();
    }));
    return b;
  }

  function addButton(primary = true) {
    return h('button', { class: `btn ${primary ? 'primary' : 'sm'}`, onclick: () => addDialog(d, load) }, icon('plus'), 'Add runner');
  }

  function render() {
    setActions(d.installed && addButton());
    setSub(d.installed ? `${d.runners.length} runner${d.runners.length === 1 ? '' : 's'} · release ${d.version}` : '');

    const notes = [];
    if (d.is_admin && d.unmanaged > 0) {
      notes.push(h('div', { class: 'alert info' }, icon('search'),
        h('div', { class: 'grow', text: `Found ${d.unmanaged} runner${d.unmanaged === 1 ? '' : 's'} on this server that ${d.unmanaged === 1 ? 'was' : 'were'} installed by hand. The panel can take ${d.unmanaged === 1 ? 'it' : 'them'} over without registering again.` }),
        h('button', { class: 'btn sm', type: 'button', onclick: () => scanDialog(load) }, 'Review')));
    }
    notice.replaceChildren(...notes);

    if (!d.installed && !d.runners.length) {
      main.replaceChildren(card({ body: emptyState({
        iconName: 'git', title: 'GitHub runners are not installed',
        text: !d.is_admin
          ? 'Ask an administrator to install GitHub runners.'
          : d.can_install
            ? 'Install GitHub\'s self-hosted runner to run Actions workflows on this server and deploy your sites from them. Each runner runs as its site\'s own user.'
            : 'Re-run the CloudPanel installer with --with-runners to install it.',
        action: d.is_admin && d.can_install && installButton('Install runners'),
      }) }));
      extra.replaceChildren(d.is_admin ? credentialsCard() : '');
      return;
    }

    if (!d.runners.length) {
      main.replaceChildren(card({ body: emptyState({
        iconName: 'git', title: 'No runners yet',
        text: 'Add a runner for a site, then use runs-on: self-hosted in that repository\'s workflows.',
        action: addButton(),
      }) }));
    } else {
      main.replaceChildren(card({ title: 'Runners', flush: true, body: table(
        ['Runner', { label: 'Site', class: 'hide-sm' }, { label: 'GitHub', class: 'hide-sm' }, 'Status', ''],
        d.runners.map((r) => h('tr', null,
          h('td', null,
            h('div', { class: 'cell-title' }, r.name, r.adopted ? h('span', { class: 'badge', text: 'Adopted' }) : ''),
            h('div', { class: 'cell-sub mono', text: `${r.system_user} · ${r.dir}` })),
          h('td', { class: 'hide-sm muted', text: r.site_domain || 'No site (admins only)' }),
          h('td', { class: 'hide-sm' },
            h('a', { href: r.github_url, target: '_blank', rel: 'noopener', class: 'mono small', text: r.github_url.replace('https://github.com/', '') }),
            h('div', { class: 'cell-sub', text: [r.org ? 'Organization' : 'Repository', r.labels].filter(Boolean).join(' · ') })),
          h('td', null, h('div', { class: 'row' }, stateBadge(r), githubBadge(r)),
            r.status && r.status.since ? h('div', { class: 'cell-sub', text: `since ${r.status.since}` }) : ''),
          h('td', { class: 'actions' }, moreButton([
            { icon: 'terminal', label: 'Logs', action: () => logsDrawer(r) },
            { icon: 'refresh', label: 'Restart', action: () => act(r, 'restart') },
            r.status && r.status.active_state === 'active'
              ? { icon: 'stop', label: 'Stop', action: () => act(r, 'stop') }
              : { icon: 'play', label: 'Start', action: () => act(r, 'start') },
            r.site_id && { icon: 'key', label: 'New deploy token', action: () => rotate(r) },
            '-',
            { icon: 'trash', label: 'Remove…', danger: true, action: () => removeDialog(r, load) },
          ].filter(Boolean))))),
      ) }));
    }

    extra.replaceChildren(h('div', { class: 'grid two' },
      card({ title: 'Deploying from a workflow', actions: copyButton(workflowSnippet), body: h('div', { class: 'form' },
        h('p', { class: 'muted', text: 'Every runner\'s jobs get CLOUDPANEL_DEPLOY_URL and CLOUDPANEL_DEPLOY_TOKEN. Calling it installs dependencies, builds and restarts the runner\'s site, the same as Deploy in the site\'s Application tab.' }),
        h('pre', { class: 'logs mono snippet', text: workflowSnippet() }),
        h('div', { class: 'alert warn' }, icon('alert'), h('div', { text: 'Anyone who can run a workflow on a runner runs code as its site\'s user. Use runners with private repositories, as GitHub recommends, and don\'t let pull requests from forks run on them.' }))) }),
      d.is_admin ? credentialsCard() : ''));
  }

  function credentialsCard() {
    const add = h('button', { class: 'btn sm', onclick: () => credentialDialog(load) }, icon('plus'), 'Add token');
    const body = d.credentials.length
      ? table(['Name', { label: 'Added', class: 'hide-sm' }, ''], d.credentials.map((c) => h('tr', null,
        h('td', { class: 'strong', text: c.name }),
        h('td', { class: 'hide-sm muted', text: fmtAgo(c.created_at) }),
        h('td', { class: 'actions' }, moreButton([{ icon: 'trash', label: 'Delete', danger: true, action: () => removeCredential(c) }])))))
      : h('p', { class: 'muted', text: 'With a saved GitHub token the panel gets registration and removal tokens itself and shows whether GitHub sees each runner. Without one, paste a token from the repository\'s Settings → Actions → Runners → New self-hosted runner.' });
    return card({ title: 'GitHub tokens', actions: add, flush: d.credentials.length > 0, body });
  }

  async function act(r, action) {
    try { await api(`${BASE}/${r.id}/${action}`, { method: 'POST' }); toast(`${r.name}: ${action} done`); load(); } catch (e) { toast(e.message, 'error'); }
  }

  async function rotate(r) {
    if (!(await confirmDialog({ title: `New deploy token for ${r.name}?`, message: 'The old token stops working and the runner restarts, which cancels a job it is running.', confirmText: 'Replace token' }))) return;
    try { await api(`${BASE}/${r.id}/deploy-token`, { method: 'POST' }); toast('Deploy token replaced'); load(); } catch (e) { toast(e.message, 'error'); }
  }

  async function removeCredential(c) {
    if (!(await confirmDialog({ title: `Delete token ${c.name}?`, message: 'Runners registered with it keep running. Removing them then needs a removal token from GitHub. Revoke the token on GitHub too.', confirmText: 'Delete', danger: true }))) return;
    try { await api(`/github-credentials/${c.id}`, { method: 'DELETE' }); toast('Token deleted'); load(); } catch (e) { toast(e.message, 'error'); }
  }

  load();
}

/** Show or hide parts of a form when a select changes. */
function toggle(select, parts) {
  const sync = () => { for (const [value, el] of parts) el.hidden = select.value !== value; };
  select.addEventListener('change', sync);
  sync();
}

function addDialog(d, done) {
  const sites = d.sites.filter((s) => s.has_user);
  if (!sites.length) {
    toast('Runners need a site with its own Linux user (Node.js, Python, static or PHP).', 'error');
    return;
  }
  const how = selectField({
    label: 'Register with', name: 'how', value: 'paste',
    options: [['paste', 'A registration token copied from GitHub'], ...(d.credentials.length ? [['saved', 'A saved GitHub token']] : [])],
  });
  const paste = h('div', null,
    field({ label: 'Registration token', name: 'token', placeholder: 'AABBCC…', validate: 'required', attrs: { autocomplete: 'off', spellcheck: 'false' } }),
    h('p', { class: 'hint', text: 'GitHub: the repository or organization → Settings → Actions → Runners → New self-hosted runner. It is the value after --token, valid for one hour.' }));
  const saved = h('div', null, d.credentials.length
    ? selectField({ label: 'Saved token', name: 'credential_id', value: String(d.credentials[0].id), options: d.credentials.map((c) => [String(c.id), c.name]) })
    : '');
  formDialog({
    title: 'Add runner',
    description: 'The runner runs as the site\'s Linux user, from ~/actions-runner/<name>, and can deploy that site.',
    submitText: 'Add runner',
    content: [
      selectField({ label: 'Site', name: 'site_id', value: String(sites[0].id), options: sites.map((s) => [String(s.id), `${s.domain} (${s.system_user})`]) }),
      field({ label: 'Repository or organization URL', name: 'url', placeholder: 'https://github.com/acme/app', validate: 'required', attrs: { spellcheck: 'false' } }),
      h('div', { class: 'form-grid' },
        field({ label: 'Name', name: 'name', placeholder: 'Default: from the domain', attrs: { maxlength: 64, spellcheck: 'false' } }),
        field({ label: 'Extra labels', name: 'labels', placeholder: 'e.g. deploy,production', attrs: { spellcheck: 'false' } })),
      field({ label: 'Runner group (organizations only)', name: 'group', placeholder: 'Default' }),
      how, paste, saved,
    ],
    async onSubmit(f, dlg) {
      const body = { site_id: Number(f.site_id), url: f.url, name: f.name || null, labels: f.labels, group: f.group };
      if (f.how === 'saved') body.credential_id = Number(f.credential_id); else body.token = f.token;
      const r = await api(BASE, { method: 'POST', body });
      dlg.close();
      const job = await jobDialog(r.job_id, 'Adding runner');
      if (job && job.status === 'succeeded') toast('Runner added');
      done();
    },
  });
  toggle(how.querySelector('select'), [['paste', paste], ['saved', saved]]);
}

function removeDialog(r, done) {
  const how = selectField({
    label: 'Unregister from GitHub with', name: 'how', value: r.credential_id ? 'saved' : 'paste',
    options: [
      ...(r.credential_id ? [['saved', 'The saved GitHub token it was added with']] : []),
      ['paste', 'A removal token copied from GitHub'],
      ['force', 'Nothing: remove it from this server only'],
    ],
  });
  const paste = h('div', null,
    field({ label: 'Removal token', name: 'token', validate: 'required', attrs: { autocomplete: 'off', spellcheck: 'false' } }),
    h('p', { class: 'hint', text: 'GitHub: Settings → Actions → Runners → the runner → Remove. It is the value after --token.' }));
  const force = h('div', { class: 'alert warn' }, icon('alert'), h('div', { text: 'GitHub keeps listing the runner as offline until you delete it there.' }));
  formDialog({
    title: `Remove runner ${r.name}?`,
    description: `Its service stops and ${r.dir} is deleted.`,
    submitText: 'Remove runner',
    content: [how, paste, force],
    async onSubmit(f, dlg) {
      const body = f.how === 'paste' ? { token: f.token } : { force: f.how === 'force' };
      const x = await api(`${BASE}/${r.id}/remove`, { method: 'POST', body });
      dlg.close();
      const job = await jobDialog(x.job_id, `Removing ${r.name}`);
      if (job && job.status === 'succeeded') toast(`${r.name} removed`);
      done();
    },
  });
  toggle(how.querySelector('select'), [['paste', paste], ['force', force]]);
}

function credentialDialog(done) {
  formDialog({
    title: 'Add GitHub token',
    description: 'It is stored encrypted and only used to ask GitHub for runner registration and removal tokens.',
    submitText: 'Save token',
    content: [
      field({ label: 'Name', name: 'name', placeholder: 'e.g. acme organization', validate: 'required', attrs: { maxlength: 64 } }),
      field({ label: 'Token', name: 'token', type: 'password', placeholder: 'github_pat_…', validate: 'required', attrs: { autocomplete: 'off' } }),
      h('p', { class: 'hint', text: 'A fine-grained token with Administration: read and write on the repositories, or Self-hosted runners: read and write on the organization.' }),
    ],
    async onSubmit(f) {
      await api('/github-credentials', { method: 'POST', body: f });
      toast('Token saved');
      done();
    },
  });
}

async function scanDialog(done) {
  const body = h('div', { class: 'form' }, skeletonRows(2));
  const dlg = openDialog({ title: 'Runners installed by hand', description: 'Adopting one replaces its actions.runner service with the panel\'s, for the same directory and GitHub registration.', body, wide: true });
  let found;
  try { found = (await api(`${BASE}/scan`)).runners; } catch (e) { body.replaceChildren(errorState(e.message)); return; }
  if (!found.length) { body.replaceChildren(h('p', { class: 'muted', text: 'Nothing to adopt.' })); return; }
  body.replaceChildren(table(['Runner', 'Runs as', ''], found.map((f) => {
    const adopt = h('button', { class: 'btn sm primary', type: 'button', disabled: !!f.problem, text: 'Adopt' });
    adopt.addEventListener('click', () => withBusy(adopt, async () => {
      try {
        const job = await runJob(`${BASE}/adopt`, `Adopting ${f.name}`, { dir: f.dir });
        if (job && job.status === 'succeeded') { toast(`${f.name} adopted`); dlg.close(); }
      } catch (e) { toast(e.message, 'error'); }
      done();
    }));
    return h('tr', null,
      h('td', null, h('div', { class: 'cell-title', text: f.name || '(unnamed)' }), h('div', { class: 'cell-sub mono', text: f.dir }),
        h('div', { class: 'cell-sub', text: f.github_url }),
        f.problem ? h('div', { class: 'cell-sub warn-text', text: f.problem }) : ''),
      h('td', null, h('div', { text: f.user }), h('div', { class: 'cell-sub', text: f.site_domain ? `Site ${f.site_domain}` : 'No site: admins only' })),
      h('td', { class: 'actions' }, adopt));
  })));
}
