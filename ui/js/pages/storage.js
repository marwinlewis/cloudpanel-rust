'use strict';
// Object Storage: Garage, an S3-compatible store on this server. Administrators only.
import {
  api, card, confirmDialog, emptyState, errorState, field, fmtBytes, fmtDate, formDialog, h, icon, kv, moreButton,
  runJob, selectField, setActions, setSub, skeletonRows, table, toast, withBusy,
} from '../core.js';
import { connectionKv, grantDialog, grantList, keyCreatedDialog, usage } from './storage-common.js';

const BASE = '/storage';

function siteOptions(sites) {
  return [['', 'No site (administrators only)'], ...sites.map((s) => [String(s.id), s.domain])];
}

export function renderStorage(view) {
  const notice = h('div');
  const top = h('div', null, card({ title: 'Object storage', body: skeletonRows(2) }));
  const buckets = h('div');
  const keys = h('div');
  view.replaceChildren(h('div', { class: 'grid' }, notice, top, buckets, keys));
  let d = null;

  async function load() {
    try {
      d = await api(BASE);
    } catch (e) {
      if (e.status !== 401) top.replaceChildren(card({ body: errorState(e.message, load) }));
      return;
    }
    render();
  }

  function installButton(label) {
    const b = h('button', { class: 'btn primary sm', type: 'button' }, icon('download'), label);
    b.addEventListener('click', () => withBusy(b, async () => {
      const job = await runJob(`${BASE}/install`, label);
      if (job && job.status === 'succeeded') toast('Garage is installed and running');
      await load();
    }));
    return b;
  }

  function render() {
    setActions(d.running && h('button', { class: 'btn primary', onclick: () => bucketDialog(d, load) }, icon('plus'), 'New bucket'));
    setSub(d.running ? `${d.buckets.length} bucket${d.buckets.length === 1 ? '' : 's'} · Garage ${d.version || ''}` : '');

    const notes = [];
    if (d.installed && d.version && d.version !== d.latest_version) {
      notes.push(h('div', { class: 'alert info' }, icon('refresh'),
        h('div', { class: 'grow', text: `Garage ${d.latest_version} is available (running ${d.version}). Updating restarts it for a few seconds.` }),
        d.can_install && installButton(`Update to ${d.latest_version}`)));
    }
    if (d.error) notes.push(h('div', { class: 'alert error' }, icon('alert'), h('div', { text: d.error })));
    notice.replaceChildren(...notes);

    if (!d.installed) {
      top.replaceChildren(card({ body: emptyState({
        iconName: 'layers', title: 'Object storage is not installed',
        text: d.can_install
          ? 'Install Garage to give your apps S3-compatible buckets on this server. It is a small, single binary that listens on this server only until you give it a public hostname.'
          : 'Re-run the CloudPanel installer with --with-garage to install it.',
        action: d.can_install && installButton('Install Garage'),
      }) }));
      buckets.replaceChildren();
      keys.replaceChildren();
      return;
    }
    if (!d.running) {
      top.replaceChildren(card({ body: emptyState({
        iconName: 'alert', title: 'Garage is not running',
        text: 'Start it on the Services page, or see its logs there.',
      }) }));
      buckets.replaceChildren();
      keys.replaceChildren();
      return;
    }

    const st = d.statistics || {};
    const health = d.health && d.health.status === 'healthy'
      ? h('span', { class: 'badge ok', text: 'Healthy' })
      : h('span', { class: 'badge danger', text: d.health ? d.health.status : 'Unknown' });
    const endpointActions = d.hostname
      ? h('button', { class: 'btn sm', onclick: () => removeEndpoint(d.hostname) }, icon('x'), 'Remove hostname')
      : h('button', { class: 'btn sm', onclick: () => endpointDialog(load) }, icon('globe'), 'Add public hostname');
    top.replaceChildren(h('div', { class: 'grid two' },
      card({ title: 'Garage', body: kv([
        ['Status', health],
        ['Version', d.version || '—'],
        ['Stored', `${st.totalObjectCount ?? '—'} objects · ${st.totalObjectBytes != null ? fmtBytes(st.totalObjectBytes) : '—'}`],
        ['Free space', st.dataAvail != null ? fmtBytes(st.dataAvail) : '—'],
      ]) }),
      card({ title: 'Connecting apps', actions: endpointActions, body: connectionKv(d.endpoint) })));

    drawBuckets();
    drawKeys();
  }

  function drawBuckets() {
    if (!d.buckets.length) {
      buckets.replaceChildren(card({ body: emptyState({
        iconName: 'archive', title: 'No buckets yet', text: 'Create a bucket, then an access key for the app that uses it.',
        action: h('button', { class: 'btn primary', onclick: () => bucketDialog(d, load) }, icon('plus'), 'New bucket'),
      }) }));
      return;
    }
    buckets.replaceChildren(card({ title: 'Buckets', flush: true, body: table(
      ['Bucket', { label: 'Site', class: 'hide-sm' }, 'Usage', 'Access', ''],
      d.buckets.map((b) => h('tr', null,
        h('td', null, h('div', { class: 'cell-title mono', text: b.name }), h('div', { class: 'cell-sub', text: `Created ${fmtDate(b.created_at)}` })),
        h('td', { class: 'hide-sm muted', text: b.site_domain || '—' }),
        h('td', null, usage(b)),
        h('td', null, grantList({ base: BASE, bucket: b, done: load })),
        h('td', { class: 'actions' }, moreButton([
          { icon: 'key', label: 'Give a key access…', action: () => grantDialog({ base: BASE, bucket: b, keys: d.keys, owner: true, done: load }) },
          { icon: 'edit', label: 'Site and limits…', action: () => editBucketDialog(b, d, load) },
          '-',
          { icon: 'trash', label: 'Delete', danger: true, action: () => removeBucket(b) },
        ])))),
    ) }));
  }

  function drawKeys() {
    const add = h('button', { class: 'btn sm', onclick: () => keyDialog(d, load) }, icon('plus'), 'New access key');
    if (!d.keys.length) {
      keys.replaceChildren(card({ title: 'Access keys', actions: add, body: h('p', { class: 'muted', text: 'Apps sign in to the S3 API with an access key. Each key only reaches the buckets you give it.' }) }));
      return;
    }
    keys.replaceChildren(card({ title: 'Access keys', actions: add, flush: true, body: table(
      ['Name', 'Access key ID', { label: 'Site', class: 'hide-sm' }, ''],
      d.keys.map((k) => h('tr', null,
        h('td', { class: 'strong', text: k.name }),
        h('td', { class: 'mono small', text: k.access_key_id }),
        h('td', { class: 'hide-sm muted', text: k.site_domain || '—' }),
        h('td', { class: 'actions' }, moreButton([
          { icon: 'edit', label: 'Site…', action: () => keySiteDialog(k, d, load) },
          '-',
          { icon: 'trash', label: 'Delete', danger: true, action: () => removeKey(k) },
        ])))),
    ) }));
  }

  async function removeBucket(b) {
    if (!(await confirmDialog({ title: `Delete bucket ${b.name}?`, message: 'Only an empty bucket can be deleted. Keys keep working for other buckets.', confirmText: 'Delete', danger: true }))) return;
    try { await api(`${BASE}/buckets/${b.id}`, { method: 'DELETE' }); toast(`${b.name} deleted`); load(); } catch (e) { toast(e.message, 'error'); }
  }

  async function removeKey(k) {
    if (!(await confirmDialog({ title: `Delete key ${k.name}?`, message: `Apps using ${k.access_key_id} lose access to every bucket at once. This cannot be undone.`, confirmText: 'Delete', danger: true }))) return;
    try { await api(`${BASE}/keys/${k.id}`, { method: 'DELETE' }); toast(`${k.name} deleted`); load(); } catch (e) { toast(e.message, 'error'); }
  }

  async function removeEndpoint(host) {
    if (!(await confirmDialog({ title: `Stop serving ${host}?`, message: 'Apps elsewhere lose access. Apps on this server keep working through 127.0.0.1:3900.', confirmText: 'Remove', danger: true }))) return;
    try { await api(`${BASE}/endpoint`, { method: 'DELETE' }); toast('Hostname removed'); load(); } catch (e) { toast(e.message, 'error'); }
  }

  load();
}

function limitFields(b) {
  const q = (b && b.quotas) || {};
  return h('div', { class: 'form-grid' },
    field({ label: 'Size limit (MB)', name: 'max_size_mb', value: q.maxSize ? String(Math.round(q.maxSize / 1048576)) : '', validate: 'optionalCount', placeholder: 'No limit', attrs: { inputmode: 'numeric' } }),
    field({ label: 'Object limit', name: 'max_objects', value: q.maxObjects ? String(q.maxObjects) : '', validate: 'optionalCount', placeholder: 'No limit', attrs: { inputmode: 'numeric' } }));
}

const num = (v) => (v ? Number(v) : null);

function bucketDialog(d, done) {
  formDialog({
    title: 'New bucket',
    description: 'Bucket names are shared by every app on this server and can\'t be changed later.',
    submitText: 'Create bucket',
    content: [
      field({ label: 'Name', name: 'name', placeholder: 'e.g. shop-media', validate: 'bucketName', attrs: { maxlength: 63, autocomplete: 'off', spellcheck: 'false' } }),
      selectField({ label: 'Site', name: 'site_id', value: '', options: siteOptions(d.sites) }),
      h('p', { class: 'hint', text: 'A site\'s managers can see its buckets and give its keys access to them.' }),
      limitFields(null),
    ],
    async onSubmit(f) {
      const b = await api(`${BASE}/buckets`, { method: 'POST', body: { name: f.name, site_id: num(f.site_id), max_size_mb: num(f.max_size_mb), max_objects: num(f.max_objects) } });
      toast(`Bucket ${b.name} created`);
      done();
    },
  });
}

function editBucketDialog(b, d, done) {
  formDialog({
    title: `Bucket ${b.name}`,
    submitText: 'Save',
    content: [
      selectField({ label: 'Site', name: 'site_id', value: b.site_id ? String(b.site_id) : '', options: siteOptions(d.sites) }),
      limitFields(b),
      h('p', { class: 'hint', text: 'Writes that would go over a limit are refused; what is stored already stays.' }),
    ],
    async onSubmit(f) {
      await api(`${BASE}/buckets/${b.id}`, { method: 'PUT', body: { site_id: num(f.site_id), max_size_mb: num(f.max_size_mb), max_objects: num(f.max_objects) } });
      toast('Bucket saved');
      done();
    },
  });
}

function keyDialog(d, done) {
  formDialog({
    title: 'New access key',
    description: 'Create one key per app, so you can take one app\'s access away without touching the others.',
    submitText: 'Create key',
    content: [
      field({ label: 'Name', name: 'name', placeholder: 'e.g. shop-backend', validate: 'keyName', attrs: { maxlength: 64 } }),
      selectField({ label: 'Site', name: 'site_id', value: '', options: siteOptions(d.sites) }),
      h('p', { class: 'hint', text: 'A site\'s key can only be given access to that site\'s buckets.' }),
    ],
    async onSubmit(f, dlg) {
      const k = await api(`${BASE}/keys`, { method: 'POST', body: { name: f.name, site_id: num(f.site_id) } });
      dlg.close();
      done();
      keyCreatedDialog(k, d.endpoint);
    },
  });
}

function keySiteDialog(k, d, done) {
  formDialog({
    title: `Key ${k.name}`,
    submitText: 'Save',
    content: [selectField({ label: 'Site', name: 'site_id', value: k.site_id ? String(k.site_id) : '', options: siteOptions(d.sites) })],
    async onSubmit(f) {
      await api(`${BASE}/keys/${k.id}`, { method: 'PUT', body: { site_id: num(f.site_id) } });
      toast('Key saved');
      done();
    },
  });
}

function endpointDialog(done) {
  formDialog({
    title: 'Public hostname for object storage',
    description: 'nginx serves the S3 API on this name over HTTPS with a Let\'s Encrypt certificate. Point the name\'s DNS at this server first.',
    submitText: 'Set up hostname',
    content: [
      field({ label: 'Hostname', name: 'hostname', placeholder: 's3.example.com', validate: 'domain' }),
      field({ label: 'Email for Let\'s Encrypt', name: 'email', type: 'email', validate: 'email' }),
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'skip_dns_check' }), 'Skip the DNS check (this server is behind NAT)'),
    ],
    async onSubmit(f) {
      const r = await api(`${BASE}/endpoint`, { method: 'PUT', body: f });
      toast(r.message);
      done();
    },
  });
}
