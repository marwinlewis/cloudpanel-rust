'use strict';
// Pieces shared by the Object Storage page (admins) and a site's Buckets tab.
import {
  api, copyButton, fmtBytes, formDialog, h, icon, kv, openDialog, toast, VALIDATORS,
} from '../core.js';

VALIDATORS.bucketName = (v) => {
  if (!/^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$/.test(v)) return '3-63 lowercase letters, digits, - and ., starting and ending with a letter or digit';
  if (/\.\.|\.-|-\./.test(v) || /^\d+\.\d+\.\d+\.\d+$/.test(v)) return 'No "..", ".-" or "-.", and not an IP address';
  return '';
};
VALIDATORS.keyName = (v) => (/^[A-Za-z0-9 ._-]{1,64}$/.test(v) ? '' : 'Up to 64 letters, digits, spaces, . _ -');
VALIDATORS.optionalCount = (v) => (!v || /^\d+$/.test(v) ? '' : 'A whole number, or empty for no limit');

/** read / write / owner as a short label. */
export function permLabel(p) {
  const parts = [p.read && 'read', p.write && 'write', p.owner && 'owner'].filter(Boolean);
  return parts.length ? parts.join(' + ') : 'none';
}

export function usage(b) {
  if (b.error) return h('span', { class: 'badge danger', title: b.error, text: 'Unavailable' });
  const size = fmtBytes(b.bytes || 0);
  const limit = b.quotas && b.quotas.maxSize ? ` of ${fmtBytes(b.quotas.maxSize)}` : '';
  return h('span', { class: 'muted small', text: `${b.objects ?? 0} object${b.objects === 1 ? '' : 's'} · ${size}${limit}` });
}

/** Where and how an app connects: the values to paste into an S3 SDK's settings. */
export function connectionKv(endpoint) {
  const row = (v) => h('span', { class: 'row' }, h('code', { class: 'mono truncate', text: v }), copyButton(v));
  return kv([
    ['Endpoint', endpoint.public ? row(endpoint.public) : h('span', { class: 'muted', text: 'No public hostname; reachable from this server only' })],
    ['On this server', row(endpoint.local)],
    ['Region', row(endpoint.region)],
    ['Addressing', 'Path-style (forcePathStyle: true)'],
  ]);
}

/** The new key's secret, shown once. */
export function keyCreatedDialog(k, endpoint) {
  const row = (label, v) => h('div', { class: 'field' }, h('label', { text: label }), h('div', { class: 'row' }, h('code', { class: 'mono secret', text: v }), copyButton(v)));
  const env = [
    `S3_ENDPOINT=${endpoint.public || endpoint.local}`,
    `S3_REGION=${endpoint.region}`,
    `S3_ACCESS_KEY_ID=${k.access_key_id}`,
    `S3_SECRET_ACCESS_KEY=${k.secret_access_key}`,
    'S3_FORCE_PATH_STYLE=true',
  ].join('\n');
  const ok = h('button', { class: 'btn primary', type: 'button', text: 'Done' });
  const d = openDialog({
    title: `Access key ${k.name}`,
    description: 'Copy the secret now. It is not stored by the panel and cannot be shown again.',
    body: h('div', { class: 'form' },
      row('Access key ID', k.access_key_id),
      row('Secret access key', k.secret_access_key),
      h('div', { class: 'row between' }, h('span', { class: 'small muted', text: 'As environment variables' }), copyButton(env)),
      h('pre', { class: 'logs mono small', text: env }),
      h('p', { class: 'hint', text: 'The key can\'t do anything yet: give it access to a bucket next.' })),
    footer: [ok],
  });
  ok.addEventListener('click', d.close);
}

/**
 * Give a key access to a bucket. `base` is `/storage` or `/sites/:id/storage`; `owner` offers owner
 * rights (admins only).
 */
export function grantDialog({ base, bucket, keys, owner, done }) {
  if (!keys.length) { toast('Create an access key first', 'error'); return; }
  const current = (id) => (bucket.grants || []).find((g) => g.key_id === id);
  const select = h('select', { class: 'input', name: 'key' }, keys.map((k) => h('option', { value: String(k.id), text: `${k.name} (${k.access_key_id})` })));
  const boxes = ['read', 'write', ...(owner ? ['owner'] : [])].map((p) => h('label', { class: 'check' },
    h('input', { type: 'checkbox', name: p, checked: p !== 'owner' }),
    { read: 'Read (list and download objects)', write: 'Write (upload and delete objects)', owner: 'Owner (bucket settings such as CORS and website access)' }[p]));
  const sync = () => {
    const g = current(+select.value);
    if (!g) return;
    for (const b of boxes) { const i = b.querySelector('input'); i.checked = !!g.permissions[i.name]; }
  };
  select.addEventListener('change', sync);
  sync();
  formDialog({
    title: `Access to ${bucket.name}`,
    description: 'Untick everything to take the key\'s access away.',
    submitText: 'Save access',
    content: [h('div', { class: 'field' }, h('label', { text: 'Access key' }), select), ...boxes],
    async onSubmit(f) {
      const body = { read: !!f.read, write: !!f.write, owner: !!f.owner };
      await api(`${base}/buckets/${bucket.id}/keys/${f.key}`, { method: 'PUT', body });
      toast(body.read || body.write || body.owner ? 'Access saved' : 'Access removed');
      done();
    },
  });
}

export function revokeButton({ base, bucket, grant, done }) {
  const b = h('button', { class: 'icon-btn', type: 'button', title: `Remove ${grant.name}'s access`, 'aria-label': `Remove ${grant.name}'s access` }, icon('x'));
  b.addEventListener('click', async () => {
    try {
      await api(`${base}/buckets/${bucket.id}/keys/${grant.key_id}`, { method: 'DELETE' });
      toast('Access removed');
      done();
    } catch (e) { toast(e.message, 'error'); }
  });
  return b;
}

/** A bucket's grants as small chips with a remove button each. */
export function grantList({ base, bucket, done }) {
  const grants = bucket.grants || [];
  const chips = grants.map((g) => h('span', { class: 'row small' },
    h('span', { class: 'badge', title: g.access_key_id, text: `${g.name}: ${permLabel(g.permissions)}` }),
    revokeButton({ base, bucket, grant: g, done })));
  if (bucket.other_grants) chips.push(h('span', { class: 'muted small', text: `+${bucket.other_grants} managed by an administrator` }));
  return chips.length ? h('div', { class: 'stack' }, ...chips) : h('span', { class: 'muted small', text: 'No keys' });
}
