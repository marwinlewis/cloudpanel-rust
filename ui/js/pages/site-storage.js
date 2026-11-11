'use strict';
// A site's buckets and access keys in Garage object storage.
import {
  api, card, confirmDialog, emptyState, errorState, field, formDialog, h, icon, isAdmin, moreButton, skeletonRows, table,
  toast,
} from '../core.js';
import { connectionKv, grantDialog, grantList, keyCreatedDialog, usage } from './storage-common.js';
import { SITE_TABS } from './site-tabs.js';

function renderSiteStorage(el, { site }) {
  const base = `/sites/${site.id}/storage`;
  const holder = h('div', null, card({ flush: true, body: table(['Bucket', 'Usage', 'Access', ''], skeletonRows(4, 2)) }));
  el.append(holder);

  async function load() {
    let d;
    try { d = await api(base); } catch (e) {
      if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) }));
      return;
    }
    if (!d.installed || !d.running) {
      holder.replaceChildren(card({ body: emptyState({
        iconName: 'layers',
        title: d.installed ? 'Object storage is not running' : 'Object storage is not installed',
        text: isAdmin() ? 'Set it up on the Object Storage page.' : 'Ask an administrator to set up object storage on this server.',
      }) }));
      return;
    }
    const newBucket = h('button', { class: 'btn primary sm', onclick: () => bucketDialog(load) }, icon('plus'), 'New bucket');
    const newKey = h('button', { class: 'btn sm', onclick: () => keyDialog(d, load) }, icon('plus'), 'New access key');

    const buckets = d.buckets.length
      ? card({ title: 'Buckets', actions: newBucket, flush: true, body: table(['Bucket', 'Usage', 'Access', ''], d.buckets.map((b) => h('tr', null,
        h('td', { class: 'strong mono', text: b.name }),
        h('td', null, usage(b)),
        h('td', null, grantList({ base, bucket: b, done: load })),
        h('td', { class: 'actions' }, moreButton([
          { icon: 'key', label: 'Give a key access…', action: () => grantDialog({ base, bucket: b, keys: d.keys, owner: false, done: load }) },
          '-',
          { icon: 'trash', label: 'Delete', danger: true, action: () => removeBucket(b) },
        ]))))) })
      : card({ body: emptyState({ iconName: 'archive', title: 'No buckets yet', text: 'S3-compatible storage for this site\'s uploads and media.', action: newBucket }) });

    const keys = card({
      title: 'Access keys', actions: newKey, flush: d.keys.length > 0,
      body: d.keys.length
        ? table(['Name', 'Access key ID', ''], d.keys.map((k) => h('tr', null,
          h('td', { class: 'strong', text: k.name }),
          h('td', { class: 'mono small', text: k.access_key_id }),
          h('td', { class: 'actions' }, moreButton([{ icon: 'trash', label: 'Delete', danger: true, action: () => removeKey(k) }])))))
        : h('p', { class: 'muted', text: 'The app signs in with an access key. Give the key access to a bucket after creating it.' }),
    });
    const notice = d.error && h('div', { class: 'alert error' }, icon('alert'), h('div', { text: d.error }));
    holder.replaceChildren(h('div', { class: 'grid' }, notice, buckets, h('div', { class: 'grid two' }, keys, card({ title: 'Connecting the app', body: connectionKv(d.endpoint) }))));
  }

  function bucketDialog(done) {
    formDialog({
      title: 'New bucket',
      description: 'Bucket names are shared by every site on this server and can\'t be changed later.',
      submitText: 'Create bucket',
      content: [field({ label: 'Name', name: 'name', placeholder: `e.g. ${site.domain.split('.')[0]}-media`, validate: 'bucketName', attrs: { maxlength: 63, autocomplete: 'off', spellcheck: 'false' } })],
      async onSubmit(f) {
        const b = await api(`${base}/buckets`, { method: 'POST', body: f });
        toast(`Bucket ${b.name} created`);
        done();
      },
    });
  }

  function keyDialog(d, done) {
    formDialog({
      title: 'New access key',
      submitText: 'Create key',
      content: [field({ label: 'Name', name: 'name', placeholder: 'e.g. app', validate: 'keyName', attrs: { maxlength: 64 } })],
      async onSubmit(f, dlg) {
        const k = await api(`${base}/keys`, { method: 'POST', body: f });
        dlg.close();
        done();
        keyCreatedDialog(k, d.endpoint);
      },
    });
  }

  async function removeBucket(b) {
    if (!(await confirmDialog({ title: `Delete bucket ${b.name}?`, message: 'Only an empty bucket can be deleted.', confirmText: 'Delete', danger: true }))) return;
    try { await api(`${base}/buckets/${b.id}`, { method: 'DELETE' }); toast(`${b.name} deleted`); load(); } catch (e) { toast(e.message, 'error'); }
  }

  async function removeKey(k) {
    if (!(await confirmDialog({ title: `Delete key ${k.name}?`, message: `Apps using ${k.access_key_id} lose access at once. This cannot be undone.`, confirmText: 'Delete', danger: true }))) return;
    try { await api(`${base}/keys/${k.id}`, { method: 'DELETE' }); toast(`${k.name} deleted`); load(); } catch (e) { toast(e.message, 'error'); }
  }

  load();
}

SITE_TABS.push({ key: 'storage', label: 'Buckets', when: () => true, render: renderSiteStorage });
