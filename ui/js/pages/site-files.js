'use strict';
import {
  api, card, confirmDialog, download, errorState, field, fmtBytes, formDialog, h, icon, moreButton, openDialog,
  skeletonRows, table, toast, upload, withBusy,
} from '../core.js';
import { SITE_TABS } from './site-tabs.js';

const ARCHIVE_RE = /\.(zip|tar|tgz|tar\.gz|tar\.bz2|tar\.xz)$/i;
const join = (dir, name) => (dir ? `${dir}/${name}` : name);
const fmtTime = (s) => (s ? new Date(s * 1000).toLocaleString() : '');

function renderFiles(el, { site }) {
  // Start in the site's htdocs when it exists.
  let cwd = `htdocs/${site.domain}`;
  const crumbs = h('div', { class: 'crumbs grow' });
  const tbody = h('tbody', null, skeletonRows(5, 4));
  const holder = h('div');
  const fileInput = h('input', { type: 'file', multiple: true, hidden: true });
  const progress = h('div', { class: 'progress', hidden: true }, h('span'));

  const btnUpload = h('button', { class: 'btn' }, icon('upload'), 'Upload');
  btnUpload.addEventListener('click', () => fileInput.click());
  const btnFolder = h('button', { class: 'btn' }, icon('folder'), 'New folder');
  btnFolder.addEventListener('click', () => nameDialog('New folder', 'Create', '', (n) => op('mkdir', join(cwd, n)).then(() => toast('Folder created'))));
  const btnFile = h('button', { class: 'btn' }, icon('file'), 'New file');
  btnFile.addEventListener('click', () => nameDialog('New file', 'Create', '', async (n) => { await op('touch', join(cwd, n)); edit(join(cwd, n)); }));
  const btnRefresh = h('button', { class: 'icon-btn', title: 'Refresh', 'aria-label': 'Refresh' }, icon('refresh'));
  btnRefresh.addEventListener('click', () => withBusy(btnRefresh, load));

  fileInput.addEventListener('change', async () => {
    const files = [...fileInput.files];
    fileInput.value = '';
    for (const f of files) await sendFile(f);
    load();
  });

  async function sendFile(f, overwrite = false) {
    const fd = new FormData();
    fd.append('path', cwd);
    fd.append('overwrite', String(overwrite));
    fd.append('file', f, f.name);
    progress.hidden = false;
    try {
      await upload(`/sites/${site.id}/files/upload`, fd, (p) => { progress.firstChild.style.width = `${Math.round(p * 100)}%`; });
      toast(`Uploaded ${f.name}`);
    } catch (e) {
      if (!overwrite && /already exists/.test(e.message) && (await confirmDialog({ title: `Replace ${f.name}?`, message: 'A file with this name already exists in this folder.', confirmText: 'Replace' }))) {
        await sendFile(f, true);
      } else toast(e.message, 'error');
    } finally {
      progress.hidden = true;
      progress.firstChild.style.width = '0';
    }
  }

  // Drag and drop upload.
  el.addEventListener('dragover', (e) => { e.preventDefault(); });
  el.addEventListener('drop', async (e) => {
    e.preventDefault();
    const files = [...(e.dataTransfer?.files || [])];
    for (const f of files) await sendFile(f);
    if (files.length) load();
  });

  const tableEl = h('div', { class: 'table-wrap' }, h('table', null,
    h('thead', null, h('tr', null, h('th', { text: 'Name' }), h('th', { class: 'num hide-sm', text: 'Size' }), h('th', { class: 'hide-sm', text: 'Mode' }), h('th', { class: 'hide-sm', text: 'Modified' }), h('th'))),
    tbody));
  holder.append(tableEl);
  el.append(card({
    flush: true,
    body: h('div', null,
      h('div', { class: 'card-head' }, crumbs, h('div', { class: 'row wrap' }, btnUpload, btnFolder, btnFile, btnRefresh)),
      progress, holder, fileInput),
  }));

  async function op(name, path, extra = {}) {
    await api(`/sites/${site.id}/files/op`, { method: 'POST', body: { op: name, path, ...extra } });
    await load();
  }

  function nameDialog(title, submitText, value, fn) {
    formDialog({
      title, submitText,
      content: [field({ label: 'Name', name: 'name', value, validate: 'required', attrs: { spellcheck: 'false', autocapitalize: 'off' } })],
      async onSubmit(d) {
        if (/[/\\]/.test(d.name)) throw new Error('Names cannot contain slashes');
        await fn(d.name);
      },
    });
  }

  function drawCrumbs() {
    const parts = cwd ? cwd.split('/') : [];
    const items = [h('button', { type: 'button', onclick: () => go('') }, icon('folder'), '~')];
    parts.forEach((p, i) => {
      items.push(h('span', { class: 'sep', text: '/' }));
      items.push(h('button', { type: 'button', text: p, onclick: () => go(parts.slice(0, i + 1).join('/')) }));
    });
    crumbs.replaceChildren(...items);
  }

  function go(dir) { cwd = dir; load(); }

  async function edit(path) {
    let r;
    try { r = await api(`/sites/${site.id}/files/content?path=${encodeURIComponent(path)}`); } catch (e) { toast(e.message, 'error'); return; }
    const ta = h('textarea', { class: 'input mono editor', spellcheck: 'false', 'aria-label': `Edit ${path}` });
    ta.value = r.content;
    ta.addEventListener('keydown', (e) => {
      if (e.key === 'Tab') { e.preventDefault(); const s = ta.selectionStart; ta.setRangeText('    ', s, ta.selectionEnd, 'end'); }
      if ((e.ctrlKey || e.metaKey) && e.key === 's') { e.preventDefault(); save.click(); }
    });
    const save = h('button', { class: 'btn primary', type: 'button', text: 'Save' });
    const close = h('button', { class: 'btn', type: 'button', text: 'Close' });
    const d = openDialog({ title: path.split('/').pop(), description: path, wide: true, body: ta, footer: [close, save] });
    close.addEventListener('click', d.close);
    save.addEventListener('click', () => withBusy(save, async () => {
      await api(`/sites/${site.id}/files/content`, { method: 'PUT', body: { path, content: ta.value } });
      // This file is the one the Application tab edits; apps read it when they start.
      const workdir = site.app_workdir || site.app_workdir_default;
      const isAppEnv = workdir && `${site.home_dir}/${path}` === `${workdir}/.env`;
      toast(isAppEnv ? 'Saved. Restart the app to apply these variables.' : 'Saved');
    }));
    setTimeout(() => ta.focus(), 30);
  }

  function row(e) {
    const path = join(cwd, e.name);
    const isDir = e.kind === 'dir';
    const nameCell = h('button', { class: 'btn ghost sm flush-left', type: 'button' },
      icon(isDir ? 'folder' : e.kind === 'symlink' ? 'link' : 'file'), e.name);
    nameCell.addEventListener('click', () => (isDir ? go(path) : e.kind === 'file' ? edit(path) : null));
    const items = [];
    if (e.kind === 'file') {
      items.push({ icon: 'edit', label: 'Edit', action: () => edit(path) });
      items.push({ icon: 'download', label: 'Download', action: () => download(`/sites/${site.id}/files/download?path=${encodeURIComponent(path)}`) });
      if (ARCHIVE_RE.test(e.name)) items.push({ icon: 'archive', label: 'Extract here', action: () => op('extract', path).then(() => toast('Extracted')).catch((x) => toast(x.message, 'error')) });
    }
    items.push({ icon: 'archive', label: 'Compress', action: () => nameDialog('Compress to .tar.gz', 'Compress', `${e.name}.tar.gz`, (n) => op('compress', cwd, { names: [e.name], name: n }).then(() => toast('Archive created'))) });
    items.push({ icon: 'edit', label: 'Rename / move', action: () => nameDialog('Rename', 'Rename', e.name, (n) => op('rename', path, { to: n.includes('/') ? n : join(cwd, n) }).then(() => toast('Renamed'))) });
    items.push({ icon: 'lock', label: 'Permissions', action: () => formDialog({
      title: `Permissions · ${e.name}`, submitText: 'Apply',
      content: [field({ label: 'Mode (octal)', name: 'mode', value: e.mode, validate: 'required', hint: 'e.g. 644 for files, 755 for folders' })],
      async onSubmit(d) { await op('chmod', path, { mode: d.mode }); toast('Permissions updated'); },
    }) });
    items.push('-', { icon: 'trash', label: 'Delete', danger: true, action: async () => {
      if (!(await confirmDialog({ title: `Delete ${e.name}?`, message: isDir ? 'The folder and everything in it will be deleted permanently.' : 'The file will be deleted permanently.', confirmText: 'Delete', danger: true }))) return;
      try { await op('delete', path); toast('Deleted'); } catch (x) { toast(x.message, 'error'); }
    } });
    return h('tr', null,
      h('td', null, nameCell, e.target && h('span', { class: 'small faint mono', text: ` → ${e.target}` })),
      h('td', { class: 'num hide-sm muted', text: isDir ? '—' : fmtBytes(e.size) }),
      h('td', { class: 'hide-sm mono muted', text: e.mode }),
      h('td', { class: 'hide-sm muted nowrap', text: fmtTime(e.modified) }),
      h('td', { class: 'actions' }, moreButton(items)));
  }

  async function load() {
    drawCrumbs();
    try {
      const r = await api(`/sites/${site.id}/files?path=${encodeURIComponent(cwd)}`);
      const rows = r.entries.map(row);
      if (cwd) {
        const up = h('button', { class: 'btn ghost sm flush-left', type: 'button' }, icon('back'), '..');
        up.addEventListener('click', () => go(cwd.split('/').slice(0, -1).join('/')));
        rows.unshift(h('tr', null, h('td', { colspan: 5 }, up)));
      }
      if (!r.entries.length) rows.push(h('tr', null, h('td', { colspan: 5, class: 'muted', text: 'This folder is empty. Drop files here to upload.' })));
      tbody.replaceChildren(...rows);
      holder.replaceChildren(tableEl);
    } catch (e) {
      if (e.status === 401) return;
      if (cwd && /No such file/.test(e.message)) { go(''); return; }
      holder.replaceChildren(errorState(e.message, load));
    }
  }
  load();
}

SITE_TABS.push({ key: 'files', label: 'Files', when: (s) => !!s.home_dir, render: renderFiles });

export { table };
