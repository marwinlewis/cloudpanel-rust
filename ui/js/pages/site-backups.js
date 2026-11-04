'use strict';
import {
  api, card, confirmDialog, download, emptyState, errorState, fmtAgo, fmtBytes, fmtDate, h, icon, moreButton, runJob,
  selectField, skeletonRows, table, toast, typedConfirm, withBusy,
} from '../core.js';
import { SITE_TABS } from './site-tabs.js';

function renderBackups(el, { site }) {
  const holder = h('div', null, card({ flush: true, body: table(['Backup', 'Size', 'Status', ''], skeletonRows(4, 2)) }));
  const policyHolder = h('div');
  const now = h('button', { class: 'btn primary' }, icon('archive'), 'Back up now');
  now.addEventListener('click', async () => {
    try { await runJob(`/sites/${site.id}/backups`, `Backup · ${site.domain}`); } catch (e) { toast(e.message, 'error'); }
    load();
  });
  el.append(h('div', { class: 'grid two' }, policyHolder, card({
    title: 'What is backed up', body: h('ul', { class: 'muted small' },
      h('li', { text: `All files in ${site.home_dir} (except .cache and .npm)` }),
      h('li', { text: 'A dump of every database of this site' }),
      h('li', { text: 'Backups are stored in /var/backups/cloudpanel and optionally copied to S3-compatible storage.' })),
  })), h('div', { class: 'row end' }, now), holder);

  function drawPolicy(p, remoteConfigured) {
    const freq = selectField({ label: 'Schedule', name: 'frequency', value: p.frequency, options: [['off', 'Off'], ['daily', 'Daily'], ['weekly', 'Weekly (Sunday)']] });
    const hour = selectField({ label: 'Time (UTC)', name: 'hour', value: String(p.hour), options: Array.from({ length: 24 }, (_, i) => [String(i), `${String(i).padStart(2, '0')}:00`]) });
    const keep = selectField({ label: 'Keep', name: 'retention', value: String(p.retention), options: [1, 3, 7, 14, 30, 60, 90].map((n) => [String(n), `${n} backup${n > 1 ? 's' : ''}`]) });
    const remote = h('input', { type: 'checkbox', checked: p.remote_enabled, disabled: !remoteConfigured });
    const save = h('button', { class: 'btn primary', type: 'button', text: 'Save schedule' });
    save.addEventListener('click', () => withBusy(save, async () => {
      await api(`/sites/${site.id}/backups/policy`, { method: 'PUT', body: {
        frequency: freq.querySelector('select').value, hour: Number(hour.querySelector('select').value),
        retention: Number(keep.querySelector('select').value), remote_enabled: remote.checked,
      } });
      toast('Backup schedule saved');
    }));
    policyHolder.replaceChildren(card({
      title: 'Schedule', sub: p.last_run ? `Last scheduled run ${fmtAgo(p.last_run)}` : 'Automatic backups',
      body: h('div', { class: 'form' }, h('div', { class: 'form-grid' }, freq, hour, keep),
        h('label', { class: 'check' }, remote, remoteConfigured ? 'Also upload to remote storage' : 'Remote storage not configured (Settings → Backups)'),
        h('div', null, save)),
    }));
  }

  async function load() {
    try {
      const r = await api(`/sites/${site.id}/backups`);
      drawPolicy(r.policy, r.remote_configured);
      if (!r.backups.length) {
        holder.replaceChildren(card({ body: emptyState({ iconName: 'archive', title: 'No backups yet', text: 'Create one now or set a schedule.' }) }));
        return;
      }
      holder.replaceChildren(card({ flush: true, body: table(['Backup', { label: 'Size', class: 'num' }, 'Status', ''], r.backups.map((b) => {
        const items = [];
        if (b.status === 'ok') {
          items.push({ icon: 'download', label: 'Download', action: () => download(`/backups/${b.id}/download`) });
          items.push({ icon: 'refresh', label: 'Restore…', action: async () => {
            if (!(await typedConfirm({ title: `Restore ${site.domain}?`, message: `All files and databases of the site are replaced with the backup from ${fmtDate(b.created_at)}. Changes made since then are lost.`, word: site.domain, confirmText: 'Restore' }))) return;
            try { await runJob(`/backups/${b.id}/restore`, `Restore · ${site.domain}`); } catch (e) { toast(e.message, 'error'); }
          } });
          items.push('-');
        }
        items.push({ icon: 'trash', label: 'Delete', danger: true, action: async () => {
          if (!(await confirmDialog({ title: 'Delete this backup?', message: b.remote_key ? 'The local file and its remote copy are deleted.' : 'The backup file is deleted.', confirmText: 'Delete', danger: true }))) return;
          try { await api(`/backups/${b.id}`, { method: 'DELETE' }); toast('Backup deleted'); load(); } catch (e) { toast(e.message, 'error'); }
        } });
        const badge = b.status === 'ok' ? h('span', { class: 'badge ok', text: b.remote_key ? 'OK · remote' : 'OK' })
          : b.status === 'running' ? h('span', { class: 'badge warn', text: 'Running' }) : h('span', { class: 'badge danger', title: b.error || '', text: 'Failed' });
        return h('tr', null,
          h('td', null, h('div', { class: 'cell-title', text: fmtDate(b.created_at) }), h('div', { class: 'cell-sub mono truncate', text: b.error || b.file_name })),
          h('td', { class: 'num muted', text: b.size ? fmtBytes(b.size) : '—' }),
          h('td', null, badge),
          h('td', { class: 'actions' }, moreButton(items)));
      })) }));
    } catch (e) { if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) })); }
  }
  load();
}

SITE_TABS.push({ key: 'backups', label: 'Backups', when: (s) => !!s.home_dir, render: renderBackups });
