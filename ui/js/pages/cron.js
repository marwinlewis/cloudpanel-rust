'use strict';
import {
  $, ApiError, DOMAIN_RE, PROPS, SVG_NS, VALIDATORS, api, append, card, closeMenu, confirmDialog, effectiveTheme, emptyState, errorState, field, fmtAgo, fmtBytes, fmtDate, fmtPct, fmtRate, fmtUptime, formData, formDialog, h, hooks, icon, isAdmin, media, moreButton, openDialog, openMenu, openMenuEl, rtf, selectField, setActions, setHost, setSub, setTheme, skeletonRows, spinner, state, store, svgEl, syncThemeIcon, table, toast, validateForm, withBusy,
} from '../core.js';

// ---------- Cron ----------

const DOW = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
function describeCron(s) {
  const macros = { '@reboot': 'At startup', '@yearly': 'Once a year', '@annually': 'Once a year', '@monthly': 'Once a month', '@weekly': 'Once a week', '@daily': 'Every day at midnight', '@midnight': 'Every day at midnight', '@hourly': 'Every hour' };
  if (macros[s]) return macros[s];
  const f = s.split(/\s+/);
  if (f.length !== 5) return '';
  const [mi, hr, dom, mon, dow] = f;
  const num = (x) => /^\d+$/.test(x);
  const time = () => `${hr.padStart(2, '0')}:${mi.padStart(2, '0')}`;
  if (f.every((x) => x === '*')) return 'Every minute';
  if (/^\*\/\d+$/.test(mi) && hr === '*' && dom === '*' && mon === '*' && dow === '*') return `Every ${mi.slice(2)} minutes`;
  if (num(mi) && hr === '*' && dom === '*' && mon === '*' && dow === '*') return `Every hour at :${mi.padStart(2, '0')}`;
  if (num(mi) && /^\*\/\d+$/.test(hr) && dom === '*' && mon === '*' && dow === '*') return `Every ${hr.slice(2)} hours at :${mi.padStart(2, '0')}`;
  if (num(mi) && num(hr) && dom === '*' && mon === '*' && dow === '*') return `Every day at ${time()}`;
  if (num(mi) && num(hr) && dom === '*' && mon === '*' && num(dow)) return `Every ${DOW[+dow] || 'week'} at ${time()}`;
  if (num(mi) && num(hr) && dom === '*' && mon === '*' && dow === '1-5') return `Weekdays at ${time()}`;
  if (num(mi) && num(hr) && num(dom) && mon === '*' && dow === '*') return `Day ${dom} of every month at ${time()}`;
  return 'Custom schedule';
}

export function renderCron(view) {
  const holder = h('div', null, card({ flush: true, body: table(['Schedule', 'Command', 'User', ''], skeletonRows(4)) }));
  view.replaceChildren(holder);
  setActions(h('button', { class: 'btn primary', onclick: () => addCronDialog(load) }, icon('plus'), 'Add job'));

  async function load() {
    try {
      const jobs = await api('/cron/jobs');
      setSub(`${jobs.length} job${jobs.length === 1 ? '' : 's'} · /etc/cron.d/cloudpanel`);
      if (!jobs.length) {
        holder.replaceChildren(card({ body: emptyState({
          iconName: 'clock', title: 'No scheduled jobs', text: 'Run backups, queue workers or maintenance scripts on a schedule.',
          action: h('button', { class: 'btn primary', onclick: () => addCronDialog(load) }, icon('plus'), 'Add job'),
        }) }));
        return;
      }
      holder.replaceChildren(card({ flush: true, body: table(['Schedule', 'Command', { label: 'User', class: 'hide-sm' }, ''], jobs.map((j) => {
        const del = h('button', { class: 'icon-btn danger', title: 'Delete job', 'aria-label': 'Delete job' }, icon('trash'));
        del.addEventListener('click', async () => {
          if (!(await confirmDialog({ title: 'Delete this cron job?', message: j.command, confirmText: 'Delete', danger: true }))) return;
          await withBusy(del, async () => { await api(`/cron/jobs/${j.id}`, { method: 'DELETE' }); toast('Cron job deleted'); await load(); });
        });
        return h('tr', null,
          h('td', null, h('div', { class: 'mono', text: j.schedule }), h('div', { class: 'cell-sub', text: describeCron(j.schedule) })),
          h('td', null, h('code', { class: 'truncate', title: j.command, text: j.command })),
          h('td', { class: 'hide-sm muted mono', text: j.user }),
          h('td', { class: 'actions' }, del));
      })) }));
    } catch (e) {
      if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) }));
    }
  }
  load();
}

function addCronDialog(done) {
  const presets = [['*/5 * * * *', 'Every 5 minutes'], ['0 * * * *', 'Every hour'], ['0 3 * * *', 'Every day at 03:00'], ['0 3 * * 0', 'Every Sunday at 03:00'], ['0 3 1 * *', 'Monthly on the 1st'], ['* * * * *', 'Every minute'], ['', 'Custom…']];
  const sched = field({ label: 'Schedule', name: 'schedule', value: '0 3 * * *', validate: 'cron', hint: 'minute hour day-of-month month day-of-week', attrs: { spellcheck: 'false', class: 'input mono' } });
  const input = sched.querySelector('input');
  const preview = h('div', { class: 'hint', text: describeCron('0 3 * * *') });
  sched.querySelector('.hint').replaceWith(preview);
  const updatePreview = () => { preview.textContent = describeCron(input.value.trim()) || 'minute hour day-of-month month day-of-week'; };
  input.addEventListener('input', updatePreview);
  const preset = selectField({ label: 'Preset', name: '_preset', value: '0 3 * * *', options: presets });
  preset.querySelector('select').addEventListener('change', (e) => {
    if (e.target.value) { input.value = e.target.value; updatePreview(); } else input.focus();
  });

  formDialog({
    title: 'Add cron job',
    description: 'Jobs are written to /etc/cron.d/cloudpanel and run by the system cron daemon.',
    submitText: 'Add job',
    content: [
      h('div', { class: 'form-grid' }, preset, sched),
      field({ label: 'Command', name: 'command', placeholder: '/usr/bin/php /var/www/app/artisan schedule:run', validate: 'required', attrs: { spellcheck: 'false', class: 'input mono', maxlength: 1000 } }),
      field({ label: 'Run as user', name: 'user', value: 'root', validate: 'required', attrs: { spellcheck: 'false', autocapitalize: 'off' } }),
    ],
    async onSubmit(d) {
      await api('/cron/jobs', { method: 'POST', body: { schedule: d.schedule, command: d.command, user: d.user } });
      toast('Cron job added');
      done();
    },
  });
}
