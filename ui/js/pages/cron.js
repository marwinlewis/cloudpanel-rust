'use strict';
import {
  api, card, confirmDialog, emptyState, errorState, field, fmtAgo, fmtDate, formDialog, h, icon, isAdmin, moreButton,
  openDialog, selectField, setActions, setSub, skeletonRows, table, toast,
} from '../core.js';

const DOW = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday'];
export function describeCron(s) {
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

function outputDrawer(title, text, code) {
  openDialog({ title, description: code == null ? '' : `Exit code ${code}`, drawer: true, body: h('pre', { class: 'logs mono', text: text || '(no output)' }) });
}

async function historyDrawer(j) {
  const body = h('div', { class: 'form' }, h('div', { class: 'skeleton' }));
  openDialog({ title: j.name || `Job #${j.id}`, description: 'Last 20 runs', drawer: true, body });
  try {
    const runs = await api(`/cron/jobs/${j.id}/runs`);
    body.replaceChildren(...(runs.length ? runs.map((r) => h('details', { class: 'run' },
      h('summary', null, h('span', { class: `badge ${r.exit_code === 0 ? 'ok' : 'danger'}`, text: r.exit_code === 0 ? 'OK' : `exit ${r.exit_code}` }), ` ${fmtDate(r.started_at)} · ${(r.duration_ms / 1000).toFixed(1)}s`),
      h('pre', { class: 'logs mono short', text: r.output || '(no output)' }))) : [h('p', { class: 'muted', text: 'This job has not run yet.' })]));
  } catch (e) { body.replaceChildren(errorState(e.message)); }
}

export function renderCron(view) {
  const holder = h('div', null, card({ flush: true, body: table(['Schedule', 'Command', 'User', ''], skeletonRows(4)) }));
  view.replaceChildren(holder);
  let sites = [];
  setActions(h('button', { class: 'btn primary', onclick: () => cronDialog(sites, null, load) }, icon('plus'), 'Add job'));

  async function load() {
    try {
      const [jobs, s] = await Promise.all([api('/cron/jobs'), api('/sites')]);
      sites = s;
      setSub(`${jobs.length} job${jobs.length === 1 ? '' : 's'} · /etc/cron.d/cloudpanel`);
      if (!jobs.length) {
        holder.replaceChildren(card({ body: emptyState({
          iconName: 'clock', title: 'No scheduled jobs', text: 'Run backups, queue workers or maintenance scripts on a schedule.',
          action: h('button', { class: 'btn primary', onclick: () => cronDialog(sites, null, load) }, icon('plus'), 'Add job'),
        }) }));
        return;
      }
      holder.replaceChildren(card({ flush: true, body: table(['Schedule', 'Command', { label: 'User', class: 'hide-sm' }, 'Last run', ''], jobs.map((j) => {
        const site = sites.find((x) => x.id === j.site_id);
        const runNow = async () => {
          toast('Running…');
          try { const r = await api(`/cron/jobs/${j.id}/run`, { method: 'POST' }); outputDrawer(j.name || `Job #${j.id}`, r.output, r.exit_code); load(); } catch (e) { toast(e.message, 'error'); }
        };
        const toggle = async () => {
          try { await api(`/cron/jobs/${j.id}`, { method: 'PUT', body: { ...j, is_active: !j.is_active } }); toast(j.is_active ? 'Job paused' : 'Job enabled'); load(); } catch (e) { toast(e.message, 'error'); }
        };
        const remove = async () => {
          if (!(await confirmDialog({ title: 'Delete this cron job?', message: j.command, confirmText: 'Delete', danger: true }))) return;
          try { await api(`/cron/jobs/${j.id}`, { method: 'DELETE' }); toast('Cron job deleted'); load(); } catch (e) { toast(e.message, 'error'); }
        };
        const last = j.last_run;
        return h('tr', null,
          h('td', null, h('div', { class: 'mono', text: j.schedule }), h('div', { class: 'cell-sub', text: j.is_active ? describeCron(j.schedule) : 'Paused' })),
          h('td', null, j.name && h('div', { class: 'cell-title', text: j.name }), h('code', { class: 'truncate', title: j.command, text: j.command }), site && h('div', { class: 'cell-sub', text: site.domain })),
          h('td', { class: 'hide-sm muted mono', text: j.user }),
          h('td', null, last ? h('span', { class: `badge ${last.exit_code === 0 ? 'ok' : 'danger'}`, title: fmtDate(last.at), text: `${last.exit_code === 0 ? 'OK' : `exit ${last.exit_code}`} · ${fmtAgo(last.at)}` }) : h('span', { class: 'faint', text: 'Never' })),
          h('td', { class: 'actions' }, moreButton([
            { icon: 'play', label: 'Run now', action: runNow },
            { icon: 'activity', label: 'History', action: () => historyDrawer(j) },
            { icon: 'edit', label: 'Edit', action: () => cronDialog(sites, j, load) },
            { icon: j.is_active ? 'stop' : 'play', label: j.is_active ? 'Pause' : 'Enable', action: toggle },
            '-',
            { icon: 'trash', label: 'Delete', danger: true, action: remove },
          ])));
      })) }));
    } catch (e) {
      if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) }));
    }
  }
  load();
}

function cronDialog(sites, job, done) {
  const presets = [['*/5 * * * *', 'Every 5 minutes'], ['0 * * * *', 'Every hour'], ['0 3 * * *', 'Every day at 03:00'], ['0 3 * * 0', 'Every Sunday at 03:00'], ['0 3 1 * *', 'Monthly on the 1st'], ['* * * * *', 'Every minute'], ['', 'Custom…']];
  const initial = job ? job.schedule : '0 3 * * *';
  const sched = field({ label: 'Schedule', name: 'schedule', value: initial, validate: 'cron', hint: 'minute hour day-of-month month day-of-week', attrs: { spellcheck: 'false', class: 'input mono' } });
  const input = sched.querySelector('input');
  const preview = h('div', { class: 'hint', text: describeCron(initial) });
  sched.querySelector('.hint').replaceWith(preview);
  const updatePreview = () => { preview.textContent = describeCron(input.value.trim()) || 'minute hour day-of-month month day-of-week'; };
  input.addEventListener('input', updatePreview);
  const preset = selectField({ label: 'Preset', name: '_preset', value: presets.some(([v]) => v === initial) ? initial : '', options: presets });
  preset.querySelector('select').addEventListener('change', (e) => { if (e.target.value) { input.value = e.target.value; updatePreview(); } else input.focus(); });

  const siteOpts = [...(isAdmin() ? [['', 'None (server-wide)']] : []), ...sites.map((s) => [String(s.id), s.domain])];
  const siteSel = selectField({ label: 'Site', name: 'site_id', value: job && job.site_id ? String(job.site_id) : (isAdmin() ? '' : siteOpts[0] && siteOpts[0][0]), options: siteOpts });
  const userField = field({ label: 'Run as user', name: 'user', value: job ? job.user : 'root', validate: 'required', hint: 'Site jobs run as the site user by default.', attrs: { spellcheck: 'false', autocapitalize: 'off' } });
  const syncUser = () => {
    const sid = siteSel.querySelector('select').value;
    const site = sites.find((s) => String(s.id) === sid);
    userField.hidden = !isAdmin();
    if (site && !job) userField.querySelector('input').value = site.system_user;
  };
  siteSel.querySelector('select').addEventListener('change', syncUser);
  syncUser();

  formDialog({
    title: job ? 'Edit cron job' : 'Add cron job',
    description: 'Jobs run from /etc/cron.d/cloudpanel. Output and exit codes of every run are recorded.',
    submitText: job ? 'Save' : 'Add job',
    content: [
      field({ label: 'Name (optional)', name: 'name', value: job ? job.name || '' : '', placeholder: 'Nightly cleanup', attrs: { maxlength: 80 } }),
      h('div', { class: 'form-grid' }, preset, sched),
      field({ label: 'Command', name: 'command', value: job ? job.command : '', placeholder: 'cd ~/htdocs/app && node scripts/cleanup.js', validate: 'required', attrs: { spellcheck: 'false', class: 'input mono', maxlength: 1000 } }),
      siteSel, userField,
      h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'is_active', checked: job ? job.is_active : true }), 'Enabled'),
    ],
    async onSubmit(d) {
      const body = { name: d.name || null, schedule: d.schedule, command: d.command, user: d.user || null, site_id: d.site_id ? Number(d.site_id) : null, is_active: !!d.is_active };
      if (job) await api(`/cron/jobs/${job.id}`, { method: 'PUT', body });
      else await api('/cron/jobs', { method: 'POST', body });
      toast(job ? 'Cron job saved' : 'Cron job added');
      done();
    },
  });
}
