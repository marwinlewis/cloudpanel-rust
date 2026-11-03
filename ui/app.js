'use strict';
// CloudPanel UI. Vanilla JS, no dependencies. All DOM is built with createElement /
// textContent; data from the server is never inserted as HTML.

(() => {
  const $ = (sel, root = document) => root.querySelector(sel);
  const SVG_NS = 'http://www.w3.org/2000/svg';
  const PROPS = new Set(['value', 'checked', 'disabled', 'hidden', 'selected', 'required', 'readOnly', 'multiple']);

  // ---------- DOM helpers ----------

  function h(tag, props, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'text') el.textContent = v;
      else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2).toLowerCase(), v);
      else if (PROPS.has(k)) el[k] = v;
      else el.setAttribute(k, v === true ? '' : String(v));
    }
    append(el, children);
    return el;
  }

  function append(el, children) {
    for (const c of children.flat(Infinity)) {
      if (c == null || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  function icon(name, cls = '') {
    const svg = document.createElementNS(SVG_NS, 'svg');
    svg.setAttribute('class', `icon ${cls}`.trim());
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS(SVG_NS, 'use');
    use.setAttribute('href', `#i-${name}`);
    svg.append(use);
    return svg;
  }

  function svgEl(tag, attrs = {}) {
    const el = document.createElementNS(SVG_NS, tag);
    for (const [k, v] of Object.entries(attrs)) el.setAttribute(k, v);
    return el;
  }

  const spinner = () => h('span', { class: 'spinner', 'aria-hidden': 'true' });

  // ---------- Formatting ----------

  function fmtBytes(n, digits = 1) {
    if (!Number.isFinite(n) || n <= 0) return '0 B';
    const u = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
    return `${(n / 1024 ** i).toFixed(i === 0 ? 0 : digits)} ${u[i]}`;
  }
  const fmtRate = (n) => `${fmtBytes(n)}/s`;
  const fmtPct = (n) => `${Math.round(n ?? 0)}`;

  function fmtUptime(s) {
    const d = Math.floor(s / 86400), hr = Math.floor((s % 86400) / 3600), m = Math.floor((s % 3600) / 60);
    if (d) return `${d}d ${hr}h`;
    if (hr) return `${hr}h ${m}m`;
    return `${m}m`;
  }

  const rtf = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto' });
  function fmtAgo(iso) {
    const t = new Date(iso).getTime();
    if (!t) return '';
    const s = Math.round((t - Date.now()) / 1000);
    const steps = [[60, 'second'], [3600, 'minute'], [86400, 'hour'], [2592000, 'day'], [31536000, 'month'], [Infinity, 'year']];
    let div = 1;
    for (const [limit, unit] of steps) {
      if (Math.abs(s) < limit) return rtf.format(Math.round(s / div), unit);
      div = limit;
    }
    return '';
  }
  const fmtDate = (iso) => new Date(iso).toLocaleString();

  // ---------- Storage (best effort) ----------

  const store = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { v == null ? localStorage.removeItem(k) : localStorage.setItem(k, v); } catch { /* ignore */ } },
  };

  // ---------- API ----------

  class ApiError extends Error {
    constructor(message, status) { super(message); this.status = status; }
  }

  async function api(path, { method = 'GET', body } = {}) {
    const headers = { 'X-Requested-With': 'cloudpanel', Accept: 'application/json' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    let res;
    try {
      res = await fetch(`/api${path}`, {
        method, headers, credentials: 'same-origin',
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch {
      throw new ApiError('Cannot reach the server. Check your connection.', 0);
    }
    let data = null;
    try { data = await res.json(); } catch { /* empty body */ }
    if (res.status === 401 && path !== '/auth/login') {
      showLogin();
      throw new ApiError('Your session has expired. Please sign in again.', 401);
    }
    if (!res.ok) throw new ApiError((data && data.error) || `Request failed (${res.status})`, res.status);
    return data;
  }

  // ---------- Toasts ----------

  function toast(message, type = 'success') {
    const el = h('div', { class: `toast ${type}`, role: type === 'error' ? 'alert' : 'status' },
      icon(type === 'error' ? 'alert' : 'check'),
      h('div', { class: 'grow', text: message }),
      h('button', { class: 'icon-btn', 'aria-label': 'Dismiss', onclick: () => el.remove() }, icon('x')));
    $('#toasts').append(el);
    setTimeout(() => el.remove(), type === 'error' ? 7000 : 3500);
  }

  // ---------- Dialogs ----------

  function openDialog({ title, description, body, footer, drawer = false, wide = false, onClose }) {
    const closeBtn = h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Close' }, icon('x'));
    const dlg = h('dialog', { class: [drawer && 'drawer', wide && 'wide'].filter(Boolean).join(' ') },
      h('div', { class: 'dialog-head' },
        h('div', { class: 'grow' }, h('h2', { text: title }), description && h('p', { text: description })),
        closeBtn),
      h('div', { class: 'dialog-body' }, body),
      footer && h('div', { class: 'dialog-foot' }, footer));
    const close = () => dlg.open && dlg.close();
    closeBtn.addEventListener('click', close);
    dlg.addEventListener('click', (e) => { if (e.target === dlg) close(); });
    dlg.addEventListener('close', () => { dlg.remove(); onClose && onClose(); });
    document.body.append(dlg);
    dlg.showModal();
    return { el: dlg, close };
  }

  function confirmDialog({ title, message, confirmText = 'Confirm', danger = false }) {
    return new Promise((resolve) => {
      let result = false;
      const ok = h('button', { class: `btn ${danger ? 'danger solid' : 'primary'}`, type: 'button', text: confirmText });
      const cancel = h('button', { class: 'btn', type: 'button', text: 'Cancel' });
      const d = openDialog({ title, body: h('p', { class: 'muted', text: message }), footer: [cancel, ok], onClose: () => resolve(result) });
      cancel.addEventListener('click', d.close);
      ok.addEventListener('click', () => { result = true; d.close(); });
      ok.focus();
    });
  }

  /** Dialog wrapping a form with busy state and inline error reporting. */
  function formDialog({ title, description, content, submitText = 'Save', drawer = false, wide = false, onSubmit }) {
    const id = `f${Math.random().toString(36).slice(2)}`;
    const error = h('div', { class: 'alert error', role: 'alert', hidden: true });
    const form = h('form', { id, class: 'form', novalidate: true }, content, error);
    const submit = h('button', { class: 'btn primary', type: 'submit', form: id, text: submitText });
    const cancel = h('button', { class: 'btn', type: 'button', text: 'Cancel' });
    const d = openDialog({ title, description, body: form, footer: [cancel, submit], drawer, wide });
    cancel.addEventListener('click', d.close);

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      error.hidden = true;
      if (!validateForm(form)) return;
      submit.disabled = true;
      submit.replaceChildren(spinner(), submitText);
      try {
        await onSubmit(formData(form), d);
        d.close();
      } catch (err) {
        error.replaceChildren(icon('alert'), h('div', { text: err.message }));
        error.hidden = false;
      } finally {
        submit.disabled = false;
        submit.replaceChildren(submitText);
      }
    });
    setTimeout(() => { const first = form.querySelector('input:not([type=hidden]):not([type=radio]), textarea, select'); first && first.focus(); }, 30);
    return d;
  }

  function formData(form) {
    const out = {};
    for (const el of form.elements) {
      if (!el.name || el.disabled || el.closest('[hidden]')) continue;
      if (el.type === 'checkbox') out[el.name] = el.checked;
      else if (el.type === 'radio') { if (el.checked) out[el.name] = el.value; }
      else out[el.name] = el.value.trim();
    }
    return out;
  }

  /** Runs `data-validate` checks; shows the message under the field. */
  function validateForm(form) {
    let ok = true;
    for (const el of form.querySelectorAll('[data-validate]')) {
      if (el.closest('[hidden]')) continue;
      const msg = VALIDATORS[el.dataset.validate](el.value.trim(), form);
      const holder = el.closest('.field');
      let err = holder && holder.querySelector('.error-text');
      if (msg) {
        ok = false;
        el.setAttribute('aria-invalid', 'true');
        if (holder && !err) { err = h('div', { class: 'error-text' }); holder.append(err); }
        if (err) err.textContent = msg;
      } else {
        el.removeAttribute('aria-invalid');
        if (err) err.remove();
      }
    }
    const firstBad = form.querySelector('[aria-invalid="true"]');
    if (firstBad) firstBad.focus();
    return ok;
  }

  const DOMAIN_RE = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/;
  const VALIDATORS = {
    required: (v) => (v ? '' : 'This field is required'),
    domain: (v) => (DOMAIN_RE.test(v.toLowerCase().replace(/\.$/, '')) ? '' : 'Enter a valid domain, e.g. app.example.com'),
    port: (v) => (/^\d+$/.test(v) && +v >= 1 && +v <= 65535 ? '' : 'Enter a port between 1 and 65535'),
    email: (v) => (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v) ? '' : 'Enter a valid email address'),
    password: (v) => (v.length >= 10 ? '' : 'Use at least 10 characters'),
    confirm: (v, form) => (v === form.elements.new_password.value ? '' : 'Passwords do not match'),
    cron: (v) => (/^(@(reboot|yearly|annually|monthly|weekly|daily|midnight|hourly)|(\S+\s+){4}\S+)$/.test(v) ? '' : 'Use 5 fields (m h dom mon dow) or a macro like @daily'),
    optionalPath: (v) => (!v || /^\/[A-Za-z0-9._\-/]*$/.test(v) ? '' : 'Use an absolute path with letters, digits, . _ - /'),
  };

  function field({ label, name, type = 'text', value = '', placeholder, hint, validate, attrs = {} }) {
    const id = `in-${name}-${Math.random().toString(36).slice(2, 7)}`;
    const input = type === 'textarea'
      ? h('textarea', { class: 'input', id, name, placeholder, 'data-validate': validate, spellcheck: 'false', ...attrs })
      : h('input', { class: 'input', id, name, type, placeholder, 'data-validate': validate, ...attrs });
    input.value = value;
    return h('div', { class: 'field' }, h('label', { for: id, text: label }), input, hint && h('div', { class: 'hint', text: hint }));
  }

  function selectField({ label, name, options, value }) {
    const id = `sel-${name}-${Math.random().toString(36).slice(2, 7)}`;
    const sel = h('select', { class: 'input', id, name },
      options.map(([v, t]) => h('option', { value: v, text: t, selected: v === value })));
    return h('div', { class: 'field' }, h('label', { for: id, text: label }), sel);
  }

  // ---------- Popover menu ----------

  let openMenuEl = null;
  function closeMenu() { if (openMenuEl) { openMenuEl.remove(); openMenuEl = null; } }
  function openMenu(anchor, items) {
    closeMenu();
    const menu = h('div', { class: 'menu', role: 'menu' },
      items.map((it) => (it === '-' ? h('hr') : h('button', {
        type: 'button', role: 'menuitem', class: it.danger ? 'danger' : '',
        onclick: () => { closeMenu(); it.action(); },
      }, icon(it.icon), it.label))));
    document.body.append(menu);
    const r = anchor.getBoundingClientRect();
    const mw = menu.offsetWidth, mh = menu.offsetHeight;
    menu.style.left = `${Math.max(8, Math.min(r.right - mw, window.innerWidth - mw - 8))}px`;
    menu.style.top = `${r.bottom + mh + 8 > window.innerHeight ? r.top - mh - 4 : r.bottom + 4}px`;
    openMenuEl = menu;
    menu.querySelector('button').focus();
  }
  document.addEventListener('click', (e) => { if (openMenuEl && !openMenuEl.contains(e.target) && !e.target.closest('[data-menu]')) closeMenu(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeMenu(); });
  window.addEventListener('scroll', closeMenu, true);
  window.addEventListener('resize', closeMenu);

  const moreButton = (items) => {
    const b = h('button', { class: 'icon-btn', type: 'button', 'aria-label': 'More actions', 'aria-haspopup': 'menu', 'data-menu': '' }, icon('more'));
    b.addEventListener('click', (e) => { e.stopPropagation(); openMenuEl ? closeMenu() : openMenu(b, items); });
    return b;
  };

  // ---------- Shared view pieces ----------

  function card({ title, sub, actions, body, flush = false }) {
    return h('section', { class: 'card' },
      title && h('div', { class: 'card-head' },
        h('div', { class: 'grow' }, h('h2', { text: title }), sub && h('div', { class: 'sub', text: sub })),
        actions),
      flush ? body : h('div', { class: 'card-body' }, body));
  }

  function emptyState({ iconName, title, text, action }) {
    return h('div', { class: 'empty' },
      h('div', { class: 'empty-icon' }, icon(iconName, 'lg')),
      h('h3', { text: title }), text && h('p', { text }), action);
  }

  function errorState(message, retry) {
    return emptyState({
      iconName: 'alert', title: 'Something went wrong', text: message,
      action: retry && h('button', { class: 'btn', onclick: retry }, icon('refresh'), 'Try again'),
    });
  }

  function skeletonRows(cols, rows = 3) {
    return Array.from({ length: rows }, () => h('tr', null,
      Array.from({ length: cols }, () => h('td', null, h('div', { class: 'skeleton' })))));
  }

  function table(headers, rows) {
    return h('div', { class: 'table-wrap' }, h('table', null,
      h('thead', null, h('tr', null, headers.map((x) => (typeof x === 'string'
        ? h('th', { text: x })
        : h('th', { class: x.class || '', text: x.label }))))),
      h('tbody', null, rows)));
  }

  async function withBusy(btn, fn) {
    const old = [...btn.childNodes];
    btn.disabled = true;
    btn.replaceChildren(spinner());
    try { await fn(); } catch (e) { toast(e.message, 'error'); } finally { btn.disabled = false; btn.replaceChildren(...old); }
  }

  function setActions(...nodes) { $('#page-actions').replaceChildren(...nodes.filter(Boolean)); }

  // ======================================================================
  // Views
  // ======================================================================

  // ---------- Overview ----------

  const HISTORY = 60;
  const history = { cpu: [], mem: [], rx: [], tx: [] };

  function sparkline(cls = '') {
    const svg = svgEl('svg', { class: `spark ${cls}`.trim(), viewBox: '0 0 100 36', preserveAspectRatio: 'none', 'aria-hidden': 'true' });
    const area = svgEl('path', { class: 'area' });
    const line = svgEl('path', { class: 'line' });
    svg.append(area, line);
    svg.update = (values, max) => {
      if (values.length < 2) return;
      const top = Math.max(max || Math.max(...values), 1);
      const step = 100 / (HISTORY - 1);
      const offset = (HISTORY - values.length) * step;
      const pts = values.map((v, i) => [offset + i * step, 34 - (Math.min(v, top) / top) * 32]);
      const d = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(2)},${y.toFixed(2)}`).join('');
      line.setAttribute('d', d);
      area.setAttribute('d', `${d}L${pts[pts.length - 1][0].toFixed(2)},36L${pts[0][0].toFixed(2)},36Z`);
    };
    return svg;
  }

  function statCard(label, iconName, sparkCls) {
    const value = h('div', { class: 'stat-value', text: '–' });
    const meta = h('div', { class: 'stat-meta', text: ' ' });
    const spark = sparkline(sparkCls);
    const el = h('section', { class: 'card stat' },
      h('div', { class: 'stat-label' }, h('span', { text: label }), icon(iconName)), value, meta, spark);
    return { el, value, meta, spark };
  }

  function barClass(p) { return p >= 90 ? 'bar danger' : p >= 75 ? 'bar warn' : 'bar'; }

  function renderOverview(view) {
    const cpu = statCard('CPU', 'cpu');
    const mem = statCard('Memory', 'memory');
    const disk = statCard('Disk', 'disk');
    const net = statCard('Network', 'network', 'alt');
    disk.spark.remove();
    const diskBar = h('div', { class: 'bar' }, h('span'));
    disk.el.append(diskBar);

    const info = h('dl', { class: 'kv' });
    const disks = h('div');
    const procBody = h('tbody', null, skeletonRows(4, 5));

    view.replaceChildren(
      h('div', { class: 'grid stats' }, cpu.el, mem.el, disk.el, net.el),
      h('div', { class: 'grid two' },
        card({ title: 'System', body: info }),
        card({ title: 'Storage', body: disks })),
      card({
        title: 'Top processes', sub: 'Sorted by CPU usage', flush: true,
        body: h('div', { class: 'table-wrap' }, h('table', null,
          h('thead', null, h('tr', null, h('th', { text: 'Process' }), h('th', { class: 'hide-sm', text: 'PID' }),
            h('th', { class: 'num', text: 'CPU' }), h('th', { class: 'num', text: 'Memory' }))),
          procBody)),
      }));

    let failed = false;
    async function tick() {
      if (document.hidden) return;
      let m;
      try {
        m = await api('/system/metrics');
        failed = false;
      } catch (e) {
        if (!failed && e.status !== 401) toast(e.message, 'error');
        failed = true;
        return;
      }
      const push = (arr, v) => { arr.push(v); if (arr.length > HISTORY) arr.shift(); };
      push(history.cpu, m.total_cpu_usage);
      push(history.mem, m.memory_usage_percentage);
      push(history.rx, m.network_rx_per_sec);
      push(history.tx, m.network_tx_per_sec);

      setHost(m.hostname);
      $('#page-sub').textContent = `${m.os_name} ${m.os_version}`.trim() + ` · up ${fmtUptime(m.uptime_seconds)}`;

      cpu.value.replaceChildren(fmtPct(m.total_cpu_usage), h('small', { text: '%' }));
      cpu.meta.textContent = `${m.cpu_count} cores · load ${m.load_average.map((x) => x.toFixed(2)).join(' ')}`;
      cpu.spark.update(history.cpu, 100);

      mem.value.replaceChildren(fmtPct(m.memory_usage_percentage), h('small', { text: '%' }));
      mem.meta.textContent = `${fmtBytes(m.used_memory_bytes)} of ${fmtBytes(m.total_memory_bytes)}`;
      mem.spark.update(history.mem, 100);

      const root = m.disks.find((d) => d.mount_point === '/') || [...m.disks].sort((a, b) => b.total_space_bytes - a.total_space_bytes)[0];
      if (root) {
        disk.value.replaceChildren(fmtPct(root.usage_percentage), h('small', { text: '%' }));
        disk.meta.textContent = `${fmtBytes(root.available_space_bytes)} free of ${fmtBytes(root.total_space_bytes)}`;
        diskBar.className = barClass(root.usage_percentage);
        diskBar.firstChild.style.width = `${root.usage_percentage}%`;
      }

      net.value.replaceChildren(fmtRate(m.network_rx_per_sec).split(' ')[0], h('small', { text: `${fmtRate(m.network_rx_per_sec).split(' ')[1]} in` }));
      net.meta.textContent = `${fmtRate(m.network_tx_per_sec)} out · ${fmtBytes(m.network_rx_bytes)} total in`;
      net.spark.update(history.rx);

      const rows = [
        ['Hostname', m.hostname], ['Operating system', `${m.os_name} ${m.os_version}`.trim()],
        ['Kernel', m.kernel_version], ['Uptime', fmtUptime(m.uptime_seconds)],
        ['Swap', m.total_swap_bytes ? `${fmtBytes(m.used_swap_bytes)} of ${fmtBytes(m.total_swap_bytes)}` : 'None'],
      ];
      info.replaceChildren(...rows.flatMap(([k, v]) => [h('dt', { text: k }), h('dd', { class: 'truncate', text: v })]));

      disks.replaceChildren(...(m.disks.length ? m.disks.map((d) => h('div', { class: 'disk' },
        h('div', { class: 'row' },
          h('span', { class: 'grow truncate mono', text: d.mount_point }),
          h('span', { class: 'small muted', text: `${fmtBytes(d.used_space_bytes)} / ${fmtBytes(d.total_space_bytes)}` })),
        (() => { const b = h('div', { class: barClass(d.usage_percentage) }, h('span')); b.firstChild.style.width = `${d.usage_percentage}%`; return b; })()))
        : [h('p', { class: 'muted', text: 'No disks reported.' })]));

      procBody.replaceChildren(...m.top_processes.map((p) => h('tr', null,
        h('td', null, h('span', { class: 'mono', text: p.name })),
        h('td', { class: 'hide-sm faint mono', text: p.pid }),
        h('td', { class: 'num', text: `${p.cpu_usage.toFixed(1)}%` }),
        h('td', { class: 'num', text: fmtBytes(p.memory_bytes) }))));
    }

    tick();
    const timer = setInterval(tick, 3000);
    const onVisible = () => { if (!document.hidden) tick(); };
    document.addEventListener('visibilitychange', onVisible);
    return () => { clearInterval(timer); document.removeEventListener('visibilitychange', onVisible); };
  }

  // ---------- Sites ----------

  const SITE_TYPES = {
    nodejs: { label: 'Node.js', desc: 'Next.js, Express, Nuxt' },
    python: { label: 'Python', desc: 'FastAPI, Django, Flask' },
    static: { label: 'Static', desc: 'HTML, Vite, SPA builds' },
    reverse_proxy: { label: 'Reverse proxy', desc: 'Any local HTTP service' },
    docker_proxy: { label: 'Docker', desc: 'Container port' },
  };

  function renderSites(view) {
    let sites = [];
    let query = '';
    const search = h('input', { class: 'input', type: 'search', placeholder: 'Search sites', 'aria-label': 'Search sites' });
    const tbody = h('tbody', null, skeletonRows(5));
    const holder = h('div');
    const tableCard = card({
      flush: true,
      body: h('div', null,
        h('div', { class: 'card-head' }, h('div', { class: 'toolbar grow' }, h('div', { class: 'search' }, icon('search'), search))),
        holder),
    });
    const tableEl = h('div', { class: 'table-wrap' }, h('table', null,
      h('thead', null, h('tr', null,
        h('th', { text: 'Domain' }), h('th', { text: 'Type' }), h('th', { class: 'hide-sm', text: 'Target' }),
        h('th', { text: 'SSL' }), h('th', { class: 'hide-sm', text: 'Created' }), h('th'))),
      tbody));
    holder.append(tableEl);
    view.replaceChildren(tableCard);
    setActions(h('button', { class: 'btn primary', onclick: () => addSiteDialog(load) }, icon('plus'), 'Add site'));

    search.addEventListener('input', () => { query = search.value.trim().toLowerCase(); draw(); });

    function draw() {
      if (!sites.length) {
        holder.replaceChildren(emptyState({
          iconName: 'globe', title: 'No sites yet',
          text: 'Add a domain to serve a static site or proxy it to an app running on this server.',
          action: h('button', { class: 'btn primary', onclick: () => addSiteDialog(load) }, icon('plus'), 'Add your first site'),
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
        return h('tr', null,
          h('td', null,
            h('div', { class: 'cell-title' }, h('a', { href: url, target: '_blank', rel: 'noopener noreferrer', text: s.domain })),
            s.include_www && h('div', { class: 'cell-sub', text: `www.${s.domain}` })),
          h('td', null, h('span', { class: 'badge', text: t.label })),
          h('td', { class: 'hide-sm mono muted truncate', text: s.site_type === 'static' ? (s.document_root || '') : `127.0.0.1:${s.target_port}` }),
          h('td', null, s.ssl_enabled
            ? h('span', { class: 'badge ok' }, icon('lock'), 'Secure')
            : h('button', { class: 'btn sm', onclick: () => sslDialog(s, load) }, icon('unlock'), 'Enable')),
          h('td', { class: 'hide-sm muted nowrap', title: fmtDate(s.created_at), text: fmtAgo(s.created_at) }),
          h('td', { class: 'actions' }, moreButton([
            { icon: 'external', label: 'Open site', action: () => window.open(url, '_blank', 'noopener,noreferrer') },
            { icon: 'lock', label: s.ssl_enabled ? 'Replace certificate' : 'Enable SSL', action: () => sslDialog(s, load) },
            '-',
            { icon: 'trash', label: 'Delete site', danger: true, action: () => deleteSite(s, load) },
          ])));
      }));
    }

    async function load() {
      try {
        sites = await api('/sites');
        $('#page-sub').textContent = `${sites.length} site${sites.length === 1 ? '' : 's'}`;
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
    const portField = field({ label: 'App port', name: 'target_port', type: 'number', placeholder: '3000', validate: 'port', hint: 'The port your app listens on at 127.0.0.1.', attrs: { min: 1, max: 65535, inputmode: 'numeric' } });
    const rootField = field({ label: 'Document root (optional)', name: 'document_root', validate: 'optionalPath', hint: 'Defaults to <sites dir>/<domain>/public.' });
    rootField.hidden = true;

    typeGroup.addEventListener('change', () => {
      const isStatic = typeGroup.querySelector('input:checked').value === 'static';
      portField.hidden = isStatic;
      rootField.hidden = !isStatic;
    });

    formDialog({
      title: 'Add site',
      description: 'Creates an nginx virtual host for the domain. Point its DNS A record to this server.',
      submitText: 'Create site',
      drawer: true,
      content: [
        field({ label: 'Domain', name: 'domain', placeholder: 'app.example.com', validate: 'domain', attrs: { autocapitalize: 'off', spellcheck: 'false' } }),
        h('div', { class: 'field' }, h('span', { class: 'label', text: 'Type' }), typeGroup),
        portField, rootField,
        h('label', { class: 'check' }, h('input', { type: 'checkbox', name: 'include_www' }), 'Also serve the www. subdomain'),
      ],
      async onSubmit(d) {
        const body = { domain: d.domain.toLowerCase(), site_type: d.site_type, include_www: !!d.include_www };
        if (d.site_type === 'static') { if (d.document_root) body.document_root = d.document_root; }
        else body.target_port = Number(d.target_port);
        await api('/sites', { method: 'POST', body });
        toast(`${body.domain} created`);
        done();
      },
    });
  }

  function sslDialog(site, done) {
    let mode = 'le';
    const le = h('div', { class: 'form' },
      h('div', { class: 'alert info' }, icon('alert'),
        h('div', { text: `DNS for ${site.domain}${site.include_www ? ` and www.${site.domain}` : ''} must already point to this server, and port 80 must be open.` })),
      field({ label: 'Email for expiry notices', name: 'email', type: 'email', placeholder: 'you@example.com', validate: 'email', attrs: { autocomplete: 'email' } }));
    const custom = h('div', { class: 'form', hidden: true },
      field({ label: 'Certificate (PEM, full chain)', name: 'custom_cert', type: 'textarea', placeholder: '-----BEGIN CERTIFICATE-----', validate: 'required' }),
      field({ label: 'Private key (PEM)', name: 'custom_key', type: 'textarea', placeholder: '-----BEGIN PRIVATE KEY-----', validate: 'required' }));
    const tabLe = h('button', { type: 'button', role: 'tab', 'aria-selected': 'true', text: "Let's Encrypt" });
    const tabCustom = h('button', { type: 'button', role: 'tab', 'aria-selected': 'false', text: 'Custom certificate' });
    const select = (m) => {
      mode = m;
      tabLe.setAttribute('aria-selected', String(m === 'le'));
      tabCustom.setAttribute('aria-selected', String(m !== 'le'));
      le.hidden = m !== 'le';
      custom.hidden = m === 'le';
    };
    tabLe.addEventListener('click', () => select('le'));
    tabCustom.addEventListener('click', () => select('custom'));

    formDialog({
      title: `SSL for ${site.domain}`,
      description: 'HTTP traffic will be redirected to HTTPS.',
      submitText: 'Install certificate',
      content: [h('div', { class: 'tabs', role: 'tablist' }, tabLe, tabCustom), le, custom],
      async onSubmit(d) {
        const body = mode === 'le' ? { email: d.email } : { custom_cert: d.custom_cert, custom_key: d.custom_key };
        await api(`/sites/${site.id}/ssl`, { method: 'POST', body });
        toast(`SSL enabled for ${site.domain}`);
        done();
      },
    });
  }

  async function deleteSite(site, done) {
    const ok = await confirmDialog({
      title: `Delete ${site.domain}?`,
      message: 'The nginx configuration is removed and the site stops responding. Files in the document root are kept.',
      confirmText: 'Delete site', danger: true,
    });
    if (!ok) return;
    try {
      const res = await api(`/sites/${site.id}`, { method: 'DELETE' });
      toast(res.warning ? `${site.domain} deleted (nginx: ${res.warning})` : `${site.domain} deleted`, res.warning ? 'error' : 'success');
      done();
    } catch (e) { toast(e.message, 'error'); }
  }

  // ---------- Docker ----------

  function renderDocker(view) {
    const holder = h('div', null, card({ flush: true, body: table(['Container', 'Image', 'Ports', 'Status', ''], skeletonRows(5)) }));
    view.replaceChildren(holder);
    const refresh = h('button', { class: 'btn', onclick: () => withBusy(refresh, load) }, icon('refresh'), h('span', { class: 'hide-sm', text: 'Refresh' }));
    setActions(refresh);

    async function load() {
      try {
        const status = await api('/docker/status');
        if (!status.available) {
          $('#page-sub').textContent = 'Docker not detected';
          holder.replaceChildren(card({ body: emptyState({
            iconName: 'box', title: 'Docker isn’t running',
            text: 'Install Docker (re-run the installer with --with-docker) or start the docker service, then refresh.',
          }) }));
          return;
        }
        const list = await api('/docker/containers');
        const running = list.filter((c) => c.state === 'running').length;
        $('#page-sub').textContent = `${running} running · ${list.length} total`;
        if (!list.length) {
          holder.replaceChildren(card({ body: emptyState({ iconName: 'box', title: 'No containers', text: 'Containers you start with docker or docker compose appear here.' }) }));
          return;
        }
        holder.replaceChildren(card({ flush: true, body: table(['Container', { label: 'Image', class: 'hide-sm' }, 'Ports', { label: 'Status', class: 'hide-sm' }, ''], list.map((c) => {
          const isUp = c.state === 'running';
          const act = (action) => async (btn) => {
            await api(`/docker/containers/${encodeURIComponent(c.id)}/${action}`, { method: 'POST' });
            toast(`${c.name}: ${action} done`);
            load();
          };
          const quick = h('button', { class: 'icon-btn', title: isUp ? 'Stop' : 'Start', 'aria-label': isUp ? 'Stop' : 'Start' }, icon(isUp ? 'stop' : 'play'));
          quick.addEventListener('click', () => withBusy(quick, act(isUp ? 'stop' : 'start')));
          return h('tr', null,
            h('td', null,
              h('div', { class: 'cell-title' }, h('span', { class: `dot ${isUp ? 'ok' : c.state === 'exited' ? '' : 'warn'}` }), h('span', { text: c.name })),
              h('div', { class: 'cell-sub mono', text: c.id.slice(0, 12) })),
            h('td', { class: 'hide-sm mono muted truncate', text: c.image }),
            h('td', null, c.ports.length ? c.ports.slice(0, 3).map((p) => h('div', { class: 'mono small', text: p })) : h('span', { class: 'faint', text: '—' })),
            h('td', { class: 'hide-sm muted', text: c.status }),
            h('td', { class: 'actions' }, quick, moreButton([
              { icon: 'terminal', label: 'View logs', action: () => logsDrawer(c) },
              { icon: 'refresh', label: 'Restart', action: () => act('restart')().catch((e) => toast(e.message, 'error')) },
              '-',
              { icon: 'link', label: 'Expose on a domain', action: () => exposeDialog(c) },
            ])));
        })) }));
      } catch (e) {
        if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) }));
      }
    }
    load();
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

  // ---------- Firewall ----------

  function renderFirewall(view) {
    const holder = h('div', null, card({ flush: true, body: table(['Port', 'Protocol', 'Action', 'Comment', ''], skeletonRows(5)) }));
    view.replaceChildren(
      h('div', { class: 'alert info' }, icon('shield'),
        h('div', { text: 'Rules are applied with UFW. SSH (22) and the panel port cannot be denied from here, so you can’t lock yourself out.' })),
      holder);
    setActions(h('button', { class: 'btn primary', onclick: () => addRuleDialog(load) }, icon('plus'), 'Add rule'));

    async function load() {
      try {
        const rules = await api('/firewall/rules');
        $('#page-sub').textContent = `${rules.length} custom rule${rules.length === 1 ? '' : 's'}`;
        if (!rules.length) {
          holder.replaceChildren(card({ body: emptyState({
            iconName: 'shield', title: 'No custom rules', text: 'Open or block ports on this server.',
            action: h('button', { class: 'btn primary', onclick: () => addRuleDialog(load) }, icon('plus'), 'Add rule'),
          }) }));
          return;
        }
        holder.replaceChildren(card({ flush: true, body: table(['Port', 'Protocol', 'Action', { label: 'Comment', class: 'hide-sm' }, ''], rules.map((r) => {
          const del = h('button', { class: 'icon-btn danger', title: 'Delete rule', 'aria-label': `Delete rule for port ${r.port}` }, icon('trash'));
          del.addEventListener('click', async () => {
            if (!(await confirmDialog({ title: `Delete rule for port ${r.port}?`, message: `The UFW "${r.action} ${r.port}/${r.protocol}" rule will be removed.`, confirmText: 'Delete', danger: true }))) return;
            await withBusy(del, async () => { await api(`/firewall/rules/${r.id}`, { method: 'DELETE' }); toast('Rule removed'); await load(); });
          });
          return h('tr', null,
            h('td', { class: 'mono', text: r.port }),
            h('td', { class: 'muted', text: r.protocol.toUpperCase() }),
            h('td', null, h('span', { class: `badge ${r.action === 'allow' ? 'ok' : 'danger'}`, text: r.action === 'allow' ? 'Allow' : 'Deny' })),
            h('td', { class: 'hide-sm muted', text: r.comment || '—' }),
            h('td', { class: 'actions' }, del));
        })) }));
      } catch (e) {
        if (e.status !== 401) holder.replaceChildren(card({ body: errorState(e.message, load) }));
      }
    }
    load();
  }

  function addRuleDialog(done) {
    formDialog({
      title: 'Add firewall rule',
      submitText: 'Add rule',
      content: [
        h('div', { class: 'form-grid' },
          field({ label: 'Port', name: 'port', type: 'number', placeholder: '3306', validate: 'port', attrs: { min: 1, max: 65535, inputmode: 'numeric' } }),
          selectField({ label: 'Protocol', name: 'protocol', value: 'tcp', options: [['tcp', 'TCP'], ['udp', 'UDP'], ['any', 'Any']] }),
          selectField({ label: 'Action', name: 'action', value: 'allow', options: [['allow', 'Allow'], ['deny', 'Deny']] })),
        field({ label: 'Comment (optional)', name: 'comment', placeholder: 'e.g. MySQL for app server', attrs: { maxlength: 120 } }),
      ],
      async onSubmit(d) {
        await api('/firewall/rules', { method: 'POST', body: { port: Number(d.port), protocol: d.protocol, action: d.action, comment: d.comment || null } });
        toast(`Port ${d.port} ${d.action === 'allow' ? 'allowed' : 'denied'}`);
        done();
      },
    });
  }

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

  function renderCron(view) {
    const holder = h('div', null, card({ flush: true, body: table(['Schedule', 'Command', 'User', ''], skeletonRows(4)) }));
    view.replaceChildren(holder);
    setActions(h('button', { class: 'btn primary', onclick: () => addCronDialog(load) }, icon('plus'), 'Add job'));

    async function load() {
      try {
        const jobs = await api('/cron/jobs');
        $('#page-sub').textContent = `${jobs.length} job${jobs.length === 1 ? '' : 's'} · /etc/cron.d/cloudpanel`;
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

  // ---------- Settings ----------

  function renderSettings(view) {
    const pwForm = h('form', { class: 'form', novalidate: true },
      field({ label: 'Current password', name: 'current_password', type: 'password', validate: 'required', attrs: { autocomplete: 'current-password' } }),
      field({ label: 'New password', name: 'new_password', type: 'password', validate: 'password', hint: 'At least 10 characters.', attrs: { autocomplete: 'new-password' } }),
      field({ label: 'Confirm new password', name: 'confirm', type: 'password', validate: 'confirm', attrs: { autocomplete: 'new-password' } }),
      h('div', null, h('button', { class: 'btn primary', type: 'submit', text: 'Update password' })));
    pwForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!validateForm(pwForm)) return;
      const btn = pwForm.querySelector('button[type=submit]');
      const d = formData(pwForm);
      await withBusy(btn, async () => {
        const r = await api('/auth/password', { method: 'POST', body: { current_password: d.current_password, new_password: d.new_password } });
        pwForm.reset();
        toast(r.message);
      });
    });

    const signOutAll = h('button', { class: 'btn danger' }, icon('logout'), 'Sign out everywhere');
    signOutAll.addEventListener('click', async () => {
      if (!(await confirmDialog({ title: 'Sign out everywhere?', message: 'Every session, including this one, will be signed out.', confirmText: 'Sign out all', danger: true }))) return;
      await withBusy(signOutAll, async () => { await api('/auth/logout-all', { method: 'POST' }); showLogin(); });
    });

    const current = store.get('cp-theme') || 'system';
    const themeTabs = h('div', { class: 'tabs', role: 'tablist', 'aria-label': 'Theme' },
      [['system', 'System'], ['light', 'Light'], ['dark', 'Dark']].map(([v, t]) => {
        const b = h('button', { type: 'button', role: 'tab', 'aria-selected': String(v === current), text: t });
        b.addEventListener('click', () => {
          setTheme(v);
          themeTabs.querySelectorAll('button').forEach((x) => x.setAttribute('aria-selected', String(x === b)));
        });
        return b;
      }));

    view.replaceChildren(h('div', { class: 'grid two' },
      card({ title: 'Password', sub: `Signed in as ${state.user.username}`, body: pwForm }),
      h('div', { class: 'grid' },
        card({ title: 'Appearance', body: themeTabs }),
        card({ title: 'Sessions', sub: 'Sessions expire after 12 hours.', body: h('div', { class: 'form' },
          h('p', { class: 'muted small', text: 'Revoke access on all browsers and devices, for example if you signed in on a shared computer.' }),
          h('div', null, signOutAll)) }))));
  }

  // ======================================================================
  // Shell, routing, auth
  // ======================================================================

  const ROUTES = {
    overview: { title: 'Overview', render: renderOverview },
    sites: { title: 'Sites', render: renderSites },
    docker: { title: 'Containers', render: renderDocker },
    firewall: { title: 'Firewall', render: renderFirewall },
    cron: { title: 'Cron jobs', render: renderCron },
    settings: { title: 'Settings', render: renderSettings },
  };

  const state = { user: null, cleanup: null };

  function route() {
    if (!state.user) return;
    const name = location.hash.replace(/^#\/?/, '') || 'overview';
    const r = ROUTES[name];
    if (!r) { location.hash = '#/overview'; return; }
    if (state.cleanup) { state.cleanup(); state.cleanup = null; }
    closeMenu();
    document.querySelectorAll('.nav a').forEach((a) => {
      if (a.dataset.route === name) a.setAttribute('aria-current', 'page'); else a.removeAttribute('aria-current');
    });
    $('#app').classList.remove('nav-open');
    $('#page-title').textContent = r.title;
    $('#page-sub').textContent = '';
    document.title = `${r.title} · CloudPanel`;
    setActions();
    const view = $('#view');
    view.replaceChildren();
    state.cleanup = r.render(view) || null;
  }

  function setHost(name) {
    if (!name) return;
    $('#server-host').textContent = name;
    $('#server-chip').hidden = false;
  }

  function showLogin() {
    state.user = null;
    if (state.cleanup) { state.cleanup(); state.cleanup = null; }
    document.querySelectorAll('dialog').forEach((d) => d.close());
    $('#app').hidden = true;
    $('#login').hidden = false;
    const insecure = location.protocol === 'http:' && !['localhost', '127.0.0.1', '[::1]'].includes(location.hostname);
    $('#login-insecure').hidden = !insecure;
    document.title = 'Sign in · CloudPanel';
    setTimeout(() => $('#login-username').focus(), 0);
  }

  function showApp(user) {
    state.user = user;
    $('#login').hidden = true;
    $('#app').hidden = false;
    $('#user-name').textContent = user.username;
    $('#user-initial').textContent = (user.username || '?')[0];
    $('#user-role').textContent = user.role === 'admin' ? 'Administrator' : 'Site manager';
    route();
  }

  $('#login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const err = $('#login-error');
    const btn = $('#login-submit');
    const username = $('#login-username').value.trim();
    const password = $('#login-password').value;
    err.hidden = true;
    if (!username || !password) {
      err.textContent = 'Enter your username and password.';
      err.hidden = false;
      return;
    }
    btn.disabled = true;
    btn.replaceChildren(spinner(), 'Signing in');
    try {
      await api('/auth/login', { method: 'POST', body: { username, password } });
      $('#login-password').value = '';
      showApp(await api('/auth/me'));
    } catch (ex) {
      err.textContent = ex.message;
      err.hidden = false;
      $('#login-password').select();
    } finally {
      btn.disabled = false;
      btn.replaceChildren('Sign in');
    }
  });

  $('#logout-btn').addEventListener('click', async () => {
    try { await api('/auth/logout', { method: 'POST' }); } catch { /* ignore */ }
    showLogin();
  });

  $('#menu-btn').addEventListener('click', () => $('#app').classList.add('nav-open'));
  $('#backdrop').addEventListener('click', () => $('#app').classList.remove('nav-open'));
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') $('#app').classList.remove('nav-open'); });
  window.addEventListener('hashchange', route);

  // ---------- Theme ----------

  const media = window.matchMedia('(prefers-color-scheme: dark)');
  function effectiveTheme() {
    const t = document.documentElement.dataset.theme;
    return t || (media.matches ? 'dark' : 'light');
  }
  function syncThemeIcon() {
    const use = $('#theme-btn use');
    use.setAttribute('href', effectiveTheme() === 'dark' ? '#i-sun' : '#i-moon');
  }
  function setTheme(t) {
    if (t === 'light' || t === 'dark') document.documentElement.dataset.theme = t;
    else delete document.documentElement.dataset.theme;
    store.set('cp-theme', t === 'system' ? null : t);
    syncThemeIcon();
  }
  $('#theme-btn').addEventListener('click', () => setTheme(effectiveTheme() === 'dark' ? 'light' : 'dark'));
  media.addEventListener('change', syncThemeIcon);
  setTheme(store.get('cp-theme') || 'system');

  // ---------- Boot ----------

  (async () => {
    try {
      showApp(await api('/auth/me'));
    } catch {
      showLogin();
    }
  })();
})();
