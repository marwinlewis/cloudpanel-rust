'use strict';
import {
  $, ApiError, DOMAIN_RE, PROPS, SVG_NS, VALIDATORS, api, append, card, closeMenu, confirmDialog, effectiveTheme, emptyState, errorState, field, fmtAgo, fmtBytes, fmtDate, fmtPct, fmtRate, fmtUptime, formData, formDialog, h, hooks, icon, isAdmin, media, moreButton, openDialog, openMenu, openMenuEl, rtf, selectField, setActions, setHost, setSub, setTheme, skeletonRows, spinner, state, store, svgEl, syncThemeIcon, table, toast, validateForm, withBusy,
} from '../core.js';

// ---------- Sites ----------

const SITE_TYPES = {
  nodejs: { label: 'Node.js', desc: 'Next.js, Express, Nuxt' },
  python: { label: 'Python', desc: 'FastAPI, Django, Flask' },
  static: { label: 'Static', desc: 'HTML, Vite, SPA builds' },
  reverse_proxy: { label: 'Reverse proxy', desc: 'Any local HTTP service' },
  docker_proxy: { label: 'Docker', desc: 'Container port' },
};

export function renderSites(view) {
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
