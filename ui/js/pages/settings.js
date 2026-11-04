'use strict';
import {
  $, ApiError, DOMAIN_RE, PROPS, SVG_NS, VALIDATORS, api, append, card, closeMenu, confirmDialog, effectiveTheme, emptyState, errorState, field, fmtAgo, fmtBytes, fmtDate, fmtPct, fmtRate, fmtUptime, formData, formDialog, h, hooks, icon, isAdmin, media, moreButton, openDialog, openMenu, openMenuEl, rtf, selectField, setActions, setHost, setSub, setTheme, skeletonRows, spinner, state, store, svgEl, syncThemeIcon, table, toast, validateForm, withBusy,
} from '../core.js';

// ---------- Settings ----------

export function renderSettings(view) {
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
    await withBusy(signOutAll, async () => { await api('/auth/logout-all', { method: 'POST' }); hooks.showLogin(); });
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
