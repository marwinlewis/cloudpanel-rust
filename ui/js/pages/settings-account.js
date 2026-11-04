'use strict';
import { api, card, confirmDialog, copyButton, field, formDialog, h, hooks, icon, openDialog, state, svgEl, toast, withBusy } from '../core.js';
import { SETTINGS_CARDS } from './settings.js';

/** Draw a QR module matrix ('1' = dark) as an SVG element. */
function qrSvg(width, modules) {
  const quiet = 2;
  const size = width + quiet * 2;
  const svg = svgEl('svg', { viewBox: `0 0 ${size} ${size}`, 'shape-rendering': 'crispEdges', role: 'img', 'aria-label': 'QR code' });
  let d = '';
  for (let y = 0; y < width; y++) {
    for (let x = 0; x < width; x++) {
      if (modules[y * width + x] === '1') d += `M${x + quiet},${y + quiet}h1v1h-1z`;
    }
  }
  svg.append(svgEl('path', { d, fill: '#000' }));
  return h('div', { class: 'qr' }, svg);
}

function showRecoveryCodes(codes) {
  const text = codes.join('\n');
  const done = h('button', { class: 'btn primary', type: 'button', text: 'I saved these codes' });
  const d = openDialog({
    title: 'Recovery codes',
    description: 'Each code signs you in once if you lose your authenticator. Store them somewhere safe; they are not shown again.',
    body: h('div', { class: 'form' }, h('div', { class: 'codes mono' }, codes.map((c) => h('span', { text: c }))), h('div', { class: 'row' }, copyButton(text), h('span', { class: 'small muted', text: 'Copy all' }))),
    footer: [done],
  });
  done.addEventListener('click', d.close);
}

function twoFactorCard() {
  const body = h('div', { class: 'form' });
  const draw = () => {
    const u = state.user;
    if (u.totp_enabled) {
      const regen = h('button', { class: 'btn', type: 'button' }, icon('refresh'), 'New recovery codes');
      regen.addEventListener('click', () => formDialog({
        title: 'Generate new recovery codes', description: 'Your old codes stop working.', submitText: 'Generate',
        content: [field({ label: 'Current password', name: 'password', type: 'password', validate: 'required', attrs: { autocomplete: 'current-password' } })],
        async onSubmit(d) { const r = await api('/auth/2fa/recovery-codes', { method: 'POST', body: d }); showRecoveryCodes(r.recovery_codes); },
      }));
      const off = h('button', { class: 'btn danger', type: 'button' }, 'Turn off');
      off.addEventListener('click', () => formDialog({
        title: 'Turn off two-factor authentication?', submitText: 'Turn off',
        content: [field({ label: 'Current password', name: 'password', type: 'password', validate: 'required', attrs: { autocomplete: 'current-password' } })],
        async onSubmit(d) { await api('/auth/2fa/disable', { method: 'POST', body: d }); await hooks.refreshUser(); toast('Two-factor authentication turned off'); draw(); },
      }));
      body.replaceChildren(
        h('div', { class: 'row' }, h('span', { class: 'badge ok' }, icon('lock'), 'Enabled'), h('span', { class: 'small muted', text: `${u.recovery_codes_left} recovery code${u.recovery_codes_left === 1 ? '' : 's'} left` })),
        h('div', { class: 'row wrap' }, regen, off));
    } else {
      const on = h('button', { class: 'btn primary', type: 'button' }, icon('lock'), 'Set up two-factor authentication');
      on.addEventListener('click', () => withBusy(on, enroll));
      body.replaceChildren(h('p', { class: 'muted small', text: 'Require a code from an authenticator app (Google Authenticator, 1Password, Authy, …) when signing in.' }), h('div', null, on));
    }
  };

  async function enroll() {
    const s = await api('/auth/2fa/setup', { method: 'POST' });
    const secret = h('code', { class: 'mono secret', text: s.secret.replace(/(.{4})/g, '$1 ').trim() });
    formDialog({
      title: 'Set up two-factor authentication', submitText: 'Verify & enable',
      content: [
        h('p', { class: 'muted small', text: '1. Scan this code with your authenticator app, or enter the key manually.' }),
        qrSvg(s.qr.width, s.qr.modules),
        h('div', { class: 'row' }, secret, copyButton(s.secret)),
        field({ label: '2. Enter the 6-digit code', name: 'code', validate: 'required', attrs: { inputmode: 'numeric', autocomplete: 'one-time-code', maxlength: 7, class: 'input mono' } }),
      ],
      async onSubmit(d) {
        const r = await api('/auth/2fa/enable', { method: 'POST', body: { code: d.code } });
        await hooks.refreshUser();
        draw();
        showRecoveryCodes(r.recovery_codes);
      },
    });
  }
  draw();
  return card({ title: 'Two-factor authentication', body });
}

function emailCard() {
  const form = h('form', { class: 'form', novalidate: true },
    field({ label: 'Email', name: 'email', type: 'email', value: state.user.email, validate: 'email' }),
    h('div', null, h('button', { class: 'btn', type: 'submit', text: 'Update email' })));
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    await withBusy(form.querySelector('button'), async () => {
      const r = await api('/auth/email', { method: 'POST', body: { email: form.elements.email.value.trim() } });
      await hooks.refreshUser();
      toast(r.message);
    });
  });
  return card({ title: 'Account', sub: `Role: ${state.user.role === 'admin' ? 'Administrator' : 'Site manager'}`, body: form });
}

SETTINGS_CARDS.push({ order: 1, column: 'left', render: twoFactorCard });
SETTINGS_CARDS.push({ order: 2, column: 'right', render: emailCard });

export { confirmDialog };
