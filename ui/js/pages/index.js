'use strict';
// Route table. Each route: title, render(view, params), icon, section (nav group), admin (admin-only).
import { renderOverview } from './overview.js';
import { renderSites } from './sites.js';
import { renderDocker } from './docker.js';
import { renderFirewall } from './firewall.js';
import { renderCron } from './cron.js';
import { renderSettings } from './settings.js';
import { renderServices } from './services.js';
// Site detail tabs register themselves.
import './site-files.js';
import './site-databases.js';
import './site-backups.js';

export const ROUTES = {
  overview: { title: 'Overview', render: renderOverview, icon: 'overview', section: '' },
  sites: { title: 'Sites', render: renderSites, icon: 'globe', section: '' },
  services: { title: 'Services', render: renderServices, icon: 'server', section: 'Server', admin: true },
  firewall: { title: 'Firewall', render: renderFirewall, icon: 'shield', section: 'Server', admin: true },
  cron: { title: 'Cron jobs', render: renderCron, icon: 'clock', section: 'Server', admin: true },
  docker: { title: 'Containers', render: renderDocker, icon: 'box', section: 'Server', admin: true },
  settings: { title: 'Settings', render: renderSettings, icon: 'settings', section: 'Admin' },
};

export const NAV_ORDER = ['overview', 'sites', 'services', 'firewall', 'security', 'cron', 'docker', 'users', 'events', 'alerts', 'settings'];
