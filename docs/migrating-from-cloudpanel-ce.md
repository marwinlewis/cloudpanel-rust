# Migrating from CloudPanel CE

`migrate-from-ce.sh` moves a server from [CloudPanel CE](https://www.cloudpanel.io) to this panel, in place, without taking its sites down.

## How it stays up

CE runs its panel separately from what serves your sites, which is what makes this possible:

| | Services | During the migration |
| :--- | :--- | :--- |
| **Sites** | `nginx`, `php*-fpm`, `mysql`/`mariadb`, Varnish, Redis, ProFTPD | Never restarted, reconfigured or upgraded |
| **CE's panel** | `clp-nginx`, `clp-php-fpm`, `clp-agent` (port 8443) | Stopped at cutover |
| **New panel** | `cloudpanel` | Runs next to CE on port 8442, then moves to 8443 |

Only the panel changes hands. Each step compares config hashes, process IDs and each site's response with how they were before, and stops if a site got worse.

Imported sites keep their exact nginx config. This panel can't reproduce what CE generates, so it never rewrites an imported site's vhost, and it refuses changes that would.

## Before you start

- Take a snapshot of the server at your hosting provider, if you can. The script backs up the panel database and the nginx, PHP and cron config, but not your sites or databases.
- Have root SSH access. The panel may be briefly unreachable at cutover, but SSH and the sites aren't affected.
- Reach the new panel during `prepare` through port 8442. CE's UFW rules allow it, but a firewall at your hosting provider may not. If so, use a tunnel: `ssh -L 8442:127.0.0.1:8442 root@your-server`.

## Steps

Get the scripts onto the server:

```bash
curl -fsSLO https://raw.githubusercontent.com/marwinlewis/cloudpanel-rust/main/migrate-from-ce.sh
curl -fsSLO https://raw.githubusercontent.com/marwinlewis/cloudpanel-rust/main/install.sh
```

### 1. Check the server

Changes nothing, and tells you what it found:

```bash
sudo bash migrate-from-ce.sh preflight
```

### 2. Prepare

Installs the new panel on port 8442 and imports sites, databases and users. CE stays in charge. If the server has PHP sites, you're asked whether the new panel should manage them, or you can say so with `--with-php` or `--no-php`. They keep running either way.

```bash
sudo bash migrate-from-ce.sh prepare
```

It prints the new panel's address and `admin` password. Sign in and look around. It's safe to leave the server like this for as long as you like, and running `prepare` again is safe.

### 3. Cut over

Moves the new panel to port 8443 and stops CE's panel. Sites added in CE since `prepare` are imported first. If the new panel doesn't come up, or a site got worse, the script goes back to CE by itself.

```bash
sudo bash migrate-from-ce.sh cutover
```

Afterwards, the new panel is at `https://your-server:8443`:

- `admin`'s password is in `/var/lib/cloudpanel/initial_admin_password`.
- CE's users have new passwords, in `/var/lib/cloudpanel-migration/panel-users.txt`. CE's password hashes can't be reused, and 2FA has to be set up again.

### Going back

Works at any later time, and doesn't touch the sites:

```bash
sudo bash migrate-from-ce.sh rollback
```

Changes made in the new panel since the cutover stay in the new panel, and CE won't know about them. `sudo bash migrate-from-ce.sh status` shows where things stand.

## What moves, and what doesn't

| | After the migration |
| :--- | :--- |
| Sites | In the panel. Node.js, Python, static and reverse proxy always; PHP if you chose it. Otherwise PHP sites keep running without appearing in the panel. |
| Site files, Linux users | Unchanged |
| Databases and their users | Listed in the panel. The data and passwords don't change. |
| Panel users | Imported with new passwords and without 2FA |
| Certificates | Unchanged, and still renewed by CE's nightly job. See below. |
| Cron jobs | Keep running from the site users' crontabs, but the panel doesn't list them |
| FTP users | Keep working through ProFTPD, but the panel doesn't list them |
| Firewall rules | Stay in UFW |
| Basic auth, Varnish, PageSpeed, vhost edits | Keep working, because they're in the vhost. The panel doesn't show them. |
| Node.js and Python apps | Keep running as they were. The panel doesn't start or manage them, so they show as not configured. |
| CE's panel settings (its own domain, basic auth, API tokens) | Not carried over. Set up the panel's hostname under **Settings → Panel certificate**. |

## Afterwards

- **Imported sites' nginx settings are read-only in the panel.** Port, www, upload limit, certificates, password protection, custom directives and disabling the site would all regenerate the vhost, so they aren't offered. Files, databases, SSH users, logs and backups work as usual. To change a setting, edit `/etc/nginx/sites-enabled/<domain>.conf` on the server, run `nginx -t`, then `systemctl reload nginx`.
- **Deleting an imported site really deletes it**, including its vhost, and rolling back won't bring it back.
- **Keep the `cloudpanel` apt package installed.** It's held, so an upgrade can't restart CE's panel, and removing it would stop certificate renewal and rollback.
- **Don't remove `/etc/cron.d/clp`.** It renews your certificates and takes CE's nightly database backups. Only the line restarting `clp-agent` is disabled.
- **New sites you add are fully managed**, including PHP sites if you enabled PHP, with Let's Encrypt through certbot.

## What hasn't been tested

The end-to-end test runs against a real CE install, but it has limits. Check these yourself on a real server:

- **Certificate renewal after the cutover.** The test install has no public domain, so CE's renewal job was run with the panel stopped but had nothing to renew. **Before relying on it, run this on the server and check for errors:** `su -s /bin/bash -c '/usr/bin/clpctl lets-encrypt:renew:certificates' clp`. Check the expiry dates later too. The panel's alerts cover expiring certificates, but only once you've set up a channel under **Alerts**.
- **Let's Encrypt for new sites on a migrated server.** certbot's nginx plugin reads CE's nginx config, which includes things like `listen 443 quic`. This needs a public domain to test.
- **Other platforms.** Tested on Debian 13 with CE's default MySQL 8.4 only. Ubuntu, other Debian versions and MariaDB should behave the same, as the script doesn't depend on them, but they haven't been run.
- **Large or busy servers.** The test server has five small sites.

## Testing the migration

```bash
scripts/debian-e2e/build-ce-image.sh    # once: installs real CE in a container, about 45 minutes
scripts/debian-e2e/run-migrate.sh       # everything, about 5 minutes
```

A second container requests every site several times a second for the whole run, so a moment of downtime fails the test. The run covers prepare, a cutover with a deliberately broken panel, a real cutover, a rollback, a second cutover and a reboot, with and without PHP, and PHP on a server that never had CE.

Only run the migration on a real server after trying it on a copy of that server, if you can make one. Most providers can create one from a snapshot.
