# CloudPanel (Rust Edition)

A lightweight, self-contained server control panel written in Rust. One static binary serves the web UI and API and manages everything a VPS needs: sites with their own Linux users, supervised Node.js/Python apps, nginx, Let's Encrypt, databases, files, backups, services, updates, Docker, the firewall, fail2ban, cron and alerts.

- **Single binary**: the UI is embedded with `rust-embed`, and there are no PHP, Node or Python runtimes to maintain.
- **Small footprint**: Tokio + Axum + embedded SQLite.
- **Secure defaults**: HTTPS out of the box, Argon2id passwords, optional TOTP 2FA, role-based access, an audit log, strict input validation and a strict Content-Security-Policy.

## Install on a VPS

Supported: **Debian 11 / 12 / 13** and **Ubuntu 22.04 / 24.04** on amd64 or arm64, on a fresh server with root access.

```bash
curl -fsSL https://raw.githubusercontent.com/marwinlewis/cloudpanel-rust/main/install.sh | sudo bash
```

The installer asks which database engines sites may use (MySQL/MariaDB, MongoDB, SQLite). To answer up front, for example with Docker as well:

```bash
curl -fsSL https://raw.githubusercontent.com/marwinlewis/cloudpanel-rust/main/install.sh | sudo bash -s -- --with-docker --databases mariadb,mongodb,sqlite
```

The installer:

1. Installs `nginx`, `certbot` (+ nginx plugin), `ufw`, `fail2ban`, `cron`, `openssl` and `unzip` with apt, plus the database engines you chose (MongoDB from the official repo.mongodb.org repository, with authorization enabled).
2. Downloads the latest release binary for your CPU and verifies its SHA-256 checksum. If no release exists, it builds from source, adding a temporary swap file on small servers.
3. Creates `/etc/cloudpanel/cloudpanel.env` (mode 600) and a self-signed TLS certificate for the panel.
4. Creates the `cloudpanel-users` / `cloudpanel-sftp` groups, a certbot hook that reloads nginx after renewals, and a hardened systemd service.
5. Opens SSH (detected from `sshd -T`), 80, 443 and the panel port in UFW *before* enabling it, so your SSH session stays up.
6. Prints the panel URL and a randomly generated admin password.

Then open `https://<server-ip>:8443`. Your browser will warn about the self-signed certificate until you issue a real one under **Settings → Panel certificate**.

### Options

| Flag | Description |
| :--- | :--- |
| `--version v0.2.0` | Install a specific release |
| `--from-source` | Build from source instead of downloading a binary |
| `--branch NAME` | Branch to build with `--from-source` (default `main`) |
| `--with-docker` | Install Docker Engine from the official docker.com repository |
| `--with-mariadb` | Install MariaDB (MySQL-compatible) for site databases |
| `--with-mongodb` | Install MongoDB Community (8.0; 7.0 on Debian 11; amd64 only on Debian) |
| `--with-sqlite` | Enable SQLite site databases |
| `--databases LIST` | Comma-separated `mariadb,mongodb,sqlite` (skips the question) |
| `--no-fail2ban` | Don't install fail2ban |
| `--port N` | Panel port (default `8443`) |
| `--no-firewall` | Don't touch UFW |
| `--force` | Try anyway on an untested Debian/Ubuntu derivative |
| `--uninstall` | Remove the binary and service (keeps data) |
| `--uninstall --purge` | Also delete `/var/lib/cloudpanel`, `/etc/cloudpanel` and the managed config files |

Pass flags after `bash -s --`, e.g. `... | sudo bash -s -- --port 9443`.

### Update or add a database engine

Run the same install command again. It replaces the binary, restarts the service, and keeps your data, secrets and certificate. Adding `--with-mariadb` / `--with-mongodb` / `--with-sqlite` installs and enables that engine.

### Forgot the admin password or lost your 2FA device?

```bash
sudo cloudpanel user-reset-password --username admin
sudo cloudpanel user-disable-2fa --username admin
```

## Features

**Sites**
- Node.js, Python, static sites, generic reverse proxies and Docker proxies, each with its own nginx vhost.
- Every site gets its own **Linux user** and home (`/home/<user>/htdocs/<domain>`). nginx reads static files through the site group.
- **App process manager**: the start command runs as the site user in a hardened systemd unit (`cloudpanel-app-<domain>`) with auto-restart, an environment editor, start/stop/restart, live journal output and an *Install dependencies* job (`npm ci` + build, or venv + `pip install -r`).
- **Site settings**: app port, `www.` alias, WebSocket support, upload limit, document root, enable/disable (maintenance page), HTTP basic auth with an IP allow-list, and custom nginx directives (admins only, checked with `nginx -t`).
- **SSL**: one-click Let's Encrypt or your own certificate, certificate details and expiry, renew now, disable HTTPS. HTTP redirects to HTTPS.
- **SSH/SFTP users** per site sharing the site's files, SFTP-only accounts (`internal-sftp`), passwords and authorized keys. Keys live in root-owned files, so a site cannot rewrite them.
- **File manager**: browse, edit, upload (up to 1 GB, drag and drop), download, rename/move, delete, chmod, and extract or compress archives. It is confined to the site home and safe against symlink escapes.
- **Databases**: MySQL/MariaDB, MongoDB and SQLite. Create databases and users, reset passwords (shown once, never stored), export/download and import dumps.
- **Backups**: files and database dumps as `tar.gz`, run now or on a daily/weekly schedule with retention, optional copies to S3-compatible storage (AWS, R2, B2, Wasabi, MinIO), download, and one-click restore. The panel can also back up itself.
- **Logs**: nginx access and error logs, app output, and the generated vhost.

**Server**
- **Services**: status and memory of nginx, SSH, cron, fail2ban, Docker, MariaDB/MySQL, MongoDB, UFW and site apps. Start, stop, restart and reload them, and read their journal.
- **Updates**: check for apt updates (security updates are flagged), install them all, and see when a reboot is required. You can reboot from the panel.
- **Firewall**: UFW port and port-range rules, optionally limited to a source IP/CIDR, and an IP block list. Rules that would block SSH or the panel for your own address are refused.
- **Security**: fail2ban jails for SSH and the panel login, with ban time, retries, an ignore list, ban/unban and live status.
- **Cron**: create, edit, pause and run jobs now. Every run's exit code and output are recorded, and jobs can be tied to a site and run as its user.
- **Containers**: list, start/stop/restart, logs, stats and removal. Run new containers from a form (ports are bound to 127.0.0.1 by default), manage images (pull/remove/prune), handle Docker Compose stacks, and expose a container on a domain.
- **Overview**: live CPU, memory, disk and network graphs, top processes, public IPs and pending updates.

**Administration**
- **Users**: administrators and site managers. Site managers only see and manage the sites assigned to them.
- **Two-factor authentication** (TOTP) with QR enrollment and single-use recovery codes.
- **Events**: audit log of sign-ins and every change, with filters and CSV export (kept 90 days).
- **Alerts**: email (SMTP), Slack, Discord or JSON webhooks for high disk/CPU/memory, expiring certificates, stopped services or apps, failed backups and security events.
- **Panel certificate**: issue a Let's Encrypt certificate for the panel hostname. It is hot-reloaded and renewed automatically.

## Security model

| Area | What CloudPanel does |
| :--- | :--- |
| Transport | Serves HTTPS natively (rustls). HSTS when TLS is on. The panel certificate can be swapped for Let's Encrypt without a restart. |
| Authentication | Argon2id password hashes and constant-time handling of unknown users. Optional TOTP 2FA with single-use recovery codes. Per-IP lockout after 5 failed logins in 15 minutes, plus fail2ban on `/var/log/cloudpanel/auth.log`. |
| Sessions | HS256 JWT in an `HttpOnly; Secure; SameSite=Strict` cookie, 12-hour lifetime. The signing key is random per install. Changing the password or role, or choosing "Sign out everywhere", revokes all tokens. The token between the password and 2FA steps is short-lived and can never be used as a session. |
| Authorization | Admins manage the server. Site managers can only reach assigned sites; other sites answer 404. Custom nginx directives, Docker, services, firewall and users are admin-only. |
| CSRF | State-changing requests need a custom header and a same-origin `Origin`/`Sec-Fetch-Site`. No CORS. |
| Input | Domains, ports, emails, users, keys, CIDRs, database identifiers, image names, paths and cron schedules are validated against strict allow-lists before they reach a config file, the filesystem or a command line. Commands run via `execve`, never through a shell (cron commands and app start commands are deliberately run by `/bin/sh` as the configured user). |
| nginx / sshd / fail2ban | Every change is tested (`nginx -t`, `sshd -t`, `fail2ban-client -t`) and rolled back if rejected. |
| Secrets | Database and SSH passwords are never stored. S3 keys, SMTP passwords and webhook URLs are encrypted with ChaCha20-Poly1305 using a key in `/etc/cloudpanel/secret.key` (mode 600). |
| Browser | Strict CSP (`default-src 'self'`, no inline scripts or styles), `X-Frame-Options: DENY` and `nosniff`. The UI never inserts server data as HTML; the 2FA QR code is drawn from a module matrix. |
| Audit | Sign-ins (including failures) and every change are recorded with user, IP and time. |
| Service | Runs as root, because it manages users, nginx, certbot, ufw, cron and systemd. It runs under systemd hardening (`NoNewPrivileges`, `ProtectSystem=full`) with write access only to the paths it manages. Tools that must rewrite `/etc/passwd` or `/usr` (`useradd`, `apt-get`) run in transient units via `systemd-run`. Site apps run as their site user with `ProtectSystem=strict`. |

> **The panel is root-equivalent.** Any administrator can run commands as any user through cron jobs, containers and custom nginx directives. Use strong passwords, enable 2FA, and consider limiting the panel port to your IP: `ufw delete allow 8443/tcp && ufw allow from <your-ip> to any port 8443 proto tcp`.

> **Docker and UFW:** ports published by Docker on 0.0.0.0 bypass UFW. The panel binds published ports to `127.0.0.1` by default. Expose containers through a site instead.

## Configuration

Settings are read from the environment. The installer writes them to `/etc/cloudpanel/cloudpanel.env`.

| Variable | Default (Linux) | Description |
| :--- | :--- | :--- |
| `CLOUDPANEL_BIND` | `0.0.0.0:8443` | Listen address |
| `CLOUDPANEL_DATA_DIR` | `/var/lib/cloudpanel` | Database, JWT key, uploaded certificates, compose stacks |
| `CLOUDPANEL_DB_PATH` | `$DATA_DIR/cloudpanel.db` | SQLite database file |
| `CLOUDPANEL_TLS_CERT` / `CLOUDPANEL_TLS_KEY` | unset (plain HTTP) | PEM certificate and key for the panel (a Let's Encrypt panel certificate overrides these) |
| `CLOUDPANEL_JWT_SECRET` | generated | Override the signing key (32+ characters) |
| `CLOUDPANEL_DB_ENGINES` | set by the installer | Enabled site database engines: `mariadb,mongodb,sqlite` |
| `CLOUDPANEL_HOME_DIR` | `/home` | Parent of site users' homes |
| `CLOUDPANEL_SITES_DIR` | `/var/www` | Document roots of sites created before v0.3 |
| `CLOUDPANEL_BACKUP_DIR` | `/var/backups/cloudpanel` | Backups and database exports |
| `CLOUDPANEL_ETC_DIR` | `/etc/cloudpanel` | App env files, htpasswd files, encryption key, MongoDB credentials |
| `CLOUDPANEL_LOG_DIR` | `/var/log/cloudpanel` | Panel auth log (read by fail2ban) |
| `CLOUDPANEL_SYSTEMD_DIR` | `/etc/systemd/system` | Where app units are written |
| `CLOUDPANEL_STACKS_DIR` | `$DATA_DIR/stacks` | Docker Compose stacks |
| `CLOUDPANEL_NGINX_AVAILABLE` / `_ENABLED` | `/etc/nginx/sites-{available,enabled}` | nginx vhost directories |
| `CLOUDPANEL_NGINX_LOG_DIR` | `/var/log/nginx` | Per-site access and error logs |
| `CLOUDPANEL_FAIL2BAN_DIR` | `/etc/fail2ban` | fail2ban configuration root |
| `CLOUDPANEL_SSHD_DIR` | `/etc/ssh/sshd_config.d` | sshd drop-in directory (SFTP-only users) |
| `CLOUDPANEL_CRON_FILE` | `/etc/cron.d/cloudpanel` | Generated crontab |

Scheduled backups use UTC times. Restoring a **panel** backup is manual: stop the service, extract the archive and put `cloudpanel.db`, `/etc/cloudpanel`, the vhosts and the cron file back in place.

## CLI

```bash
cloudpanel server                                   # start (default)
cloudpanel user-add --username alice --email alice@example.com   # prompts for password
cloudpanel user-reset-password --username admin     # prompts for password, signs out sessions
cloudpanel user-disable-2fa --username admin        # turn off 2FA (lost device)
cloudpanel site-add --domain api.example.com --site-type nodejs --port 3000 [--www]
cloudpanel site-list
cloudpanel cron-run <id>                            # used by /etc/cron.d/cloudpanel
```

The old `user:add`-style names still work as aliases.

## Development

```bash
cargo run            # http://localhost:8443, data stored in ./data
cargo test
cargo clippy --all-targets -- -D warnings
```

On Windows and in local development, system tools (nginx, ufw, certbot, systemctl, useradd, …) are skipped when they aren't installed, and configs are written under `./data`. The UI lives in `ui/` as plain ES modules (`ui/js/core.js` for shared helpers, one module per page under `ui/js/pages/`).

### Releasing

Push a tag such as `v0.3.0`. The release workflow builds static musl binaries for x86_64 and aarch64, publishes them with `.sha256` checksums, and the installer picks them up automatically.

## License

MIT
