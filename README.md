# CloudPanel (Rust Edition)

A lightweight, self-contained server control panel written in Rust. One static binary serves the web UI and API, manages nginx virtual hosts, Let's Encrypt certificates, Docker containers, UFW firewall rules and cron jobs.

- **Single binary**: the UI is embedded with `rust-embed`, and there are no PHP, Node or Python runtimes to maintain.
- **Small footprint**: Tokio + Axum + embedded SQLite.
- **Secure defaults**: HTTPS out of the box, Argon2id passwords, hardened sessions, strict input validation, and a strict Content-Security-Policy.

## Install on a VPS

Supported: **Debian 11 / 12 / 13** and **Ubuntu 22.04 / 24.04** on amd64 or arm64, on a fresh server with root access.

```bash
curl -fsSL https://raw.githubusercontent.com/marwinlewis/cloudpanel-rust/main/install.sh | sudo bash
```

With Docker Engine as well:

```bash
curl -fsSL https://raw.githubusercontent.com/marwinlewis/cloudpanel-rust/main/install.sh | sudo bash -s -- --with-docker
```

The installer:

1. Installs `nginx`, `certbot` (+ nginx plugin), `ufw`, `cron` and `openssl` with apt.
2. Downloads the latest release binary for your CPU and verifies its SHA-256 checksum. If no release exists, it builds from source, adding a temporary swap file on small servers.
3. Creates `/etc/cloudpanel/cloudpanel.env` (mode 600) and a self-signed TLS certificate for the panel.
4. Installs a hardened systemd service and starts it.
5. Opens SSH (detected from `sshd -T`), 80, 443 and the panel port in UFW *before* enabling it, so your SSH session stays up.
6. Prints the panel URL and a randomly generated admin password.

Then open `https://<server-ip>:8443`. Your browser will warn about the self-signed certificate once.

### Options

| Flag | Description |
| :--- | :--- |
| `--version v0.2.0` | Install a specific release |
| `--from-source` | Build from source instead of downloading a binary |
| `--branch NAME` | Branch to build with `--from-source` (default `main`) |
| `--with-docker` | Install Docker Engine from the official docker.com repository |
| `--port N` | Panel port (default `8443`) |
| `--no-firewall` | Don't touch UFW |
| `--force` | Try anyway on an untested Debian/Ubuntu derivative |
| `--uninstall` | Remove the binary and service (keeps data) |
| `--uninstall --purge` | Also delete `/var/lib/cloudpanel`, `/etc/cloudpanel` and the cron file |

Pass flags after `bash -s --`, e.g. `... | sudo bash -s -- --port 9443`.

### Update

Run the same install command again. It replaces the binary, restarts the service, and keeps your data, secrets and certificate.

### Forgot the admin password?

```bash
sudo cloudpanel user-reset-password --username admin
```

## Features

- **Sites**: Node.js, Python, static sites and generic reverse proxies, each with its own nginx vhost. Optional `www.` alias, websocket support and security headers.
- **SSL**: one-click Let's Encrypt via certbot, or upload your own certificate. HTTP redirects to HTTPS.
- **Containers**: list, start, stop, restart and view logs for Docker containers, and expose a container on a domain in one step.
- **Firewall**: add and remove UFW allow/deny rules. Denying SSH or the panel port is refused, so you can't lock yourself out.
- **Cron**: scheduled jobs written to `/etc/cron.d/cloudpanel`, with presets and a readable schedule preview.
- **Overview**: live CPU, memory, disk and network graphs, plus the top processes.

## Security model

| Area | What CloudPanel does |
| :--- | :--- |
| Transport | Serves HTTPS natively (rustls). HSTS when TLS is on. |
| Authentication | Argon2id password hashes and constant-time handling of unknown users. Per-IP lockout after 5 failed logins in 15 minutes. |
| Sessions | HS256 JWT in an `HttpOnly; Secure; SameSite=Strict` cookie, 12-hour lifetime. The signing key is random per install (`/var/lib/cloudpanel/jwt.secret`, mode 600). Changing the password or choosing "Sign out everywhere" revokes all tokens. |
| CSRF | State-changing requests need a custom header and a same-origin `Origin`/`Sec-Fetch-Site`. No CORS. |
| Input | Domains, ports, emails, users, container ids, cron schedules and paths are validated against strict allow-lists before they reach nginx configs, the filesystem or a command line. Commands run via `execve`, never through a shell. |
| nginx | Every change is checked with `nginx -t`. A failing config is rolled back before reload. |
| Browser | Strict CSP (`default-src 'self'`, no inline scripts), `X-Frame-Options: DENY` and `nosniff`. The UI never inserts server data as HTML. |
| Files | The database, JWT key, initial password and private keys are mode 600. |
| Service | Runs as root, because it manages nginx, certbot, ufw and cron, under systemd hardening (`NoNewPrivileges`, `ProtectSystem=full` with write access only to the paths it manages). |

> **Cron jobs and the panel are root-equivalent.** Anyone with an admin login can run commands as any user. Use a strong password, and consider limiting the panel port to your IP: `ufw delete allow 8443/tcp && ufw allow from <your-ip> to any port 8443 proto tcp`.

> **Docker and UFW:** ports published by Docker bypass UFW. Bind containers to `127.0.0.1` (`-p 127.0.0.1:8080:80`) and expose them through a site.

## Configuration

Settings are read from the environment. The installer writes them to `/etc/cloudpanel/cloudpanel.env`.

| Variable | Default (Linux) | Description |
| :--- | :--- | :--- |
| `CLOUDPANEL_BIND` | `0.0.0.0:8443` | Listen address |
| `CLOUDPANEL_DATA_DIR` | `/var/lib/cloudpanel` | Database, JWT key, uploaded certificates |
| `CLOUDPANEL_DB_PATH` | `$DATA_DIR/cloudpanel.db` | SQLite database file |
| `CLOUDPANEL_TLS_CERT` / `CLOUDPANEL_TLS_KEY` | unset (plain HTTP) | PEM certificate and key for the panel |
| `CLOUDPANEL_JWT_SECRET` | generated | Override the signing key (32+ characters) |
| `CLOUDPANEL_SITES_DIR` | `/var/www` | Base directory for static site files |
| `CLOUDPANEL_NGINX_AVAILABLE` | `/etc/nginx/sites-available` | nginx vhost directory |
| `CLOUDPANEL_NGINX_ENABLED` | `/etc/nginx/sites-enabled` | nginx enabled-sites directory |
| `CLOUDPANEL_CRON_FILE` | `/etc/cron.d/cloudpanel` | Generated crontab |

To use a real certificate for the panel itself, point `CLOUDPANEL_TLS_CERT`/`CLOUDPANEL_TLS_KEY` at it (e.g. a Let's Encrypt `fullchain.pem`/`privkey.pem`) and run `systemctl restart cloudpanel`.

## CLI

```bash
cloudpanel server                                   # start (default)
cloudpanel user-add --username alice --email alice@example.com   # prompts for password
cloudpanel user-reset-password --username admin     # prompts for password, signs out sessions
cloudpanel site-add --domain api.example.com --site-type nodejs --port 3000 [--www]
cloudpanel site-list
```

The old `user:add`-style names still work as aliases.

## Development

```bash
cargo run            # http://localhost:8443, data stored in ./data
cargo test
cargo clippy --all-targets -- -D warnings
```

On Windows and in local development, nginx/ufw/certbot calls are skipped when the tools aren't installed, and configs are written under `./data`.

### Releasing

Push a tag such as `v0.2.0`. The release workflow builds static musl binaries for x86_64 and aarch64, publishes them with `.sha256` checksums, and the installer picks them up automatically.

## License

MIT
