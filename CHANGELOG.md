# Changelog

All notable changes to the [CloudPanel (Rust Edition)](https://github.com/marwinlewis/cloudpanel-rust) project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release descriptions and downloadable binaries are also published to the [GitHub Releases](https://github.com/marwinlewis/cloudpanel-rust/releases) page.

---

## [Unreleased]

### Added
- Automated changelog extraction and release synchronization scripts (`scripts/extract-changelog.py`, `scripts/sync-release-notes.py`).
- Automatic release notes generation configuration for GitHub (`.github/release.yml`).

---

## [v0.4.4] - 2026-11-22

### Added
- **Email Service Management UI**: Built a dedicated web interface (`ui/js/pages/email.js`) to configure and inspect mail domains, mailboxes, DKIM keys, and DNS verification records.
- **Mail API Handlers & Service**: Added backend handlers and management service (`src/api/mail_handlers.rs`, `src/mail/manage.rs`) for mailbox provisioning, password updates, quota control, and DKIM generation.
- **Mail Integration & End-to-End Tests**: Added automated unit and integration tests (`src/api/mail_tests.rs`) along with a full Debian mail test harness (`scripts/debian-e2e/mail-e2e.sh`, `scripts/debian-e2e/run-mail.sh`).
- **Site Management Frontend Enhancements**: Added site management handlers and frontend enhancements for custom domain settings and site configuration (`src/api/site_handlers.rs`, `ui/js/pages/sites.js`).
- **Full-Spectrum Debian E2E Test Suite**: Enhanced `scripts/debian-e2e/e2e.sh` to validate all CloudPanel services, lifecycle actions, and permissions in real Debian environments.

### Fixed
- **Insecure Direct Object Reference (IDOR) Hardening**: Added explicit IDOR security tests and access checks ensuring site managers cannot access or modify sites or cron jobs outside their granted scope (`src/api/security_tests/idor.rs`).

### Security
- **Dependency Audit & Policy Hardening**: Updated Cargo dependencies and tuned security policies (`.cargo/audit.toml`, `deny.toml`).

---

## [v0.4.3] - 2026-11-17

### Added
- **CloudPanel CE Database Import**: Added a dedicated migration import service (`src/services/ce_import.rs`) to automatically migrate MySQL/MariaDB databases and users from existing CloudPanel Community Edition installations.
- **SSH & SFTP User Management Handlers**: Implemented dedicated API handlers and system integration services (`src/services/sysusers.rs`, `src/api/ssh_handlers.rs`) for managing site-scoped SSH/SFTP users.

### Fixed
- **System Group Resolution in Installer**: Improved group resolution and permission assignments during install and user provisioning, preventing permission conflicts when creating multiple SFTP users under a site group.

---

## [v0.4.2] - 2026-11-16

### Added
- **GitHub Actions Self-Hosted Runners**:
  - Full management for self-hosted GitHub Actions runners directly from the control panel (`src/services/runners.rs`, `src/api/runner_handlers.rs`).
  - Added dedicated UI page (`ui/js/pages/runners.js`) showing runner connectivity, labels, execution environment, and live runner service logs.
  - Added SQLite schema migrations, data models, and token validation for runner registration (`src/db/models.rs`, `src/validate.rs`).
  - Added comprehensive Debian end-to-end runner test suite (`scripts/debian-e2e/runners-e2e.sh`, `scripts/debian-e2e/run-runners.sh`).

### Changed
- Updated API security route matrix and test suite to include GitHub Actions runner endpoints.

---

## [v0.4.1] - 2026-11-16

### Added
- **Integrated Email Sending Service (`src/mail/`)**:
  - Embedded high-performance SMTP server and HTTP submission API (`src/mail/smtp.rs`, `src/mail/http.rs`, `src/mail/serve.rs`).
  - Automated 2048-bit RSA DKIM key pair generation and automatic message signing (`src/mail/dkim.rs`, `src/mail/keys.rs`).
  - Complete DNS record generator for SPF, DKIM, DMARC, and MX records (`src/mail/dns.rs`).
  - Postfix MTA automated installation and configuration with Sender Rewriting Scheme (SRS) support (`src/mail/install.rs`).
  - Deliverability tracking and mail event storage (`src/mail/events.rs`, `src/mail/store.rs`).
  - Command-line administration via `cloudpanel mail` CLI (`src/mail/cli.rs`).
  - Debian end-to-end automated email test suite (`scripts/debian-e2e/mail-e2e.sh`).

### Changed
- Added `--with-mail` option to `install.sh` for optional mail stack provisioning.

---

## [v0.4.0] - 2026-11-15

### Added
- **Overhauled Firewall Management**:
  - Redesigned Firewall UI (`ui/js/pages/firewall.js`) with support for port ranges (e.g. `3000:3010`), CIDR source network filtering, and rule prioritization.
  - Enhanced backend firewall API handlers (`src/api/firewall_handlers.rs`) with strict port and IP validation.
- **System Services Management UI**:
  - Real-time status cards and controls for systemd units (Nginx, SSH, Cron, Fail2ban, Docker, Databases) with journal log streaming (`ui/js/pages/services.js`).
- **Automatic Panel Updates UI**:
  - Added schedule controls and status cards in the UI for configuring automatic panel update checks and overnight upgrades (`src/services/panel_update.rs`).

---

## [v0.3.9] - 2026-11-14

### Added
- **Panel Auto-Update & Upgrade Service**:
  - Automated version check querying GitHub Releases API (`https://api.github.com/repos/marwinlewis/cloudpanel-rust/releases/latest`).
  - One-click panel upgrade via transient systemd service (`cloudpanel-upgrade`).
  - Health check verification with automatic fallback: rolls back to the previous binary if the upgraded panel fails to stay running for 30 seconds.
  - Background auto-update scheduler configured for low-traffic hours.

### Changed
- Improved Nginx template generation and site update handlers (`src/api/site_handlers.rs`, `src/services/nginx.rs`).

---

## [v0.3.8] - 2026-11-12

### Added
- **Site-Scoped Docker Management**:
  - Isolated Docker container and compose stack management mapped directly to individual site managers (`src/api/docker_handlers.rs`).
  - Added database schema updates and models for site-scoped Docker configurations.
  - Integrated Docker security policies into the route authorization matrix.

---

## [v0.3.7] - 2026-11-11

### Added
- **Garage S3 Object Storage Service**:
  - Integrated distributed, lightweight S3-compatible object storage service (`src/services/garage.rs`).
  - Storage UI for creating buckets, managing API access keys, and tracking storage cluster nodes (`ui/js/pages/storage.js`, `ui/js/pages/site-storage.js`).
- **WireGuard VPN Service**:
  - Built-in WireGuard VPN peer configuration and service management (`src/services/wireguard.rs`, `src/api/vpn_handlers.rs`, `ui/js/pages/vpn.js`).
  - Enables encrypted private administrative networking without opening administrative ports to the public internet.
- Automated Debian test scripts for Garage S3 and WireGuard (`scripts/debian-e2e/garage-e2e.sh`).

---

## [v0.3.6] - 2026-11-09

### Added
- **CloudPanel CE Migration Suite**:
  - Automated migration tool (`migrate-from-ce.sh`) and migration guide (`docs/migrating-from-cloudpanel-ce.md`).
  - Automated migration of vhosts, SSL certificates, databases, database users, and system users.
  - Integration testing harness with Pebble ACME server (`scripts/debian-e2e/migrate-e2e.sh`).
- Added UI preview screenshots to `README.md`.

### Changed
- Upgraded `rusqlite` dependency and introduced transactional SQLite helpers (`src/db/mod.rs`).

---

## [v0.3.5] - 2026-11-08

### Added
- **Security Hardening & RBAC Audit**:
  - Route authorization test matrix validating all endpoints against unauthenticated and cross-role requests (`src/api/security_tests/route_matrix.rs`).
  - Automated IDOR tests (`src/api/security_tests/idor.rs`) and session isolation tests (`src/api/security_tests/session.rs`).
  - Automated end-to-end security test runner (`scripts/debian-e2e/security.sh`).
- Enhanced Nginx vhost generation service (`src/services/nginx.rs`).
- Added Cargo audit and security policies configuration (`deny.toml`).

---

## [v0.3.4] - 2026-11-06

### Added
- **Panel SSL Certificate Management**:
  - Support for custom Let's Encrypt and self-signed TLS certificates for the panel domain (`src/services/panel_cert.rs`).
  - Dedicated Panel Certificate settings UI in `ui/js/pages/settings-panel.js`.
- Alert handler API endpoints and tests for webhooks, Slack, Discord, and SMTP notifications (`src/api/alert_handlers.rs`).
- Expanded Debian end-to-end test suite for site lifecycle and configuration.

---

## [v0.3.3] - 2026-11-06

### Added
- **PM2 Process Manager Integration**:
  - Native supervision of Node.js sites using PM2 process manager.
  - Application lifecycle controls (start, stop, restart, delete, status).
- Expanded Debian 12 end-to-end test runner (`scripts/debian-e2e/e2e.sh`, `scripts/debian-e2e/run.sh`).
- Added database models for application runtime configurations.

---

## [v0.3.2] - 2026-11-05

### Added
- **Node.js Site Hosting**:
  - Node.js runtime detection and process supervision (`src/services/runtimes.rs`).
  - Application handlers for Node.js dependency installation and execution (`src/api/app_handlers.rs`).

### Fixed
- Fixed `install.sh` to ensure the downloaded binary is marked executable (`chmod 0755`) and improved execution check diagnostics.

---

## [v0.3.1] - 2026-11-05

### Added
- **CI / CD Automation**:
  - Local containerized CI testing environment (`scripts/ci-local.Dockerfile`, `scripts/ci-local.sh`).
  - GitHub Actions CI workflow for Rust formatting, clippy, tests, and shell scripts (`.github/workflows/ci.yml`).
  - GitHub Actions Release workflow with cross-compilation for `x86_64` and `aarch64` musl static targets (`.github/workflows/release.yml`).
- **Secure File System Service**:
  - Implemented `SiteFs` service strictly sandboxing file manipulations to the site's home directory (`src/services/files.rs`).
- **Streaming Command Execution**:
  - Implemented command execution service with streaming output and systemd-run escape prevention (`src/services/cmd.rs`).

### Fixed
- **Low-Memory Build OOM Kills**: Enabled thin LTO during compilation on servers with <= 2GB RAM to prevent compiler OOM killer crashes.
- **Debian 12 Compatibility**:
  - Fixed Fail2ban timestamp stripping in regex filters and added `python3-systemd` package for sshd journal backend.
  - Fixed site deletion cleanup to drop associated MariaDB/MongoDB/SQLite databases and remove leftover system user groups.
  - Assigned user login group (`user:`) when creating files instead of assuming an identical group name.
- Fixed installer swap configuration exit status when swap was already active.
- Fixed `/etc/os-release` variables overriding installer internal variables.

### Changed
- Added `--swap-size` option to configure permanent system swap during installation.

---

## [v0.3.0] - 2026-11-04

### Added
- **Initial Foundation of CloudPanel Rust Edition**:
  - High-performance, self-contained server control panel built with Rust (Axum, Tokio, embedded SQLite) and embedded SPA frontend (`rust-embed`).
  - **Site Hosting**: Multi-tenant site isolation with dedicated Linux system users (`/home/<user>/htdocs/<domain>`), Nginx reverse proxy, custom vhosts, and document roots.
  - **Database Management**: Multi-engine support for MariaDB / MySQL, MongoDB, and SQLite with database creation, user privileges, and import/export (.sql, .sql.gz, mongodump, sqlite).
  - **File Manager**: Web-based file manager confined to site home with drag-and-drop upload up to 1GB, zip/tar archive extraction and compression.
  - **Automated Backups**: Scheduled file and database backups with local retention and remote S3-compatible cloud storage sync.
  - **Security & Authentication**: Argon2id password hashing, TOTP two-factor authentication with client-side SVG QR rendering, 10 recovery codes, and fail2ban brute-force protection.
  - **Firewall & Cron**: UFW firewall rule configuration with SSH lockout protection, and user/site-scoped cron job scheduler.
  - **Docker & Compose**: Container management, Compose stack editor with validation, image pulling and pruning, live resource stats.
  - **Alerts**: Multi-channel alerts for disk, memory, CPU thresholds, service failures, and backup status via SMTP, Slack, Discord, and Webhooks.

---

[Unreleased]: https://github.com/marwinlewis/cloudpanel-rust/compare/v0.4.4...HEAD
[v0.4.4]: https://github.com/marwinlewis/cloudpanel-rust/compare/v0.4.3...v0.4.4
[v0.4.3]: https://github.com/marwinlewis/cloudpanel-rust/compare/v0.4.2...v0.4.3
[v0.4.2]: https://github.com/marwinlewis/cloudpanel-rust/compare/v0.4.1...v0.4.2
[v0.4.1]: https://github.com/marwinlewis/cloudpanel-rust/compare/v0.4.0...v0.4.1
[v0.4.0]: https://github.com/marwinlewis/cloudpanel-rust/compare/v0.3.9...v0.4.0
[v0.3.9]: https://github.com/marwinlewis/cloudpanel-rust/compare/v0.3.8...v0.3.9
[v0.3.8]: https://github.com/marwinlewis/cloudpanel-rust/compare/v0.3.7...v0.3.8
[v0.3.7]: https://github.com/marwinlewis/cloudpanel-rust/compare/v0.3.6...v0.3.7
[v0.3.6]: https://github.com/marwinlewis/cloudpanel-rust/compare/v0.3.5...v0.3.6
[v0.3.5]: https://github.com/marwinlewis/cloudpanel-rust/compare/v0.3.4...v0.3.5
[v0.3.4]: https://github.com/marwinlewis/cloudpanel-rust/compare/v0.3.3...v0.3.4
[v0.3.3]: https://github.com/marwinlewis/cloudpanel-rust/compare/v0.3.2...v0.3.3
[v0.3.2]: https://github.com/marwinlewis/cloudpanel-rust/compare/v0.3.1...v0.3.2
[v0.3.1]: https://github.com/marwinlewis/cloudpanel-rust/compare/v0.3.0...v0.3.1
[v0.3.0]: https://github.com/marwinlewis/cloudpanel-rust/releases/tag/v0.3.0
