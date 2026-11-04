#!/usr/bin/env bash
# CloudPanel (Rust Edition) installer
#
# Supported: Debian 11 / 12 / 13 and Ubuntu 22.04 / 24.04 (amd64, arm64)
#
#   curl -fsSL https://raw.githubusercontent.com/marwinlewis/cloudpanel-rust/main/install.sh | sudo bash
#   curl -fsSL https://raw.githubusercontent.com/marwinlewis/cloudpanel-rust/main/install.sh | sudo bash -s -- --with-docker
#
# Re-running the script upgrades CloudPanel in place and keeps all data and secrets.
#
# Options:
#   --version vX.Y.Z   Install a specific release (default: latest)
#   --from-source      Build from source instead of downloading a release binary
#   --binary PATH      Install a local cloudpanel binary instead of downloading one
#   --binary PATH      Install a locally built cloudpanel binary (offline installs, testing)
#   --branch NAME      Git branch to build when building from source (default: main)
#   --with-docker      Also install Docker Engine from the official docker.com repository
#   --with-mariadb     Install MariaDB (MySQL-compatible) for site databases
#   --with-mongodb     Install MongoDB Community from the official mongodb.org repository
#   --with-sqlite      Enable SQLite site databases (installs the sqlite3 CLI)
#   --databases LIST   Same as the three flags above, e.g. --databases mariadb,sqlite
#   --no-fail2ban      Don't install fail2ban
#   --port N           Port for the panel (default: 8443)
#   --swap-size GB     Permanent swap file to create if the server has none (default: ask, 2)
#   --no-firewall      Don't configure or enable UFW
#   --force            Continue on an untested distribution
#   --uninstall        Remove CloudPanel (keeps data in /var/lib/cloudpanel)
#   --purge            With --uninstall: also delete data, config and the cron file
#   -h, --help         Show this help

set -Eeuo pipefail

REPO="${CLOUDPANEL_REPO:-marwinlewis/cloudpanel-rust}"
VERSION="latest"
BRANCH="main"
FROM_SOURCE=0
LOCAL_BIN=""
WITH_DOCKER=0
WITH_MARIADB=0
WITH_MONGODB=0
WITH_SQLITE=0
DB_CHOSEN=0
NO_FAIL2BAN=0
NO_FIREWALL=0
FORCE=0
UNINSTALL=0
PURGE=0
PORT=8443
PORT_SET=0

BIN=/usr/local/bin/cloudpanel
DATA_DIR=/var/lib/cloudpanel
CONF_DIR=/etc/cloudpanel
ENV_FILE="$CONF_DIR/cloudpanel.env"
TLS_DIR="$CONF_DIR/tls"
UNIT=/etc/systemd/system/cloudpanel.service
SITES_DIR=/var/www

TMP_DIR=""
SWAP_FILE=""
SWAP_SIZE=""   # GB of temporary swap for a source build; asked if empty

if [ -t 1 ]; then
  C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'; C_RST=$'\033[0m'
else
  C_BOLD=""; C_DIM=""; C_RED=""; C_GRN=""; C_YLW=""; C_RST=""
fi

log()  { printf '%s==>%s %s\n' "$C_GRN" "$C_RST" "$*"; }
info() { printf '    %s%s%s\n' "$C_DIM" "$*" "$C_RST"; }
warn() { printf '%s!!%s  %s\n' "$C_YLW" "$C_RST" "$*" >&2; }
die()  { printf '%sxx%s  %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }

cleanup() {
  if [ -n "$SWAP_FILE" ] && [ -f "$SWAP_FILE" ]; then
    swapoff "$SWAP_FILE" 2>/dev/null || true
    rm -f "$SWAP_FILE"
  fi
  if [ -n "$TMP_DIR" ] && [ -d "$TMP_DIR" ]; then
    rm -rf "$TMP_DIR"
  fi
}
trap cleanup EXIT
trap 'die "Installation failed on line $LINENO. See the output above."' ERR

usage() {
  cat <<'EOF'
CloudPanel installer (Debian 11/12/13, Ubuntu 22.04/24.04)

  --version vX.Y.Z   Install a specific release (default: latest)
  --from-source      Build from source instead of downloading a release binary
  --branch NAME      Git branch to build when building from source (default: main)
  --with-docker      Also install Docker Engine from docker.com
  --with-mariadb     Install MariaDB (MySQL-compatible) for site databases
  --with-mongodb     Install MongoDB Community (mongodb.org repository)
  --with-sqlite      Enable SQLite site databases
  --databases LIST   Comma-separated: mariadb,mongodb,sqlite (asked interactively if omitted)
  --no-fail2ban      Don't install fail2ban
  --port N           Port for the panel (default: 8443)
  --swap-size GB     Permanent swap file to create if the server has none (default: ask, 2)
  --no-firewall      Don't configure or enable UFW
  --force          Continue on an untested distribution
  --uninstall        Remove CloudPanel (keeps data)
  --purge            With --uninstall: also delete data, config and cron jobs
EOF
}

set_databases() {
  local list="$1" e
  DB_CHOSEN=1
  for e in $(printf '%s' "$list" | tr ',' ' '); do
    case "$e" in
      mariadb|mysql) WITH_MARIADB=1 ;;
      mongodb|mongo) WITH_MONGODB=1 ;;
      sqlite) WITH_SQLITE=1 ;;
      none) ;;
      *) die "Unknown database engine: $e (use mariadb, mongodb, sqlite)" ;;
    esac
  done
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --version) VERSION="${2:?--version needs a value}"; shift ;;
      --branch) BRANCH="${2:?--branch needs a value}"; shift ;;
      --from-source) FROM_SOURCE=1 ;;
      --binary) LOCAL_BIN="${2:?--binary needs a path}"; shift ;;
      --with-docker) WITH_DOCKER=1 ;;
      --with-mariadb|--with-mysql) WITH_MARIADB=1; DB_CHOSEN=1 ;;
      --with-mongodb) WITH_MONGODB=1; DB_CHOSEN=1 ;;
      --with-sqlite) WITH_SQLITE=1; DB_CHOSEN=1 ;;
      --databases) set_databases "${2:?--databases needs a value}"; shift ;;
      --no-fail2ban) NO_FAIL2BAN=1 ;;
      --no-firewall) NO_FIREWALL=1 ;;
      --port) PORT="${2:?--port needs a value}"; PORT_SET=1; shift ;;
      --swap-size) SWAP_SIZE="${2:?--swap-size needs a value in GB}"; shift ;;
      --force) FORCE=1 ;;
      --uninstall) UNINSTALL=1 ;;
      --purge) PURGE=1 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1 (use --help)" ;;
    esac
    shift
  done
  case "$PORT" in
    ''|*[!0-9]*) die "--port must be a number" ;;
  esac
  if [ "$PORT" -lt 1 ] || [ "$PORT" -gt 65535 ] || [ "$PORT" -eq 80 ] || [ "$PORT" -eq 443 ]; then
    die "--port must be 1-65535 and not 80/443 (used by nginx)"
  fi
  if [ -n "$SWAP_SIZE" ] && ! valid_swap_size "$SWAP_SIZE"; then
    die "--swap-size must be a whole number of GB from 0 to 64"
  fi
  if [ "$VERSION" != "latest" ] && ! printf '%s' "$VERSION" | grep -Eq '^v?[0-9]+\.[0-9]+\.[0-9]+([-.][0-9A-Za-z.]+)?$'; then
    die "--version must look like v1.2.3"
  fi
  if [ "$VERSION" != "latest" ] && [ "${VERSION#v}" = "$VERSION" ]; then
    VERSION="v$VERSION"
  fi
}

require_root() {
  [ "$(id -u)" -eq 0 ] || die "Please run as root, e.g.: curl -fsSL ... | sudo bash"
}

detect_os() {
  [ -r /etc/os-release ] || die "Cannot detect the operating system (/etc/os-release missing)"
  # shellcheck disable=SC1091
  # Read os-release in a subshell: it defines VERSION, NAME, ID etc., which
  # would otherwise overwrite this script's own VERSION (the release to install).
  OS_ID=$(. /etc/os-release && printf '%s' "${ID:-}")
  OS_VERSION=$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")
  OS_CODENAME=$(. /etc/os-release && printf '%s' "${VERSION_CODENAME:-}")
  PRETTY_NAME=$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-}")

  local supported=0
  case "$OS_ID" in
    debian) case "$OS_VERSION" in 11|12|13) supported=1 ;; esac ;;
    ubuntu) case "$OS_VERSION" in 22.04|24.04) supported=1 ;; esac ;;
  esac
  if [ "$supported" -ne 1 ]; then
    if [ "$FORCE" -eq 1 ] && printf '%s' "${ID_LIKE:-} $OS_ID" | grep -qwE 'debian|ubuntu'; then
      warn "Untested distribution ${PRETTY_NAME:-$OS_ID}; continuing because of --force"
    else
      die "Unsupported OS: ${PRETTY_NAME:-unknown}. Supported: Debian 11/12/13, Ubuntu 22.04/24.04 (use --force to try anyway)"
    fi
  fi

  case "$(uname -m)" in
    x86_64|amd64) ARCH=x86_64 ;;
    aarch64|arm64) ARCH=aarch64 ;;
    *) die "Unsupported CPU architecture: $(uname -m) (amd64 and arm64 are supported)" ;;
  esac

  command -v systemctl >/dev/null 2>&1 || die "systemd is required"
  log "Detected ${PRETTY_NAME:-$OS_ID $OS_VERSION} ($ARCH)"
}

apt_install() {
  DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends \
    -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold "$@"
}

install_packages() {
  log "Installing system packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt_install ca-certificates curl gnupg openssl tar gzip unzip nginx certbot python3-certbot-nginx ufw cron iproute2 passwd
  if [ "$NO_FAIL2BAN" -eq 0 ]; then
    # The sshd jail reads the systemd journal (Debian 12+ has no auth.log by default).
    apt_install fail2ban python3-systemd
  fi
  if [ "$WITH_SQLITE" -eq 1 ]; then
    apt_install sqlite3
  fi
  systemctl enable --now nginx >/dev/null 2>&1 || warn "Could not start nginx (is port 80 in use?)"
  systemctl enable --now cron >/dev/null 2>&1 || true
}

install_docker() {
  if command -v docker >/dev/null 2>&1; then
    info "Docker is already installed"
    return
  fi
  log "Installing Docker Engine (docker.com repository)"
  [ -n "$OS_CODENAME" ] || die "Cannot determine the release codename for the Docker repository"
  install -m 0755 -d /etc/apt/keyrings
  curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" -o /etc/apt/keyrings/docker.asc
  chmod a+r /etc/apt/keyrings/docker.asc
  printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
    "$(dpkg --print-architecture)" "$OS_ID" "$OS_CODENAME" > /etc/apt/sources.list.d/docker.list
  apt-get update -q
  apt_install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
  systemctl enable --now docker >/dev/null 2>&1 || warn "Docker installed but failed to start"
}

# Ask which database engines to install when no flag was given. The answer is read from
# /dev/tty because stdin is the script itself when piped from curl.
choose_databases() {
  if [ "$DB_CHOSEN" -eq 1 ]; then
    return
  fi
  if [ -f "$ENV_FILE" ] && grep -q '^CLOUDPANEL_DB_ENGINES=' "$ENV_FILE"; then
    set_databases "$(sed -n 's/^CLOUDPANEL_DB_ENGINES=//p' "$ENV_FILE" | head -n1)"
    [ -n "$(sed -n 's/^CLOUDPANEL_DB_ENGINES=//p' "$ENV_FILE" | head -n1)" ] || DB_CHOSEN=1
    info "Keeping database engines: $(sed -n 's/^CLOUDPANEL_DB_ENGINES=//p' "$ENV_FILE" | head -n1)"
    return
  fi
  local answer=""
  if { exec 3</dev/tty; } 2>/dev/null; then
    printf '\n%sWhich databases should sites be able to use?%s\n' "$C_BOLD" "$C_RST"
    printf '  1) MySQL / MariaDB\n  2) MongoDB\n  3) SQLite\n'
    printf 'Enter numbers separated by commas [default: 3]: '
    read -r answer <&3 || answer=""
    exec 3<&-
  fi
  answer=${answer:-3}
  local list="" n
  for n in $(printf '%s' "$answer" | tr ',' ' '); do
    case "$n" in
      1|mariadb|mysql) list="${list},mariadb" ;;
      2|mongodb|mongo) list="${list},mongodb" ;;
      3|sqlite) list="${list},sqlite" ;;
      0|none) ;;
      *) warn "Ignoring unknown choice: $n" ;;
    esac
  done
  set_databases "${list#,}"
  [ -n "${list#,}" ] || set_databases none
}

db_engines_csv() {
  local out=""
  [ "$WITH_MARIADB" -eq 1 ] && out="${out},mariadb"
  [ "$WITH_MONGODB" -eq 1 ] && out="${out},mongodb"
  [ "$WITH_SQLITE" -eq 1 ] && out="${out},sqlite"
  printf '%s' "${out#,}"
}

install_mariadb() {
  if command -v mariadb >/dev/null 2>&1 || command -v mysql >/dev/null 2>&1; then
    info "MariaDB/MySQL is already installed"
  else
    log "Installing MariaDB"
    apt_install mariadb-server mariadb-client
  fi
  systemctl enable --now mariadb >/dev/null 2>&1 || systemctl enable --now mysql >/dev/null 2>&1 || warn "Could not start MariaDB"
  # root authenticates over the local socket (unix_socket); there is no network root login.
}

install_mongodb() {
  local mv codename repo
  mv="8.0"
  case "$OS_ID:$OS_VERSION" in
    debian:11) mv="7.0"; codename=bullseye ;;
    debian:12|debian:13) codename=bookworm ;;
    ubuntu:22.04) codename=jammy ;;
    ubuntu:24.04) codename=noble ;;
    *) warn "MongoDB has no packages for ${OS_ID} ${OS_VERSION}; skipping"; WITH_MONGODB=0; return ;;
  esac
  if [ "$OS_ID" = "debian" ] && [ "$ARCH" != "x86_64" ]; then
    warn "MongoDB only publishes amd64 packages for Debian; skipping MongoDB"
    WITH_MONGODB=0
    return
  fi
  if ! command -v mongod >/dev/null 2>&1; then
    log "Installing MongoDB ${mv} (repo.mongodb.org)"
    curl -fsSL "https://www.mongodb.org/static/pgp/server-${mv}.asc" | gpg --dearmor --yes -o "/usr/share/keyrings/mongodb-server-${mv}.gpg"
    if [ "$OS_ID" = "debian" ]; then
      repo="deb [ signed-by=/usr/share/keyrings/mongodb-server-${mv}.gpg ] http://repo.mongodb.org/apt/debian ${codename}/mongodb-org/${mv} main"
    else
      repo="deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-${mv}.gpg ] https://repo.mongodb.org/apt/ubuntu ${codename}/mongodb-org/${mv} multiverse"
    fi
    printf '%s\n' "$repo" > "/etc/apt/sources.list.d/mongodb-org-${mv}.list"
    apt-get update -q
    apt_install mongodb-org
  else
    info "MongoDB is already installed"
  fi
  systemctl enable --now mongod >/dev/null 2>&1 || { warn "Could not start mongod"; return; }

  local creds="$CONF_DIR/mongodb.env"
  if [ ! -s "$creds" ]; then
    local pw i
    pw=$(openssl rand -hex 24)
    for i in $(seq 1 30); do
      mongosh --quiet --eval 'db.runCommand({ ping: 1 }).ok' >/dev/null 2>&1 && break
      sleep 1
    done
    if mongosh --quiet --eval "db.getSiblingDB('admin').createUser({ user: 'cloudpanel', pwd: '${pw}', roles: ['root'] })" >/dev/null; then
      install -d -m 0700 "$CONF_DIR"
      umask 077
      printf 'MONGO_ADMIN_USER=cloudpanel\nMONGO_ADMIN_PASSWORD=%s\n' "$pw" > "$creds"
      umask 022
      chmod 600 "$creds"
    else
      warn "Could not create the MongoDB admin user (is authorization already enabled?)"
    fi
  fi
  if ! grep -q '^security:' /etc/mongod.conf 2>/dev/null; then
    printf '\nsecurity:\n  authorization: enabled\n' >> /etc/mongod.conf
    systemctl restart mongod || warn "mongod failed to restart"
  fi
  if ! grep -Eq '^\s*bindIp:\s*127\.0\.0\.1\s*$' /etc/mongod.conf 2>/dev/null; then
    warn "mongod is not bound to 127.0.0.1 only; check /etc/mongod.conf"
  fi
}

install_databases() {
  if [ "$WITH_MARIADB" -eq 1 ]; then install_mariadb; fi
  if [ "$WITH_MONGODB" -eq 1 ]; then install_mongodb; fi
}

download_release() {
  local asset="cloudpanel-linux-${ARCH}" base
  if [ "$VERSION" = "latest" ]; then
    base="https://github.com/${REPO}/releases/latest/download"
  else
    base="https://github.com/${REPO}/releases/download/${VERSION}"
  fi
  log "Downloading ${asset} (${VERSION})"
  curl -fsSL --retry 3 -o "$TMP_DIR/$asset" "$base/$asset" || return 1
  curl -fsSL --retry 3 -o "$TMP_DIR/$asset.sha256" "$base/$asset.sha256" || {
    warn "Release has no checksum file"
    return 1
  }
  (cd "$TMP_DIR" && sha256sum -c --status "$asset.sha256") || die "Checksum verification failed for $asset"
  info "Checksum verified"
  NEW_BIN="$TMP_DIR/$asset"
}

valid_swap_size() {
  case "$1" in ''|*[!0-9]*) return 1 ;; esac
  [ "$1" -le 64 ]
}

mem_kb() { awk '/^MemTotal:/ {print $2}' /proc/meminfo; }
swap_kb() { awk '/^SwapTotal:/ {print $2}' /proc/meminfo; }

# Create and enable a swap file of $2 GB at $1. Returns 1 (with a warning)
# when the system does not allow swap, e.g. in containers or OpenVZ/LXC VPSes.
make_swap_file() {
  local file="$1" gb="$2" free_kb
  free_kb=$(df -Pk "$(dirname "$file")" | awk 'NR==2 {print $4}')
  if [ "$free_kb" -lt $(( (gb + 1) * 1048576 )) ]; then
    warn "Not enough free disk space for a ${gb} GB swap file; skipping"
    return 1
  fi
  rm -f "$file"
  if ! fallocate -l "${gb}G" "$file" 2>/dev/null; then
    dd if=/dev/zero of="$file" bs=1M count=$((gb * 1024)) status=none
  fi
  chmod 600 "$file"
  if ! mkswap "$file" >/dev/null 2>&1 || ! swapon "$file" 2>/dev/null; then
    rm -f "$file"
    warn "This system does not allow swap files (container or OpenVZ/LXC VPS?); skipping"
    return 1
  fi
}

# Offer a permanent swap file when the server has none. Small VPSes run nginx,
# databases and PHP/Node apps far more reliably with some swap. Asked on
# /dev/tty because stdin is the script itself when piped from curl.
setup_swap() {
  if [ "$(swap_kb)" -gt 0 ]; then
    [ -n "$SWAP_SIZE" ] && [ "$SWAP_SIZE" -gt 0 ] && info "Swap is already enabled; leaving it as it is"
    return
  fi
  local answer="$SWAP_SIZE"
  if [ -z "$answer" ]; then
    if { exec 3</dev/tty; } 2>/dev/null; then
      printf '\n%sThis server has no swap. A swap file helps small servers avoid running out of memory.%s\n' "$C_BOLD" "$C_RST"
      while :; do
        printf 'Swap file size in GB (0 = no swap) [default: 2]: '
        read -r answer <&3 || answer=""
        answer=${answer:-2}
        answer=${answer%[gG]}
        valid_swap_size "$answer" && break
        warn "Enter a whole number from 0 to 64"
      done
      exec 3<&-
    else
      answer=2
    fi
  fi
  if [ "$answer" -eq 0 ]; then
    info "No swap file created"
    return
  fi
  log "Creating a ${answer} GB swap file at /swapfile"
  make_swap_file /swapfile "$answer" || return 0
  grep -qE '^\s*/swapfile\s' /etc/fstab || printf '/swapfile none swap sw 0 0\n' >> /etc/fstab
  # Prefer RAM; only use swap under real memory pressure.
  printf 'vm.swappiness=10\n' > /etc/sysctl.d/90-cloudpanel-swap.conf
  sysctl -q -w vm.swappiness=10 2>/dev/null || true
}

# Compiling needs ~2.5 GB of RAM + swap. If the server still has less, add a
# throwaway swap file that cleanup() removes after the build.
ensure_build_memory() {
  local total_kb need_gb
  total_kb=$(( $(mem_kb) + $(swap_kb) ))
  [ "$total_kb" -ge 2500000 ] && return
  need_gb=$(( (3000000 - total_kb) / 1048576 + 1 ))
  log "Adding a temporary ${need_gb} GB swap file for the build (removed afterwards)"
  SWAP_FILE=/cloudpanel-build.swap
  make_swap_file "$SWAP_FILE" "$need_gb" || { SWAP_FILE=""; warn "The build may run out of memory"; }
}

build_from_source() {
  log "Building CloudPanel from source (this can take 5-15 minutes)"
  apt_install build-essential pkg-config git
  ensure_build_memory

  export RUSTUP_HOME="$TMP_DIR/rustup" CARGO_HOME="$TMP_DIR/cargo"
  # Keep rustup's unpacking and cargo's parallel jobs light on small servers.
  export RUSTUP_IO_THREADS=1 TMPDIR="$TMP_DIR"
  if [ "$(mem_kb)" -lt 2000000 ]; then
    export CARGO_BUILD_JOBS=1
  fi
  info "Installing the Rust toolchain"
  curl -fsSL --proto '=https' --tlsv1.2 https://sh.rustup.rs -o "$TMP_DIR/rustup-init.sh"
  sh "$TMP_DIR/rustup-init.sh" -y -q --profile minimal --no-modify-path
  local ref="$BRANCH"
  [ "$VERSION" != "latest" ] && ref="$VERSION"
  info "Downloading the source (${ref})"
  git clone -q --depth 1 --branch "$ref" "https://github.com/${REPO}.git" "$TMP_DIR/src"
  info "Compiling. Progress is shown below; on a 1 CPU server this takes about 5-15 minutes."
  (cd "$TMP_DIR/src" && "$CARGO_HOME/bin/cargo" build --release --locked)
  NEW_BIN="$TMP_DIR/src/target/release/cloudpanel"
}

install_binary() {
  # /var/tmp is on disk. /tmp is a RAM-backed tmpfs on Debian 13+, too small
  # on low-memory servers for the Rust toolchain and build (~2 GB).
  TMP_DIR=$(mktemp -d -p /var/tmp cloudpanel-install.XXXXXX)
  NEW_BIN=""
  if [ -n "$LOCAL_BIN" ]; then
    [ -f "$LOCAL_BIN" ] || die "--binary: $LOCAL_BIN not found"
    NEW_BIN="$LOCAL_BIN"
  elif [ "$FROM_SOURCE" -eq 0 ]; then
    if ! download_release; then
      [ "$VERSION" = "latest" ] || die "Release ${VERSION} not found for ${ARCH}"
      warn "No release binary available; falling back to building from source"
      build_from_source
    fi
  else
    build_from_source
  fi
  "$NEW_BIN" --version >/dev/null 2>&1 || die "The downloaded binary does not run on this system"
  # Copy then rename so a running binary is replaced atomically.
  install -m 0755 "$NEW_BIN" "$BIN.new"
  mv -f "$BIN.new" "$BIN"
  log "Installed $("$BIN" --version)"
}

detect_public_ip() {
  local ip=""
  ip=$(curl -fsS4 --max-time 5 https://api.ipify.org 2>/dev/null || true)
  if ! printf '%s' "$ip" | grep -Eq '^[0-9]+(\.[0-9]+){3}$'; then
    ip=$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="src") {print $(i+1); exit}}')
  fi
  printf '%s' "${ip:-127.0.0.1}"
}

configure() {
  log "Configuring CloudPanel"
  install -d -m 0700 "$DATA_DIR"
  install -d -m 0755 "$CONF_DIR" "$SITES_DIR"
  install -d -m 0700 "$TLS_DIR"
  install -d -m 0755 /etc/nginx/sites-available /etc/nginx/sites-enabled /etc/nginx/conf.d /var/www/html
  install -d -m 0700 /var/backups/cloudpanel
  install -d -m 0750 /var/log/cloudpanel
  install -d -m 0755 /etc/ssh/sshd_config.d /etc/ssh/cloudpanel_keys
  getent group cloudpanel-users >/dev/null || groupadd cloudpanel-users
  getent group cloudpanel-sftp >/dev/null || groupadd cloudpanel-sftp
  if ! grep -Eq '^\s*Include\s+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config 2>/dev/null; then
    warn "/etc/ssh/sshd_config does not include sshd_config.d; SFTP-only users will not be enforced"
  fi
  # Reload nginx after certbot renews a certificate.
  install -d -m 0755 /etc/letsencrypt/renewal-hooks/deploy
  printf '#!/bin/sh\n# Installed by CloudPanel\nsystemctl reload nginx\n' > /etc/letsencrypt/renewal-hooks/deploy/cloudpanel-reload-nginx
  chmod 755 /etc/letsencrypt/renewal-hooks/deploy/cloudpanel-reload-nginx

  if [ ! -f "$ENV_FILE" ]; then
    umask 077
    cat > "$ENV_FILE" <<EOF
# CloudPanel configuration. Restart after editing: systemctl restart cloudpanel
CLOUDPANEL_BIND=0.0.0.0:${PORT}
CLOUDPANEL_DATA_DIR=${DATA_DIR}
CLOUDPANEL_SITES_DIR=${SITES_DIR}
CLOUDPANEL_TLS_CERT=${TLS_DIR}/panel.crt
CLOUDPANEL_TLS_KEY=${TLS_DIR}/panel.key
RUST_LOG=cloudpanel=info
EOF
    umask 022
  elif [ "$PORT_SET" -eq 1 ]; then
    sed -i "s|^CLOUDPANEL_BIND=.*|CLOUDPANEL_BIND=0.0.0.0:${PORT}|" "$ENV_FILE"
  else
    PORT=$(sed -n 's/^CLOUDPANEL_BIND=.*:\([0-9]\{1,5\}\)$/\1/p' "$ENV_FILE" | head -n1)
    PORT=${PORT:-8443}
  fi
  local engines
  engines=$(db_engines_csv)
  if grep -q '^CLOUDPANEL_DB_ENGINES=' "$ENV_FILE"; then
    sed -i "s|^CLOUDPANEL_DB_ENGINES=.*|CLOUDPANEL_DB_ENGINES=${engines}|" "$ENV_FILE"
  else
    printf 'CLOUDPANEL_DB_ENGINES=%s\n' "$engines" >> "$ENV_FILE"
  fi
  chmod 600 "$ENV_FILE"

  PUBLIC_IP=$(detect_public_ip)
  if [ ! -s "$TLS_DIR/panel.crt" ] || [ ! -s "$TLS_DIR/panel.key" ]; then
    log "Generating a self-signed TLS certificate for the panel"
    local host san
    host=$(hostname -f 2>/dev/null || hostname)
    san="IP:${PUBLIC_IP},IP:127.0.0.1,DNS:localhost"
    if printf '%s' "$host" | grep -Eq '^[A-Za-z0-9.-]+$'; then
      san="${san},DNS:${host}"
    fi
    openssl req -x509 -nodes -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 825 \
      -subj "/CN=CloudPanel" -addext "subjectAltName=${san}" \
      -keyout "$TLS_DIR/panel.key" -out "$TLS_DIR/panel.crt" >/dev/null 2>&1
    chmod 600 "$TLS_DIR/panel.key"
    chmod 644 "$TLS_DIR/panel.crt"
  fi
}

install_service() {
  log "Installing systemd service"
  cat > "$UNIT" <<'EOF'
[Unit]
Description=CloudPanel (Rust Edition)
Documentation=https://github.com/marwinlewis/cloudpanel-rust
After=network-online.target nginx.service
Wants=network-online.target

[Service]
Type=simple
User=root
EnvironmentFile=/etc/cloudpanel/cloudpanel.env
WorkingDirectory=/var/lib/cloudpanel
ExecStart=/usr/local/bin/cloudpanel server
Restart=on-failure
RestartSec=3
LimitNOFILE=65535
UMask=0022

# Hardening. CloudPanel manages nginx, certbot, ufw, cron, site users and their apps,
# so it runs as root, but it only gets write access to the paths it manages.
# Tools that must rewrite /etc/passwd or /usr (useradd, apt-get) are run outside this
# sandbox in transient units via systemd-run.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectClock=yes
ProtectHostname=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
ReadWritePaths=-/etc/nginx -/etc/cron.d -/etc/letsencrypt -/etc/ufw -/etc/cloudpanel -/etc/fail2ban
ReadWritePaths=-/etc/systemd/system -/etc/ssh/sshd_config.d -/etc/ssh/cloudpanel_keys -/home -/var/www -/var/backups/cloudpanel
ReadWritePaths=-/var/log/cloudpanel -/var/lib/cloudpanel

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable cloudpanel >/dev/null 2>&1
  systemctl restart cloudpanel
}

configure_firewall() {
  if [ "$NO_FIREWALL" -eq 1 ]; then
    info "Skipping firewall setup (--no-firewall)"
    return
  fi
  log "Configuring UFW firewall"
  local ssh_ports p
  ssh_ports=$(sshd -T 2>/dev/null | awk '$1 == "port" {print $2}' | sort -u || true)
  [ -n "$ssh_ports" ] || ssh_ports=22
  # Always allow SSH before enabling so the current session can't be cut off.
  for p in $ssh_ports; do
    ufw allow "${p}/tcp" comment 'SSH' >/dev/null
  done
  ufw allow 80/tcp comment 'HTTP' >/dev/null
  ufw allow 443/tcp comment 'HTTPS' >/dev/null
  ufw allow "${PORT}/tcp" comment 'CloudPanel' >/dev/null
  if ufw status | grep -q 'Status: inactive'; then
    ufw --force enable >/dev/null
    info "UFW enabled (allowed: SSH $(echo "$ssh_ports" | tr '\n' ' '), 80, 443, ${PORT})"
  else
    info "UFW already active; rules added"
  fi
}

wait_for_panel() {
  local code
  for _ in $(seq 1 30); do
    code=$(curl -sk -o /dev/null -w '%{http_code}' "https://127.0.0.1:${PORT}/api/auth/me" || true)
    if [ "$code" = "401" ]; then
      return 0
    fi
    sleep 1
  done
  warn "CloudPanel did not respond yet. Check: journalctl -u cloudpanel -n 50"
  return 1
}

print_summary() {
  local pw_file="$DATA_DIR/initial_admin_password"
  echo
  printf '%s  CloudPanel is ready%s\n\n' "$C_BOLD" "$C_RST"
  printf '  URL       https://%s:%s\n' "$PUBLIC_IP" "$PORT"
  if [ -s "$pw_file" ]; then
    printf '  Username  admin\n'
    printf '  Password  %s\n' "$(cat "$pw_file")"
    printf '\n  %sChange the password under Settings after signing in.%s\n' "$C_DIM" "$C_RST"
  else
    printf '  Sign in with your existing account.\n'
  fi
  printf '\n  %sThe panel uses a self-signed certificate, so your browser will show a warning once.%s\n' "$C_DIM" "$C_RST"
  printf '  %sForgot the password?  cloudpanel user-reset-password --username admin%s\n' "$C_DIM" "$C_RST"
  printf '  Databases %s\n' "$(db_engines_csv | sed 's/^$/none/')"
  if [ "$WITH_DOCKER" -eq 1 ]; then
    printf '  %sNote: ports published by Docker bypass UFW; bind containers to 127.0.0.1 and expose them via a site.%s\n' "$C_DIM" "$C_RST"
  fi
  echo
}

uninstall() {
  log "Uninstalling CloudPanel"
  systemctl disable --now cloudpanel >/dev/null 2>&1 || true
  rm -f "$UNIT" "$BIN"
  systemctl daemon-reload
  if [ "$PURGE" -eq 1 ]; then
    rm -rf "$DATA_DIR" "$CONF_DIR"
    rm -f /etc/cron.d/cloudpanel /etc/nginx/conf.d/cloudpanel-upgrade-map.conf
    rm -f /etc/ssh/sshd_config.d/cloudpanel.conf /etc/fail2ban/jail.d/cloudpanel.conf /etc/fail2ban/filter.d/cloudpanel.conf
    rm -f /etc/letsencrypt/renewal-hooks/deploy/cloudpanel-reload-nginx
    info "Site users, app services (cloudpanel-app-*) and backups in /var/backups/cloudpanel were left in place"
    info "Removed data, configuration and cron jobs"
    info "nginx site configs in /etc/nginx/sites-available were left in place"
  else
    info "Data kept in $DATA_DIR and $CONF_DIR (use --uninstall --purge to delete)"
  fi
  log "Done"
}

main() {
  parse_args "$@"
  require_root
  if [ "$UNINSTALL" -eq 1 ]; then
    uninstall
    exit 0
  fi
  detect_os
  setup_swap
  choose_databases
  install_packages
  install_databases
  if [ "$WITH_DOCKER" -eq 1 ]; then
    install_docker
  fi
  if systemctl is-active --quiet cloudpanel 2>/dev/null; then
    log "Existing installation found; upgrading"
  fi
  install_binary
  configure
  install_service
  configure_firewall
  wait_for_panel || true
  print_summary
}

main "$@"
