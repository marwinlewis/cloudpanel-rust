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
#   --branch NAME      Git branch to build when building from source (default: main)
#   --with-docker      Also install Docker Engine from the official docker.com repository
#   --port N           Port for the panel (default: 8443)
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
WITH_DOCKER=0
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
  --port N           Port for the panel (default: 8443)
  --no-firewall      Don't configure or enable UFW
  --force            Continue on an untested distribution
  --uninstall        Remove CloudPanel (keeps data)
  --purge            With --uninstall: also delete data, config and cron jobs
EOF
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --version) VERSION="${2:?--version needs a value}"; shift ;;
      --branch) BRANCH="${2:?--branch needs a value}"; shift ;;
      --from-source) FROM_SOURCE=1 ;;
      --with-docker) WITH_DOCKER=1 ;;
      --no-firewall) NO_FIREWALL=1 ;;
      --port) PORT="${2:?--port needs a value}"; PORT_SET=1; shift ;;
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
  . /etc/os-release
  OS_ID="${ID:-}"
  OS_VERSION="${VERSION_ID:-}"
  OS_CODENAME="${VERSION_CODENAME:-}"

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
  apt_install ca-certificates curl openssl tar gzip nginx certbot python3-certbot-nginx ufw cron iproute2
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

ensure_build_memory() {
  local mem_kb swap_kb
  mem_kb=$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)
  swap_kb=$(awk '/^SwapTotal:/ {print $2}' /proc/meminfo)
  if [ $((mem_kb + swap_kb)) -lt 1600000 ]; then
    warn "Less than 1.5 GB of memory; adding a temporary 2 GB swap file for the build"
    SWAP_FILE=/cloudpanel-build.swap
    if ! fallocate -l 2G "$SWAP_FILE" 2>/dev/null; then
      dd if=/dev/zero of="$SWAP_FILE" bs=1M count=2048 status=none
    fi
    chmod 600 "$SWAP_FILE"
    mkswap "$SWAP_FILE" >/dev/null
    swapon "$SWAP_FILE"
  fi
}

build_from_source() {
  log "Building CloudPanel from source (this can take 5-15 minutes)"
  apt_install build-essential pkg-config git
  ensure_build_memory

  export RUSTUP_HOME="$TMP_DIR/rustup" CARGO_HOME="$TMP_DIR/cargo"
  curl -fsSL --proto '=https' --tlsv1.2 https://sh.rustup.rs -o "$TMP_DIR/rustup-init.sh"
  sh "$TMP_DIR/rustup-init.sh" -y -q --profile minimal --no-modify-path >/dev/null
  local ref="$BRANCH"
  [ "$VERSION" != "latest" ] && ref="$VERSION"
  git clone -q --depth 1 --branch "$ref" "https://github.com/${REPO}.git" "$TMP_DIR/src"
  (cd "$TMP_DIR/src" && "$CARGO_HOME/bin/cargo" build --release --locked -q)
  NEW_BIN="$TMP_DIR/src/target/release/cloudpanel"
}

install_binary() {
  TMP_DIR=$(mktemp -d)
  NEW_BIN=""
  if [ "$FROM_SOURCE" -eq 0 ]; then
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

# Hardening. CloudPanel manages nginx, certbot, ufw and cron, so it runs as root,
# but it only gets write access to the paths it manages.
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ProtectHome=read-only
ProtectClock=yes
ProtectHostname=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
LockPersonality=yes
ReadWritePaths=-/etc/nginx -/etc/cron.d -/etc/letsencrypt -/etc/ufw

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
  install_packages
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
