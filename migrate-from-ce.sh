#!/usr/bin/env bash
# Move a server from CloudPanel CE to CloudPanel (Rust Edition) without taking its sites down.
#
# What serves the sites (nginx, PHP-FPM, MySQL, Varnish, Redis) is shared and stays exactly as it
# is: never restarted, never reconfigured, and CE's vhosts are kept byte for byte. Only the panel
# is swapped. CE's panel has its own nginx and PHP-FPM (clp-nginx, clp-php-fpm), which is what
# makes that possible. Each step checks what it claims, by comparing process IDs, config hashes
# and each site's response before and after.
#
#   sudo bash migrate-from-ce.sh preflight    Check the server. Changes nothing.
#   sudo bash migrate-from-ce.sh prepare      Install the new panel next to CE, on a spare port,
#                                             and import sites, databases and users. CE stays in
#                                             charge and you can try the new panel.
#   sudo bash migrate-from-ce.sh cutover      Move the new panel to CE's port and stop CE's panel.
#                                             Undoes itself if a check fails.
#   sudo bash migrate-from-ce.sh rollback     Go back to CE's panel. Works at any later time.
#   sudo bash migrate-from-ce.sh status       Show where things stand.
#   sudo bash migrate-from-ce.sh fix-apt      Let apt upgrades run on a server that has already cut
#                                             over. (Cutover does this itself.)
#
# Options:
#   --with-php         Manage PHP sites in the new panel. (Asked if the server has PHP sites.)
#   --no-php           Don't. PHP sites keep running, but the panel won't show them.
#   --side-port N      Port for the new panel during prepare (default 8442, inside the range CE
#                      opens in UFW)
#   --binary PATH      Use a local cloudpanel binary (offline installs, testing)
#   --version vX.Y.Z   Install a specific release
#   --yes              Don't ask for confirmation
#   -h, --help         Show this help
#
# See docs/migrating-from-cloudpanel-ce.md.

set -Eeuo pipefail

CE_DB=/home/clp/htdocs/app/data/db.sq3
CE_PORT=8443
CE_CRON=/etc/cron.d/clp
CE_PANEL_UNITS="clp-nginx clp-php-fpm clp-agent"
NEW_BIN=/usr/local/bin/cloudpanel
NEW_ENV=/etc/cloudpanel/cloudpanel.env
MYSQL_ADMIN=/etc/cloudpanel/mysql-admin.cnf
CE_APT_PIN=/etc/apt/preferences.d/00packages.cloudpanel.io.pref
APT_PIN=/etc/apt/preferences.d/01-cloudpanel-rust.pref
STATE_DIR=/var/lib/cloudpanel-migration
STATE_FILE="$STATE_DIR/state"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
INSTALLER_URL="https://raw.githubusercontent.com/marwinlewis/cloudpanel-rust/main/install.sh"

COMMAND=""
SIDE_PORT=8442
PHP_CHOICE=""
BINARY=""
VERSION=""
ASSUME_YES=0
PROBLEMS=0

if [ -t 1 ]; then
  C_BOLD=$'\033[1m'; C_DIM=$'\033[2m'; C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YLW=$'\033[33m'; C_RST=$'\033[0m'
else
  C_BOLD=""; C_DIM=""; C_RED=""; C_GRN=""; C_YLW=""; C_RST=""
fi

log()  { printf '%s==>%s %s\n' "$C_GRN" "$C_RST" "$*"; }
info() { printf '    %s%s%s\n' "$C_DIM" "$*" "$C_RST"; }
pass() { printf '  %sok%s   %s\n' "$C_GRN" "$C_RST" "$*"; }
warn() { printf '  %s!!%s   %s\n' "$C_YLW" "$C_RST" "$*"; }
bad()  { printf '  %sFAIL%s %s\n' "$C_RED" "$C_RST" "$*"; PROBLEMS=$((PROBLEMS + 1)); }
die()  { printf '%sxx%s  %s\n' "$C_RED" "$C_RST" "$*" >&2; exit 1; }

usage() { sed -n '2,/^$/p' "$0" | sed -e 's/^# \{0,1\}//' -e '$d'; }

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      preflight|prepare|cutover|rollback|status|fix-apt) COMMAND="$1" ;;
      --with-php) PHP_CHOICE=1 ;;
      --no-php) PHP_CHOICE=0 ;;
      --side-port) SIDE_PORT="${2:?--side-port needs a value}"; shift ;;
      --binary) BINARY="${2:?--binary needs a path}"; shift ;;
      --version) VERSION="${2:?--version needs a value}"; shift ;;
      --yes|-y) ASSUME_YES=1 ;;
      -h|--help) usage; exit 0 ;;
      *) die "Unknown option: $1 (use --help)" ;;
    esac
    shift
  done
  [ -n "$COMMAND" ] || { usage; exit 2; }
  case "$SIDE_PORT" in
    ''|*[!0-9]*) die "--side-port must be a number" ;;
  esac
  if [ "$SIDE_PORT" -lt 1024 ] || [ "$SIDE_PORT" -gt 65535 ] || [ "$SIDE_PORT" -eq "$CE_PORT" ]; then
    die "--side-port must be 1024-65535 and not $CE_PORT"
  fi
}

state() { cat "$STATE_FILE" 2>/dev/null || echo none; }
set_state() { printf '%s\n' "$1" > "$STATE_FILE"; }

confirm() {
  [ "$ASSUME_YES" -eq 1 ] && return 0
  local answer=""
  { exec 3</dev/tty; } 2>/dev/null || die "Can't ask for confirmation without a terminal. Pass --yes to go ahead."
  printf '%s [y/N]: ' "$1"
  read -r answer <&3 || answer=""
  exec 3<&-
  case "$answer" in [yY]*) return 0 ;; *) return 1 ;; esac
}

# ---------- Facts about the server ----------

ce_sql() { sqlite3 -readonly "$CE_DB" "$1"; }

ce_domains() { ce_sql 'SELECT domain_name FROM site ORDER BY id'; }

# What must not change. Certificates are left out because CE may renew one at any moment, and the
# new panel's own files are left out because it owns them.
fingerprint() {
  {
    sha256sum /etc/nginx/nginx.conf
    find /etc/nginx/sites-enabled /etc/nginx/sites-available /etc/nginx/conf.d /etc/php \
      -type f \( -path '*/sites-*' -o -path '*/conf.d/*' -o -path '*/fpm/pool.d/*' \) \
      ! -name 'cloudpanel-*' -print0 2>/dev/null | sort -z | xargs -0 -r sha256sum
  } 2>/dev/null
}

# The main process of everything that serves sites. A changed ID means it restarted.
service_pids() {
  local unit pid
  for unit in $(systemctl list-units --type=service --state=running --no-legend --plain 2>/dev/null \
    | awk '{print $1}' | grep -E '^(nginx|mysql|mariadb|varnish|redis-server|proftpd|php[0-9.]+-fpm)\.service$' | sort); do
    pid=$(systemctl show -p MainPID --value "$unit")
    printf '%s %s\n' "$unit" "$pid"
  done
}

probe_one() {
  curl -sk --max-time 15 -o /dev/null -w '%{http_code}' --resolve "$1:443:127.0.0.1" "https://$1/" || true
}

# One `domain status` per line.
probe_sites() {
  local d
  for d in $(ce_domains); do
    printf '%s %s\n' "$d" "$(probe_one "$d")"
  done
}

record_baseline() {
  fingerprint > "$STATE_DIR/fingerprint.$1"
  service_pids > "$STATE_DIR/pids.$1"
  probe_sites > "$STATE_DIR/probes.$1"
}

# Compare the server with a recorded baseline. A site that worked and now doesn't is a failure. A
# different status that still works is only reported, because apps change what they answer.
check_against_baseline() {
  local tag="$1" diff_out d before after
  if diff_out=$(diff "$STATE_DIR/fingerprint.$tag" <(fingerprint)); then
    pass "Site configs are byte for byte what they were"
  else
    bad "Site configs changed:"
    printf '%s\n' "$diff_out" | head -20 | sed 's/^/         /'
  fi
  if diff_out=$(diff "$STATE_DIR/pids.$tag" <(service_pids)); then
    pass "nginx, PHP-FPM and MySQL were not restarted"
  else
    bad "Site services changed process ID (restarted):"
    printf '%s\n' "$diff_out" | sed 's/^/         /'
  fi
  while read -r d before; do
    after=$(probe_one "$d")
    if [ "$after" = "$before" ]; then
      pass "$d answers $after, as before"
    elif { [ "$after" = 000 ] || [ "${after:0:1}" = 5 ]; } && [ "$before" != 000 ] && [ "${before:0:1}" != 5 ]; then
      bad "$d answered $before before and answers $after now"
    else
      warn "$d answered $before before and answers $after now"
    fi
  done < "$STATE_DIR/probes.$tag"
}

# The panel answers 401 to an anonymous request once it is up.
panel_answers() {
  local port="$1" code tries="${2:-30}"
  for _ in $(seq 1 "$tries"); do
    code=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "https://127.0.0.1:${port}/api/auth/me" || true)
    [ "$code" = 401 ] && return 0
    sleep 1
  done
  return 1
}

# CE's panel answers on its own port with something other than the new panel's 401.
ce_panel_answers() {
  local code tries="${1:-30}"
  for _ in $(seq 1 "$tries"); do
    code=$(curl -sk --max-time 5 -o /dev/null -w '%{http_code}' "https://127.0.0.1:${CE_PORT}/" || true)
    case "$code" in 2*|3*) return 0 ;; esac
    sleep 1
  done
  return 1
}

port_in_use() { ss -ltnH "sport = :$1" 2>/dev/null | grep -q .; }

# ---------- preflight ----------

preflight_checks() {
  PROBLEMS=0
  log "Checking this server (nothing is changed)"
  [ "$(id -u)" -eq 0 ] || die "Please run as root, e.g.: sudo bash $0 $COMMAND"

  local tool
  for tool in sqlite3 curl ss systemctl sha256sum; do
    command -v "$tool" >/dev/null 2>&1 || bad "$tool is needed and isn't installed"
  done

  if [ -f "$CE_DB" ] && command -v clpctl >/dev/null 2>&1; then
    pass "CloudPanel CE found ($(dpkg-query -W -f='${Version}' cloudpanel 2>/dev/null || echo 'unknown version'))"
  else
    die "CloudPanel CE isn't on this server ($CE_DB or clpctl is missing), so there is nothing to migrate."
  fi

  local unit
  for unit in $CE_PANEL_UNITS; do
    if [ "$(state)" = cutover ]; then
      continue
    fi
    if systemctl is-active --quiet "$unit"; then
      pass "$unit is running"
    else
      warn "$unit isn't running"
    fi
  done

  if systemctl is-active --quiet cloudpanel 2>/dev/null && [ "$(state)" = none ]; then
    bad "The Rust panel is already running here, but not from this script. Check it before migrating."
  elif [ -d /var/lib/cloudpanel ] && [ "$(state)" = none ]; then
    bad "/var/lib/cloudpanel already exists. Remove it or check what made it before migrating."
  fi

  if [ "$(state)" != prepared ] && [ "$(state)" != cutover ] && port_in_use "$SIDE_PORT"; then
    bad "Port $SIDE_PORT is in use. Pick another with --side-port."
  fi

  local nginx_out
  if nginx_out=$(nginx -t 2>&1); then
    pass "nginx accepts its current config"
  else
    bad "nginx rejects its current config. Fix this first, as any reload would take the sites down:"
    printf '%s\n' "$nginx_out" | tail -5 | sed 's/^/         /'
  fi

  local free_kb
  free_kb=$(df -Pk /var/lib | awk 'NR==2 {print $4}')
  if [ "$free_kb" -lt 1048576 ]; then
    bad "Less than 1 GB free on the disk holding /var/lib"
  else
    pass "$((free_kb / 1048576)) GB free"
  fi

  local creds
  creds=$(clpctl db:show:master-credentials </dev/null 2>/dev/null || true)
  if printf '%s\n' "$creds" | grep -q '^| Password'; then
    pass "MySQL credentials can be read from CE"
  else
    warn "Could not read MySQL credentials with clpctl. Panel database features won't work until this is fixed."
  fi

  if [ -z "$BINARY" ] && [ ! -f "$SCRIPT_DIR/install.sh" ] && ! curl -fsSI --max-time 10 "$INSTALLER_URL" >/dev/null 2>&1; then
    bad "install.sh isn't next to this script and can't be downloaded"
  fi

  log "What's here"
  local total php issued
  total=$(ce_sql 'SELECT COUNT(*) FROM site')
  php=$(ce_sql "SELECT COUNT(*) FROM site WHERE type = 'php'")
  issued=$(ce_sql 'SELECT COUNT(*) FROM certificate c JOIN site s ON s.certificate_id = c.id WHERE c.default_certificate = 0')
  info "$total site(s), $php of them PHP"
  ce_sql "SELECT '    ' || type || '  ' || domain_name FROM site ORDER BY type, domain_name"
  info "$(ce_sql 'SELECT COUNT(*) FROM "database"') database(s), $(ce_sql 'SELECT COUNT(*) FROM user') panel user(s), $(ce_sql 'SELECT COUNT(*) FROM cron_job') cron job(s), $(ce_sql 'SELECT COUNT(*) FROM ftp_user') FTP user(s)"
  info "$issued site(s) have a certificate other than CE's self-signed default. CE's nightly renewal job stays in place after the cutover."

  log "Sites as they answer now"
  local d code
  for d in $(ce_domains); do
    code=$(probe_one "$d")
    case "$code" in
      000) warn "$d doesn't answer" ;;
      5*) warn "$d answers $code. It's already failing, so a failure here later won't be from migrating." ;;
      *) pass "$d answers $code" ;;
    esac
  done

  if ufw status 2>/dev/null | grep -q 'Status: active'; then
    if ufw status 2>/dev/null | grep -Eq "(8433:8443|${SIDE_PORT})/tcp"; then
      pass "UFW allows port $SIDE_PORT"
    else
      warn "UFW doesn't allow port $SIDE_PORT. Reach the new panel with: ssh -L $SIDE_PORT:127.0.0.1:$SIDE_PORT root@this-server"
    fi
  fi
  info "A firewall at your hosting provider may also block port $SIDE_PORT. An SSH tunnel gets past that too."
}

cmd_preflight() {
  preflight_checks
  echo
  if [ "$PROBLEMS" -gt 0 ]; then
    die "$PROBLEMS problem(s) to fix before migrating."
  fi
  log "Ready. Next: sudo bash $0 prepare"
}

# ---------- prepare ----------

choose_php() {
  [ -n "$PHP_CHOICE" ] && return
  local php
  php=$(ce_sql "SELECT COUNT(*) FROM site WHERE type = 'php'")
  if [ "$php" -eq 0 ]; then
    PHP_CHOICE=0
    return
  fi
  if ! { exec 3</dev/tty; } 2>/dev/null; then
    die "This server has $php PHP site(s). Say what to do with them: --with-php or --no-php."
  fi
  local answer=""
  printf '\n%sThis server has %s PHP site(s).%s They keep running whichever you choose.\n' "$C_BOLD" "$php" "$C_RST"
  printf 'Manage PHP sites in the new panel? [Y/n]: '
  read -r answer <&3 || answer=""
  exec 3<&-
  case "$answer" in [nN]*) PHP_CHOICE=0 ;; *) PHP_CHOICE=1 ;; esac
}

run_installer() {
  local installer="$SCRIPT_DIR/install.sh"
  if [ ! -f "$installer" ]; then
    installer="$STATE_DIR/install.sh"
    curl -fsSL "$INSTALLER_URL" -o "$installer" || die "Could not download install.sh"
  fi
  local args=(--port "$SIDE_PORT" --no-firewall --no-nodejs --no-upgrade --swap-size 0 --databases mariadb,sqlite)
  if [ "$PHP_CHOICE" = 1 ]; then args+=(--with-php); else args+=(--no-php); fi
  if [ -n "$BINARY" ]; then args+=(--binary "$BINARY"); fi
  if [ -n "$VERSION" ]; then args+=(--version "$VERSION"); fi
  log "Installing the new panel on port $SIDE_PORT"
  info "This adds what's missing (certbot, for example) and upgrades nothing."
  bash "$installer" "${args[@]}" > "$STATE_DIR/install.log" 2>&1 || {
    tail -20 "$STATE_DIR/install.log" >&2
    die "The installer failed. Full log: $STATE_DIR/install.log. The sites weren't touched."
  }
}

# The panel manages site databases as MySQL's root, whose password only clpctl can read: it's
# encrypted in CE's database. Root only accepts 127.0.0.1, not the socket.
write_mysql_admin() {
  local out password port
  out=$(clpctl db:show:master-credentials </dev/null 2>/dev/null || true)
  password=$(printf '%s\n' "$out" | sed -n 's/^| Password *| *\([^ ]*\) .*/\1/p')
  port=$(printf '%s\n' "$out" | sed -n 's/^| Port *| *\([0-9]*\) .*/\1/p')
  if [ -z "$password" ]; then
    warn "Could not read MySQL credentials from CE. Create $MYSQL_ADMIN by hand to use panel database features."
    return 0
  fi
  ( umask 077; printf '[client]\nhost=127.0.0.1\nport=%s\nuser=root\npassword="%s"\n' "${port:-3306}" "$password" > "$MYSQL_ADMIN" )
  chmod 600 "$MYSQL_ADMIN"
  if command -v mysql >/dev/null 2>&1 && mysql "--defaults-extra-file=$MYSQL_ADMIN" -e 'SELECT 1' >/dev/null 2>&1; then
    pass "The new panel can manage MySQL"
  else
    warn "The saved MySQL credentials didn't work. Panel database features won't work until $MYSQL_ADMIN is fixed."
  fi
}

# Import from a consistent copy. The import writes only the new panel's database. Exit code 1 means
# some site needs looking at; the rest is imported and the report says which.
run_import() {
  local copy="$STATE_DIR/ce-db.sq3" out="$STATE_DIR/import.last" rc=0
  sqlite3 -readonly "$CE_DB" ".backup '$copy'"
  chmod 600 "$copy"
  (
    set -a
    # shellcheck disable=SC1090
    . "$NEW_ENV"
    set +a
    "$NEW_BIN" import-ce --source "$copy" --credentials-file "$STATE_DIR/panel-users.txt"
  ) > "$out" 2>&1 || rc=$?
  cat "$out" >> "$STATE_DIR/import.log"
  sed 's/^/    /' "$out"
  case "$rc" in
    0) ;;
    1) warn "The import reported problems (above). The rest was imported, and those sites keep running." ;;
    *) die "The import failed (exit code $rc). The sites weren't touched." ;;
  esac
}

backup_config() {
  local dest="$STATE_DIR/backup-$(date -u +%Y%m%dT%H%M%SZ)"
  mkdir -p "$dest"
  chmod 700 "$dest"
  sqlite3 -readonly "$CE_DB" ".backup '$dest/db.sq3'"
  tar -czf "$dest/config.tar.gz" --ignore-failed-read -C / etc/nginx etc/php etc/cron.d 2>/dev/null || true
  info "Backup of CE's database and the nginx, PHP and cron config: $dest"
}

cmd_prepare() {
  [ "$(state)" != cutover ] || die "Already cut over. To go back first: sudo bash $0 rollback"
  preflight_checks
  [ "$PROBLEMS" -eq 0 ] || die "$PROBLEMS problem(s) to fix before migrating."
  mkdir -p "$STATE_DIR"
  chmod 700 "$STATE_DIR"
  choose_php

  echo
  log "Recording how the sites are running now"
  record_baseline prepare
  backup_config

  run_installer
  write_mysql_admin
  log "Importing from CE"
  run_import

  log "Checking nothing changed for the sites"
  PROBLEMS=0
  if panel_answers "$SIDE_PORT"; then
    pass "The new panel answers on port $SIDE_PORT"
  else
    bad "The new panel isn't answering on port $SIDE_PORT. See: journalctl -u cloudpanel -n 50"
  fi
  check_against_baseline prepare
  if ce_panel_answers 5; then
    pass "CE's panel still answers on port $CE_PORT"
  else
    warn "CE's panel isn't answering on port $CE_PORT"
  fi
  [ "$PROBLEMS" -eq 0 ] || die "$PROBLEMS check(s) failed. CE is still in charge. Undo with: sudo bash $0 rollback"
  set_state prepared

  echo
  log "Prepared. CE is still in charge, and nothing changed for the sites."
  printf '  New panel  https://%s:%s\n' "$(hostname -I 2>/dev/null | awk '{print $1}')" "$SIDE_PORT"
  if [ -s /var/lib/cloudpanel/initial_admin_password ]; then
    printf '  Username   admin\n  Password   %s\n' "$(cat /var/lib/cloudpanel/initial_admin_password)"
  fi
  if [ -s "$STATE_DIR/panel-users.txt" ]; then
    printf '  CE users   new passwords are in %s\n' "$STATE_DIR/panel-users.txt"
  fi
  printf '\n  Check it over. It is safe to leave it like this for days. Then: sudo bash %s cutover\n' "$0"
}

# ---------- cutover ----------

set_new_panel_port() {
  sed -i "s|^CLOUDPANEL_BIND=.*|CLOUDPANEL_BIND=0.0.0.0:$1|" "$NEW_ENV"
}

# The nightly job restarts clp-agent, which would bring part of CE back. Everything else in that
# file stays, certificate renewal above all.
disable_ce_agent_cron() {
  [ -f "$CE_CRON" ] || return 0
  cp -p "$CE_CRON" "$STATE_DIR/clp-cron.original"
  sed -i '/systemctl restart clp-agent/s/^/# disabled by migrate-from-ce.sh: /' "$CE_CRON"
}

# What `apt-get upgrade` would downgrade, one package per line.
apt_downgrades() {
  LC_ALL=C apt-get -s -q upgrade 2>/dev/null \
    | sed -n '/will be DOWNGRADED/,/upgraded, /p' | sed -e '1d' -e '$d' | tr -s ' ' '\n' | sed '/^$/d'
}

# CE gives its repository priority 1000, the level at which apt may downgrade. It carries a few
# packages Debian has too (sgml-base, at the same version), so apt wants to replace Debian's copy
# with CE's. That counts as a downgrade, and `apt-get -y upgrade` then refuses to run at all.
# Lowering the priority to 990 doesn't help, and holding the package would also stop Debian's
# updates to it, so this blocks only CE's copy of each.
pin_ce_downgrades() {
  local origin pkgs p
  [ -f "$CE_APT_PIN" ] || return 0
  origin=$(sed -n 's/^Pin: origin //p' "$CE_APT_PIN" | head -n1)
  [ -n "$origin" ] || return 0
  apt-get update -q >/dev/null 2>&1 || warn "apt-get update failed, so this check may use old package lists"
  pkgs=$(apt_downgrades)
  if [ -f "$APT_PIN" ]; then
    # Keep what's already blocked: blocking it is why it's no longer on the list.
    pkgs=$(printf '%s\n%s\n' "$pkgs" "$(sed -n 's/^Package: //p' "$APT_PIN")" | sed '/^$/d' | sort -u)
  fi
  if [ -z "$pkgs" ]; then
    pass "apt upgrades won't downgrade anything"
    return 0
  fi
  {
    printf '# Written by migrate-from-ce.sh. Stops apt replacing these with copies from CE, which makes\n'
    printf '# apt-get -y upgrade refuse to run. Updates to them from Debian still install.\n'
    for p in $pkgs; do
      printf 'Package: %s\nPin: origin %s\nPin-Priority: -1\n\n' "$p" "$origin"
    done
  } > "$APT_PIN"
  if [ -n "$(apt_downgrades)" ]; then
    warn "apt upgrades would still downgrade: $(apt_downgrades | tr '\n' ' ')"
  else
    pass "apt upgrades won't downgrade anything (blocked CE's copy of: $(printf '%s ' $pkgs))"
  fi
}

restore_ce() {
  if [ -f "$STATE_DIR/clp-cron.original" ]; then
    cp -p "$STATE_DIR/clp-cron.original" "$CE_CRON"
  fi
  rm -f "$APT_PIN"
  apt-mark unhold cloudpanel >/dev/null 2>&1 || true
  local unit
  for unit in clp-php-fpm clp-nginx clp-agent; do
    systemctl enable --now "$unit" >/dev/null 2>&1 || warn "Could not start $unit"
  done
}

# Back to CE: free its port, then bring its panel up. Touches only the panels.
back_to_ce() {
  systemctl stop cloudpanel 2>/dev/null || true
  systemctl disable cloudpanel >/dev/null 2>&1 || true
  [ -f "$NEW_ENV" ] && set_new_panel_port "$SIDE_PORT"
  restore_ce
  if ce_panel_answers 30; then
    pass "CE's panel is back on port $CE_PORT"
  else
    bad "CE's panel didn't come back on port $CE_PORT. See: journalctl -u clp-nginx -n 50"
  fi
  set_state rolled-back
}

undo_cutover() {
  echo
  printf '%s==> Going back to CE%s\n' "$C_YLW" "$C_RST"
  PROBLEMS=0
  back_to_ce
  die "The cutover was undone: ${1}. The sites weren't touched."
}

cmd_cutover() {
  [ "$(state)" = prepared ] || [ "$(state)" = rolled-back ] || die "Run prepare first (state: $(state))."
  [ "$(id -u)" -eq 0 ] || die "Please run as root."

  log "Catching up with changes made in CE since prepare"
  # Taken before the import and any change, so a site added in CE since prepare counts as normal.
  record_baseline cutover
  run_import

  cat <<EOF

This moves the new panel to port $CE_PORT and stops CE's panel. The sites aren't touched.
Sign-ins to CE's panel end. If anything fails, this script goes back to CE by itself.

EOF
  confirm "Cut over now?" || die "Nothing was changed."

  log "Stopping CE's panel"
  # So that an apt upgrade can't re-enable it: the package's post-install script starts clp-nginx,
  # which would then fight the new panel for the port.
  apt-mark hold cloudpanel >/dev/null
  systemctl stop clp-nginx || undo_cutover "clp-nginx wouldn't stop"

  log "Moving the new panel to port $CE_PORT"
  set_new_panel_port "$CE_PORT"
  systemctl enable cloudpanel >/dev/null 2>&1 || true
  systemctl restart cloudpanel || undo_cutover "the new panel wouldn't start"
  panel_answers "$CE_PORT" 30 || undo_cutover "the new panel isn't answering on port $CE_PORT"
  pass "The new panel answers on port $CE_PORT"

  PROBLEMS=0
  log "Checking nothing changed for the sites"
  check_against_baseline cutover
  [ "$PROBLEMS" -eq 0 ] || undo_cutover "$PROBLEMS check(s) failed"

  # Only now is the rest of CE's panel unneeded. The package stays installed: clpctl keeps renewing
  # certificates, and rollback needs it.
  systemctl disable clp-nginx >/dev/null 2>&1 || true
  systemctl disable --now clp-php-fpm clp-agent >/dev/null 2>&1 || true
  disable_ce_agent_cron
  set_state cutover
  # After the state is saved: this only affects later upgrades, so it's no reason to undo anything.
  log "Checking apt upgrades will work"
  pin_ce_downgrades || warn "Could not check. If upgrades fail, run: sudo bash $0 fix-apt"

  echo
  log "Done. The new panel is on port $CE_PORT."
  printf '  Browsers may warn about its certificate until you issue one under Settings → Panel certificate.\n'
  printf '  Passwords: admin in /var/lib/cloudpanel/initial_admin_password, CE users in %s\n' "$STATE_DIR/panel-users.txt"
  printf '  CE is kept for going back: sudo bash %s rollback\n' "$0"
}

# ---------- rollback ----------

cmd_rollback() {
  [ "$(id -u)" -eq 0 ] || die "Please run as root."
  [ -d "$STATE_DIR" ] || die "Nothing to roll back: this script hasn't run here."
  log "Going back to CE's panel. The sites aren't touched."
  info "Changes made in the new panel since cutover stay in the new panel; CE won't know about them."
  confirm "Go back to CE?" || die "Nothing was changed."
  PROBLEMS=0
  back_to_ce
  [ "$PROBLEMS" -eq 0 ] || die "CE's panel needs attention."
  log "CE's panel is in charge again. The new panel is stopped, with its data kept."
  info "To try again: sudo bash $0 prepare, then cutover. To remove it: bash install.sh --uninstall --purge"
}

# ---------- fix-apt ----------

cmd_fix_apt() {
  [ "$(id -u)" -eq 0 ] || die "Please run as root."
  [ -f "$CE_APT_PIN" ] || die "CE's apt settings aren't on this server, so there's nothing to fix."
  PROBLEMS=0
  pin_ce_downgrades
  log "Done. This doesn't upgrade anything. Run the upgrade from Services > Updates when it suits you."
}

# ---------- status ----------

cmd_status() {
  printf 'Migration state: %s\n' "$(state)"
  local unit
  for unit in cloudpanel $CE_PANEL_UNITS nginx mysql; do
    printf '  %-14s %s\n' "$unit" "$(systemctl is-active "$unit" 2>/dev/null || true)"
  done
  ss -ltnpH "sport = :$CE_PORT" 2>/dev/null | awk '{print "  port '"$CE_PORT"': " $NF}' | head -1
  ss -ltnpH "sport = :$SIDE_PORT" 2>/dev/null | awk '{print "  port '"$SIDE_PORT"': " $NF}' | head -1
  if apt-mark showhold 2>/dev/null | grep -qx cloudpanel; then
    printf '  apt: the cloudpanel package is held\n'
  fi
}

main() {
  parse_args "$@"
  case "$COMMAND" in
    preflight) cmd_preflight ;;
    prepare) cmd_prepare ;;
    cutover) cmd_cutover ;;
    rollback) cmd_rollback ;;
    status) cmd_status ;;
    fix-apt) cmd_fix_apt ;;
  esac
}

main "$@"
