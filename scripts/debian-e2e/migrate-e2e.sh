#!/usr/bin/env bash
# Checks the migration from inside a server running real CloudPanel CE. See run-migrate.sh.
#   migrate-e2e.sh setup | with-php | without-php
set -uo pipefail

MIGRATE="bash /var/tmp/migrate-from-ce.sh"
BIN=/var/tmp/cloudpanel
STATE=/var/lib/cloudpanel-migration
DB=/var/lib/cloudpanel/cloudpanel.db
failures=0

ok() { echo "  ok   $1"; }
fail() { echo "  FAIL $1"; failures=$((failures + 1)); }
check() {
  if eval "$2"; then ok "$1"; else
    fail "$1"
    [ -n "${3:-}" ] && eval "$3" 2>&1 | tail -15 | sed 's/^/       /'
  fi
}
heading() { echo; echo "== $1"; }
sql() { sqlite3 "$DB" "$1"; }
port_owner() { ss -ltnpH "sport = :$1" | grep -o '"[^"]*"' | head -1 | tr -d '"'; }
pid_of() { systemctl show -p MainPID --value "$1"; }
site_body() { curl -sk --max-time 8 --resolve "$1:443:127.0.0.1" "https://$1/"; }
http_get() { curl -s --max-time 8 -H "Host: $1" "http://127.0.0.1${2:-/}"; }

# An nginx reload returns before its new workers have taken over, so a site just created isn't
# served for a moment, and until then requests get the default server. Wait for that to pass, or
# what the checks after it see says nothing about the new site. (It takes about a quarter second.)
wait_until_served() {
  for _ in $(seq 1 100); do
    # Only the new vhost answers 403 for a dotfile. The default server answers 404, or nothing on CE.
    [ "$(curl -s -m2 -o /dev/null -w '%{http_code}' -H "Host: $1" http://127.0.0.1/.cloudpanel-served-check)" = 403 ] && return 0
    sleep 0.1
  done
  return 1
}

# Sites with no app behind them answer 502 forever, which proves nothing. Give them backends, run
# as the site users, the way a CE user runs their app: outside anything the panel manages.
start_backends() {
  local spec user port text
  for spec in nodesite:3100:node-ok pysite:3200:py-ok proxysite:3300:proxy-ok; do
    IFS=: read -r user port text <<<"$spec"
    mkdir -p "/home/$user/app"
    echo "$text" > "/home/$user/app/index.html"
    chown -R "$user:$user" "/home/$user/app"
    systemd-run --quiet --unit="backend-$user" --uid="$user" --working-directory="/home/$user/app" \
      python3 -m http.server "$port" --bind 127.0.0.1
  done
  sleep 2
}

cmd_setup() {
  systemctl start nginx mysql php8.4-fpm clp-php-fpm clp-nginx clp-agent 2>/dev/null
  start_backends
  clpctl db:add --domainName=php.test.local --databaseName=otherdb --databaseUserName=otheruser \
    --databaseUserPassword='Test-Only-Pass-1234' </dev/null >/dev/null 2>&1
  for d in php:php-ok static:static-ok node:node-ok py:py-ok proxy:proxy-ok; do
    check "${d%%:*} site answers before migrating" "site_body ${d%%:*}.test.local | grep -q ${d#*:}" "site_body ${d%%:*}.test.local"
  done
  exit "$failures"
}

package_versions() {
  dpkg-query -W -f='${Package} ${Version}\n' nginx nginx-common nginx-full php8.4-fpm percona-server-server cloudpanel
}

# Bytes and process IDs of what serves the sites, for comparing at the very end.
snapshot() {
  package_versions > /var/tmp/snap.packages
  find /etc/nginx/sites-enabled /etc/php/*/fpm/pool.d -type f ! -name 'cloudpanel-*' -print0 | sort -z | xargs -0 sha256sum > /var/tmp/snap.files
  sha256sum /etc/nginx/nginx.conf >> /var/tmp/snap.files
  for u in nginx mysql php8.4-fpm; do echo "$u $(pid_of "$u")"; done > /var/tmp/snap.pids
}
same_as_snapshot() {
  check "$1: site configs unchanged" "sha256sum --quiet -c /var/tmp/snap.files" "sha256sum -c /var/tmp/snap.files | grep -v OK"
  local u want
  while read -r u want; do
    check "$1: $u wasn't restarted" "[ \"\$(pid_of $u)\" = $want ]" "echo was $want, is \$(pid_of $u)"
  done < /var/tmp/snap.pids
}

test_preflight() {
  heading "preflight"
  snapshot
  check "preflight passes" "$MIGRATE preflight --binary $BIN --yes > /var/tmp/preflight.log 2>&1" "cat /var/tmp/preflight.log"
  check "lists the PHP site" "grep -q 'php  php.test.local' /var/tmp/preflight.log" "cat /var/tmp/preflight.log"
  check "makes no state of its own" "[ ! -e $STATE ]"
  same_as_snapshot "after preflight"
}

test_prepare() {
  heading "prepare ($1)"
  check "prepare succeeds" "$MIGRATE prepare --binary $BIN $1 --yes > /var/tmp/prepare.log 2>&1" "cat /var/tmp/prepare.log"
  check "new panel on the side port" "[ \"\$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8442/api/auth/me)\" = 401 ]"
  check "CE still owns its port" "[ \"\$(port_owner 8443)\" = nginx ]"
  check "CE's panel is still running" "systemctl is-active --quiet clp-nginx clp-php-fpm clp-agent"
  check "the package isn't held yet" "! apt-mark showhold | grep -qx cloudpanel"
  check "what serves the sites wasn't upgraded" "[ \"\$(package_versions)\" = \"\$(cat /var/tmp/snap.packages)\" ]" "package_versions | diff - /var/tmp/snap.packages"
  same_as_snapshot "after prepare"
}

test_imported_records() {
  heading "what was imported"
  check "static site" "[ \"\$(sql \"select site_type from sites where domain='static.test.local'\")\" = static ]"
  check "reverse proxy keeps its port" "[ \"\$(sql \"select site_type||':'||target_port from sites where domain='proxy.test.local'\")\" = reverse_proxy:3300 ]"
  check "Node.js site keeps its port" "[ \"\$(sql \"select target_port from sites where domain='node.test.local'\")\" = 3100 ]"
  check "every imported vhost is protected" "[ \"\$(sql 'select count(*) from sites where vhost_managed=1')\" = 0 ]"
  check "no app was started for an imported site" "[ \"\$(sql 'select count(*) from sites where app_enabled=1')\" = 0 ]"
  check "certificate read from the vhost" "[ \"\$(sql \"select ssl_cert_path from sites where domain='static.test.local'\")\" = /etc/nginx/ssl-certificates/static.test.local.crt ]"
  check "document root read from the vhost" "[ \"\$(sql \"select document_root from sites where domain='static.test.local'\")\" = /home/staticsite/htdocs/static.test.local ]"
  check "CE's admin imported as an admin" "[ \"\$(sql \"select role from users where username='ceadmin'\")\" = admin ]"
  check "its new password is saved privately" "grep -q '^ceadmin' $STATE/panel-users.txt && [ \"\$(stat -c %a $STATE/panel-users.txt)\" = 600 ]"
}

# A real session, so that this goes through the API rather than the database.
api_login() {
  local port=$1 user pass
  user=ceadmin
  pass=$(awk -F'\t' '$1=="ceadmin"{print $2}' "$STATE/panel-users.txt")
  rm -f /var/tmp/jar
  curl -sk -c /var/tmp/jar -o /dev/null -H 'Content-Type: application/json' -H 'X-Requested-With: cloudpanel' \
    -H "Origin: https://127.0.0.1:$port" -d "{\"username\":\"$user\",\"password\":\"$pass\"}" \
    -w '%{http_code}' "https://127.0.0.1:$port/api/auth/login"
}
api() {
  local port=$1 method=$2 path=$3 data=${4:-}
  curl -sk -b /var/tmp/jar -X "$method" -H 'Content-Type: application/json' -H 'X-Requested-With: cloudpanel' \
    -H "Origin: https://127.0.0.1:$port" ${data:+-d "$data"} "https://127.0.0.1:$port/api$path"
}
json() { python3 -c "import json,sys; d=json.load(sys.stdin); print($1)"; }

test_panel_protects_sites() {
  local port=$1 id before
  heading "the new panel can't break an imported site"
  check "CE's admin can sign in with the new password" "[ \"\$(api_login $port)\" = 200 ]" "api_login $port"
  id=$(sql "select id from sites where domain='static.test.local'")
  before=$(sha256sum /etc/nginx/sites-enabled/static.test.local.conf)
  local out
  out=$(api "$port" PATCH "/sites/$id" '{"max_body_mb":99}')
  check "saving settings is refused with a reason" "echo \"\$out\" | grep -q 'imported from CloudPanel CE'" "echo \"\$out\""
  out=$(api "$port" POST "/sites/$id/state" '{"active":false}')
  check "disabling is refused too" "echo \"\$out\" | grep -q 'imported from CloudPanel CE'" "echo \"\$out\""
  out=$(api "$port" DELETE "/sites/$id/ssl")
  check "removing the certificate is refused too" "echo \"\$out\" | grep -q 'imported from CloudPanel CE'" "echo \"\$out\""
  out=$(api "$port" PUT "/sites/$id/directives" '{"custom_directives":"# nothing"}')
  check "custom directives are refused too" "echo \"\$out\" | grep -q 'imported from CloudPanel CE'" "echo \"\$out\""
  out=$(api "$port" PUT "/sites/$id/basic-auth" '{"enabled":false,"allow":[]}')
  check "password protection is refused too" "echo \"\$out\" | grep -q 'imported from CloudPanel CE'" "echo \"\$out\""
  out=$(api "$port" POST "/sites/$id/basic-auth/users" '{"username":"someone","password":"Test-Only-Pass-1234"}')
  check "adding a password user is refused, rather than doing nothing" "echo \"\$out\" | grep -q 'imported from CloudPanel CE'" "echo \"\$out\""
  # certbot's nginx plugin edits and reloads nginx, so it mustn't even start.
  local reloads
  reloads=$(journalctl -u nginx --no-pager -q | grep -c 'Reloaded nginx')
  out=$(api "$port" POST "/sites/$id/ssl" '{"email":"someone@test.local"}')
  check "a Let's Encrypt request is refused too" "echo \"\$out\" | grep -q 'imported from CloudPanel CE'" "echo \"\$out\""
  check "before certbot could touch nginx" "[ \"\$(journalctl -u nginx --no-pager -q | grep -c 'Reloaded nginx')\" = $reloads ] && ! [ -e /etc/letsencrypt/live/static.test.local ]"
  check "the vhost is byte for byte the same" "[ \"\$(sha256sum /etc/nginx/sites-enabled/static.test.local.conf)\" = \"\$before\" ]"
  check "the site's record wasn't changed" "[ \"\$(sql \"select is_active from sites where id=$id\")\" = 1 ]"
  check "the site still answers" "site_body static.test.local | grep -q static-ok"
  out=$(api "$port" GET "/sites/$id/vhost")
  check "the vhost can be read in the panel" "echo \"\$out\" | grep -q 'ssl-certificates/static.test.local.crt'" "echo \"\$out\" | head -c 300"
}

test_new_site_alongside() {
  local port=$1 out id
  heading "new sites work next to CE's nginx config"
  out=$(api "$port" POST /sites '{"domain":"new.test.local","site_type":"reverse_proxy","target_port":3300}')
  id=$(echo "$out" | json "d['id']" 2>/dev/null)
  check "a WebSocket proxy site can be created (needs the upgrade map to load)" "[ -n \"$id\" ]" "echo \"\$out\""
  check "nginx loaded it" "wait_until_served new.test.local"
  check "and proxies to the app" "http_get new.test.local | grep -q proxy-ok" "http_get new.test.local | head -c 200"
  check "the map is where CE's nginx reads it" "[ -f /etc/nginx/sites-enabled/cloudpanel-upgrade-map.conf ]"
  check "nginx still accepts its config" "nginx -t 2>/dev/null"
  out=$(api "$port" DELETE "/sites/$id?delete_files=true")
  check "and can be deleted again" "echo \"\$out\" | grep -q deleted" "echo \"\$out\""
  check "taking the others with it" "site_body static.test.local | grep -q static-ok"
}

# New and CE's PHP sites side by side, on the PHP-FPM CE installed.
test_new_php_site() {
  local port=$1 out id root
  heading "a new PHP site next to CE's"
  out=$(api "$port" POST /sites '{"domain":"newphp.test.local","site_type":"php"}')
  id=$(echo "$out" | json "d['id']" 2>/dev/null)
  check "it can be created" "[ -n \"$id\" ]" "echo \"\$out\""
  [ -n "$id" ] || return 0
  check "with the newest PHP installed" "[ \"\$(sql \"select php_version from sites where id=$id\")\" = 8.5 ]" "sql \"select php_version from sites where id=$id\""
  root=$(sql "select document_root from sites where id=$id")
  printf '<?php echo "newphp-ok ", get_current_user(), " ", posix_getpwuid(posix_geteuid())["name"];' > "$root/index.php"
  chown "$(stat -c %U "$root"):$(stat -c %G "$root")" "$root/index.php"
  rm -f "$root/index.html"
  check "nginx loaded it" "wait_until_served newphp.test.local"
  check "PHP runs" "http_get newphp.test.local | grep -q newphp-ok" "http_get newphp.test.local | head -c 300; systemctl status php8.5-fpm --no-pager | tail -5"
  check "as the site's own user" "http_get newphp.test.local | grep -q \"newphp-ok \$(stat -c %U $root) \$(stat -c %U $root)\"" "http_get newphp.test.local"
  out=$(api "$port" DELETE "/sites/$id?delete_files=true")
  check "deleting it removes its pool" "! ls /etc/php/8.5/fpm/pool.d/newphp.test.local.conf 2>/dev/null" "echo \"\$out\""
  check "CE's PHP site still runs" "site_body php.test.local | grep -q 'php-ok.*db=ok'"
}

test_new_database() {
  local port=$1 id out
  heading "the panel manages MySQL on a migrated server"
  id=$(sql "select id from sites where domain='php.test.local'")
  out=$(api "$port" POST "/sites/$id/databases" '{"engine":"mariadb","name":"paneldb"}')
  check "a database can be created with CE's root login" "mysql --defaults-extra-file=/etc/cloudpanel/mysql-admin.cnf -e 'use paneldb' 2>/dev/null" "echo \"\$out\""
  local dbid
  # Not the user the PHP site logs in with: changing that would fail the requests probing the site.
  dbid=$(api "$port" GET "/sites/$id/databases" | python3 -c "import json,sys; print(next(d['id'] for d in json.load(sys.stdin) if d['name']=='otherdb'))" 2>/dev/null)
  out=$(api "$port" POST "/databases/$dbid/users/otheruser/password" '{"password":"Test-Only-New-5678"}')
  check "a CE database user's password can be reset (they are @'%', not @'localhost')" \
    "MYSQL_PWD=Test-Only-New-5678 mysql -uotheruser -h127.0.0.1 -e 'select 1' >/dev/null 2>&1" "echo \"\$out\""
}

test_databases() {
  local port=$1 out dbs
  heading "databases"
  dbs=$(api "$port" GET "/sites/$(sql "select id from sites where domain='$2'")/databases")
  check "CE's database is listed under its site" "echo \"\$dbs\" | grep -q phpdb" "echo \"\$dbs\""
  check "MySQL credentials work for the panel" "mysql --defaults-extra-file=/etc/cloudpanel/mysql-admin.cnf -e 'select 1' >/dev/null 2>&1"
  check "that file is private" "[ \"\$(stat -c %a /etc/cloudpanel/mysql-admin.cnf)\" = 600 ]"
}

test_cutover() {
  heading "cutover"
  check "cutover succeeds" "$MIGRATE cutover --yes > /var/tmp/cutover.log 2>&1" "cat /var/tmp/cutover.log"
  check "new panel now owns the port" "[ \"\$(port_owner 8443)\" = cloudpanel ]"
  check "new panel answers there" "[ \"\$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/api/auth/me)\" = 401 ]"
  check "the side port is closed" "! ss -ltnH 'sport = :8442' | grep -q ."
  check "CE's panel is stopped" "! systemctl is-active --quiet clp-nginx && ! systemctl is-active --quiet clp-php-fpm && ! systemctl is-active --quiet clp-agent"
  check "and won't come back at boot" "! systemctl is-enabled --quiet clp-nginx && ! systemctl is-enabled --quiet clp-php-fpm && ! systemctl is-enabled --quiet clp-agent"
  check "the package is held, so apt can't restart it" "apt-mark showhold | grep -qx cloudpanel"
  check "certificate renewal stays scheduled" "grep -q '^[0-9].*lets-encrypt:renew:certificates' /etc/cron.d/clp"
  check "CE's backups stay scheduled" "grep -q '^[0-9].*db:backup' /etc/cron.d/clp"
  check "only the agent restart was disabled" "[ \"\$(grep -c '^# disabled by migrate' /etc/cron.d/clp)\" = 1 ]"
  check "renewal still runs with CE's panel stopped" "su -s /bin/bash -c '/usr/bin/clpctl lets-encrypt:renew:certificates' clp </dev/null >/dev/null 2>&1"
  same_as_snapshot "after cutover"
}

test_reboot_safe_units() {
  heading "after cutover, what starts at boot"
  check "new panel is enabled" "systemctl is-enabled --quiet cloudpanel"
  check "its port is saved" "grep -q '^CLOUDPANEL_BIND=0.0.0.0:8443' /etc/cloudpanel/cloudpanel.env"
}

test_rollback() {
  heading "rollback"
  check "rollback succeeds" "$MIGRATE rollback --yes > /var/tmp/rollback.log 2>&1" "cat /var/tmp/rollback.log"
  check "CE owns its port again" "[ \"\$(port_owner 8443)\" = nginx ]"
  check "CE's panel answers" "curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/ | grep -qE '^(2|3)'"
  check "all of CE's panel is running" "systemctl is-active --quiet clp-nginx clp-php-fpm clp-agent"
  check "and will start at boot" "systemctl is-enabled --quiet clp-nginx clp-php-fpm clp-agent"
  check "the new panel is stopped" "! systemctl is-active --quiet cloudpanel"
  check "and won't start at boot" "! systemctl is-enabled --quiet cloudpanel"
  check "the package is no longer held" "! apt-mark showhold | grep -qx cloudpanel"
  check "the cron file is as it was" "cmp -s /etc/cron.d/clp $STATE/clp-cron.original"
  check "CE's apt settings are as they were" "[ ! -e /etc/apt/preferences.d/01-cloudpanel-rust.pref ]"
  check "the new panel's data is kept" "[ -s $DB ]"
  same_as_snapshot "after rollback"
}

# The new panel won't start. The script has to notice and put CE back by itself.
test_automatic_undo() {
  heading "a broken new panel undoes the cutover by itself"
  cp -p /usr/local/bin/cloudpanel /var/tmp/cloudpanel.good
  rm -f /usr/local/bin/cloudpanel
  printf '#!/bin/sh\necho broken on purpose >&2\nexit 1\n' > /usr/local/bin/cloudpanel
  chmod +x /usr/local/bin/cloudpanel
  check "cutover reports the failure" "! $MIGRATE cutover --yes > /var/tmp/cutover-bad.log 2>&1" "cat /var/tmp/cutover-bad.log"
  rm -f /usr/local/bin/cloudpanel
  cp -p /var/tmp/cloudpanel.good /usr/local/bin/cloudpanel
  check "it says it went back" "grep -q 'cutover was undone' /var/tmp/cutover-bad.log" "cat /var/tmp/cutover-bad.log"
  check "CE owns its port again" "[ \"\$(port_owner 8443)\" = nginx ]"
  check "CE's panel answers" "curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/ | grep -qE '^(2|3)'"
  check "the package is no longer held" "! apt-mark showhold | grep -qx cloudpanel"
  same_as_snapshot "after the failed cutover"
}

test_catches_up() {
  heading "a site added in CE after prepare"
  clpctl site:add:static --domainName=late.test.local --siteUser=latesite --siteUserPassword='Test-Only-Pass-1234' </dev/null >/dev/null 2>&1
  check "CE made it" "[ -f /etc/nginx/sites-enabled/late.test.local.conf ]"
}

cmd_with_php() {
  test_preflight
  test_prepare --with-php
  test_imported_records
  check "PHP site imported with its version" "[ \"\$(sql \"select site_type||':'||php_version from sites where domain='php.test.local'\")\" = php:8.4 ]"
  check "PHP is enabled in the new panel" "grep -q '^CLOUDPANEL_PHP=1' /etc/cloudpanel/cloudpanel.env"
  test_panel_protects_sites 8442
  test_new_site_alongside 8442
  test_new_php_site 8442
  test_databases 8442 php.test.local
  test_new_database 8442
  test_catches_up
  snapshot
  test_automatic_undo
  test_cutover
  check "the late site was imported at cutover" "[ \"\$(sql \"select count(*) from sites where domain='late.test.local'\")\" = 1 ]"
  test_reboot_safe_units
  test_panel_protects_sites 8443
  test_rollback
  test_cutover
  check "running it twice added no duplicates" "[ \"\$(sql \"select count(*) from sites where domain='php.test.local'\")\" = 1 ]"
  exit "$failures"
}

cmd_without_php() {
  test_preflight
  test_prepare --no-php
  test_imported_records
  check "the PHP site isn't in the panel" "[ \"\$(sql \"select count(*) from sites where domain='php.test.local'\")\" = 0 ]"
  check "and the report says so" "grep -q 'php site left unmanaged: php.test.local' $STATE/import.log" "cat $STATE/import.log"
  check "PHP is off in the new panel" "grep -q '^CLOUDPANEL_PHP=0' /etc/cloudpanel/cloudpanel.env"
  api_login 8442 >/dev/null
  local out
  out=$(api 8442 POST /sites '{"domain":"nophp.test.local","site_type":"php"}')
  check "a PHP site can't be created" "echo \"\$out\" | grep -q 'with-php'" "echo \"\$out\""
  check "the form doesn't offer PHP" "api 8442 GET /sites/options | grep -q '\"php_enabled\":false'"
  test_cutover
  check "the PHP site still runs PHP and reaches its database" "site_body php.test.local | grep -q 'php-ok.*db=ok'" "site_body php.test.local"
  exit "$failures"
}

# ---------- Moving certificates to certbot, then removing CE for good ----------

# What Let's Encrypt or someone else issued, in the place CE keeps it. CE's test install only has
# self-signed certificates, and the real ones need a public domain.
seed_cert() {
  local domain=$1 org=$2 dir=/etc/nginx/ssl-certificates
  openssl req -x509 -newkey rsa:2048 -nodes -days 60 -subj "/O=$org/CN=$domain" \
    -addext "subjectAltName=DNS:$domain" -keyout "$dir/$domain.key" -out "$dir/$domain.crt" >/dev/null 2>&1
}

cmd_setup_removal() {
  systemctl start nginx mysql php8.4-fpm clp-php-fpm clp-nginx clp-agent 2>/dev/null
  start_backends
  seed_cert static.test.local "Let's Encrypt"
  seed_cert node.test.local "Let's Encrypt"
  seed_cert proxy.test.local "Some Other CA"
  nginx -t >/dev/null 2>&1 && systemctl reload nginx
  sleep 1
  # Data that has to survive: CE's removal scripts would delete all of it.
  clpctl db:add --domainName=static.test.local --databaseName=keepdb --databaseUserName=keepuser \
    --databaseUserPassword='Test-Only-Pass-1234' </dev/null >/dev/null 2>&1
  local creds password
  creds=$(clpctl db:show:master-credentials </dev/null 2>/dev/null)
  password=$(printf '%s\n' "$creds" | sed -n 's/^| Password *| *\([^ ]*\) .*/\1/p')
  MYSQL_PWD="$password" mysql -uroot -h127.0.0.1 keepdb -e "CREATE TABLE t (v TEXT); INSERT INTO t VALUES ('survived')"
  for d in static:static-ok node:node-ok py:py-ok proxy:proxy-ok; do
    check "${d%%:*} site answers before migrating" "site_body ${d%%:*}.test.local | grep -q ${d#*:}" "site_body ${d%%:*}.test.local"
  done
  check "the test database holds its marker" "MYSQL_PWD='$password' mysql -uroot -h127.0.0.1 -N keepdb -e 'select v from t' | grep -q survived"
  exit "$failures"
}

served_cert() {
  openssl s_client -servername "$1" -connect 127.0.0.1:443 </dev/null 2>/dev/null | openssl x509 -noout "$2"
}
keep_marker() { mysql --defaults-extra-file=/etc/cloudpanel/mysql-admin.cnf -N keepdb -e 'select v from t' 2>/dev/null; }
vhost_hashes() { find /etc/nginx/sites-enabled -type f ! -name 'cloudpanel-*' -print0 | sort -z | xargs -0 sha256sum; }

cmd_removal() {
  local out serial id before
  heading "before removing anything"
  check "prepare succeeds" "$MIGRATE prepare --binary $BIN --no-php --yes > /var/tmp/prepare.log 2>&1" "cat /var/tmp/prepare.log"
  check "cutover succeeds" "$MIGRATE cutover --yes > /var/tmp/cutover.log 2>&1" "cat /var/tmp/cutover.log"
  vhost_hashes > /var/tmp/vhosts.before
  echo "nginx $(pid_of nginx)" > /var/tmp/pids.before
  echo "mysql $(pid_of mysql)" >> /var/tmp/pids.before

  heading "remove-ce refuses while a PHP site exists"
  check "it refuses" "! $MIGRATE remove-ce --yes > /var/tmp/refuse1.log 2>&1" "cat /var/tmp/refuse1.log"
  check "and names the site" "grep -q 'php.test.local' /var/tmp/refuse1.log" "cat /var/tmp/refuse1.log"
  check "CE's package is still there and still held" "dpkg-query -W -f='\${Status}' cloudpanel | grep -q 'hold ok installed'"
  check "PHP is still there" "[ -d /etc/php/8.4 ]"
  check "CE's removal scripts weren't touched" "grep -q 'delete:sites' /var/lib/dpkg/info/cloudpanel.prerm"
  clpctl site:delete --domainName=php.test.local --force </dev/null >/dev/null 2>&1
  check "the test's PHP site is gone" "[ ! -f /etc/nginx/sites-enabled/php.test.local.conf ]"
  vhost_hashes > /var/tmp/vhosts.before

  heading "remove-ce refuses while a certificate depends on CE"
  check "it refuses" "! $MIGRATE remove-ce --yes > /var/tmp/refuse2.log 2>&1" "cat /var/tmp/refuse2.log"
  check "and names the certificates" "grep -q 'still renewed by ce: static.test.local' /var/tmp/refuse2.log && grep -q 'still renewed by ce: node.test.local' /var/tmp/refuse2.log" "cat /var/tmp/refuse2.log"
  check "but not the one that isn't from Let's Encrypt" "! grep -q 'still renewed by ce: proxy' /var/tmp/refuse2.log"
  check "or the self-signed one" "! grep -q 'still renewed by ce: py' /var/tmp/refuse2.log"

  heading "moving certificates to certbot, domain by domain"
  serial=$(served_cert static.test.local -serial)
  check "a dry run passes" "$MIGRATE move-certs --email admin@example.com --dry-run > /var/tmp/dry.log 2>&1" "cat /var/tmp/dry.log"
  check "it covers what can move" "grep -q 'can be moved: static.test.local' /var/tmp/dry.log && grep -q 'can be moved: node.test.local' /var/tmp/dry.log" "cat /var/tmp/dry.log"
  check "and skips what can't" "grep -q 'not let.s encrypt, nothing renews it: proxy.test.local' /var/tmp/dry.log" "cat /var/tmp/dry.log"
  check "and changes nothing" "[ \"\$(served_cert static.test.local -serial)\" = '$serial' ] && [ ! -e /etc/letsencrypt/renewal/static.test.local.conf ]"
  check "one domain can move alone" "$MIGRATE move-certs --email admin@example.com --domain static.test.local > /var/tmp/one.log 2>&1" "cat /var/tmp/one.log"
  check "leaving the other on CE" "[ ! -e /etc/letsencrypt/renewal/node.test.local.conf ]"
  sleep 1
  check "nginx serves the new certificate" "served_cert static.test.local -issuer | grep -qi pebble" "served_cert static.test.local -issuer"
  check "CE's original is kept" "[ -s /etc/nginx/ssl-certificates/static.test.local.crt.ce ] && [ -s /etc/nginx/ssl-certificates/static.test.local.key.ce ]"
  check "the private key stays private" "[ \"\$(stat -c %a /etc/nginx/ssl-certificates/static.test.local.key)\" = 600 ]"
  check "the vhost didn't change" "sha256sum --quiet -c /var/tmp/vhosts.before" "sha256sum -c /var/tmp/vhosts.before | grep -v OK"
  check "nginx wasn't restarted" "[ \"nginx \$(pid_of nginx)\" = \"\$(head -1 /var/tmp/pids.before)\" ]"

  heading "a domain that fails doesn't stop the others"
  mv /home/nodesite/htdocs/node.test.local /home/nodesite/htdocs/node.moved
  check "move-certs reports the failure" "! $MIGRATE move-certs --email admin@example.com > /var/tmp/partial.log 2>&1" "cat /var/tmp/partial.log"
  check "naming the domain" "grep -q 'failed: node.test.local' /var/tmp/partial.log" "cat /var/tmp/partial.log"
  check "the other stays moved" "grep -q 'renewed by certbot: static.test.local' /var/tmp/partial.log" "cat /var/tmp/partial.log"
  check "the failed site keeps its certificate" "served_cert node.test.local -issuer | grep -q 'Encrypt'" "served_cert node.test.local -issuer"
  mv /home/nodesite/htdocs/node.moved /home/nodesite/htdocs/node.test.local
  check "and it works once fixed" "$MIGRATE move-certs --email admin@example.com > /var/tmp/rest.log 2>&1" "cat /var/tmp/rest.log"

  heading "certbot really renews, and nginx follows"
  serial=$(served_cert static.test.local -serial)
  check "a forced renewal succeeds" "certbot renew --no-verify-ssl --force-renewal --non-interactive --cert-name static.test.local > /var/tmp/renew.log 2>&1" "tail -15 /var/tmp/renew.log"
  check "the hook is in place" "[ -x /etc/letsencrypt/renewal-hooks/deploy/cloudpanel-ce-certs ]"
  sleep 2
  check "nginx serves the renewed certificate" "[ \"\$(served_cert static.test.local -serial)\" != '$serial' ]" "served_cert static.test.local -serial; ls -la /etc/letsencrypt/renewal-hooks/deploy/; tail -5 /var/tmp/renew.log"
  check "certbot's timer is on" "systemctl is-enabled --quiet certbot.timer"
  check "CE's admin can sign in" "[ \"\$(api_login 8443)\" = 200 ]"
  id=$(sql "select id from sites where domain='static.test.local'")
  check "the panel says certbot renews it" "api 8443 GET /sites/$id | grep -q '\"certificate_renewal\":\"certbot\"'" "api 8443 GET /sites/$id | head -c 400"
  check "and can renew it now" "api 8443 GET /sites/$id | grep -q '\"certificate_managed\":true'"
  id=$(sql "select id from sites where domain='proxy.test.local'")
  check "and says nothing renews an uploaded one" "api 8443 GET /sites/$id | grep -q '\"certificate_renewal\":\"none\"'" "api 8443 GET /sites/$id | head -c 400"
  out=$(api 8443 POST "/sites/$id/ssl/takeover" '{"email":"admin@example.com"}')
  check "and refuses to move it" "echo \"\$out\" | grep -q 'not Let.s Encrypt'" "echo \"\$out\""

  heading "remove-ce"
  check "it succeeds" "$MIGRATE remove-ce --yes > /var/tmp/remove.log 2>&1" "cat /var/tmp/remove.log"
  check "its own checks saw no restart" "grep -q 'nginx and MySQL were not restarted' /var/tmp/remove.log" "cat /var/tmp/remove.log"

  heading "what's gone"
  check "CE's package" "! dpkg-query -W cloudpanel >/dev/null 2>&1 || ! dpkg-query -W -f='\${db:Status-Abbrev}' cloudpanel | grep -q '^ii'"
  check "every version of PHP" "[ -z \"\$(dpkg-query -W -f='\${Package} \${db:Status-Abbrev}\n' 'php*' 2>/dev/null | awk '\$2 ~ /^ii/')\" ]" "dpkg-query -W -f='\${Package} \${db:Status-Abbrev}\n' 'php*' | awk '\$2 ~ /^ii/' | head"
  check "PHP's config and services" "[ ! -d /etc/php ] && ! systemctl list-unit-files --no-legend 'php*-fpm.service' | grep -q ."
  check "CE's services" "! systemctl list-unit-files --no-legend 'clp-*' | grep -q . && ! pgrep -x clp-agent >/dev/null"
  check "CE's tools" "[ ! -e /usr/bin/clpctl ] && [ ! -e /usr/bin/clpctlWrapper ] && [ ! -e /usr/sbin/clp-agent ]" "command -v clpctl; ls -la /usr/bin/clp* /usr/sbin/clp-agent; dpkg-query -W -f='\${db:Status-Abbrev}
' cloudpanel; tail -5 $STATE/remove-ce.log"
  check "CE's cron jobs" "[ -z \"\$(ls /etc/cron.d/clp* 2>/dev/null)\" ]"
  check "CE's passwordless sudo" "[ ! -e /etc/sudoers.d/cloudpanel ] && ! grep -q clp /etc/sudoers"
  check "sudo still works" "visudo -c >/dev/null 2>&1"
  check "the clp user" "! getent passwd clp >/dev/null && [ ! -d /home/clp ]"

  heading "what must stay"
  check "the databases, with their data" "[ \"\$(keep_marker)\" = survived ]" "keep_marker; ls -ld /home/mysql"
  check "MySQL's data directory" "[ -d /home/mysql/mysql ]"
  check "site files" "[ -s /home/staticsite/htdocs/static.test.local/index.html ]"
  check "site users" "getent passwd staticsite nodesite pysite proxysite >/dev/null"
  check "vhosts, byte for byte" "sha256sum --quiet -c /var/tmp/vhosts.before" "sha256sum -c /var/tmp/vhosts.before | grep -v OK"
  check "nginx wasn't restarted" "[ \"nginx \$(pid_of nginx)\" = \"\$(head -1 /var/tmp/pids.before)\" ]"
  check "MySQL wasn't restarted" "[ \"mysql \$(pid_of mysql)\" = \"\$(tail -1 /var/tmp/pids.before)\" ]"
  check "the new panel owns the port" "[ \"\$(port_owner 8443)\" = cloudpanel ]"
  check "every site answers" "site_body static.test.local | grep -q static-ok && site_body node.test.local | grep -q node-ok && site_body py.test.local | grep -q py-ok && site_body proxy.test.local | grep -q proxy-ok"
  check "a site user can still log in, with no errors" "[ -z \"\$(su - nodesite -c true 2>&1)\" ]" "su - nodesite -c true"
  check "CE's data is saved privately" "ls /var/backups/cloudpanel/ce-archive-*.tar.gz >/dev/null && [ \"\$(stat -c %a /var/backups/cloudpanel/ce-archive-*.tar.gz)\" = 600 ]"
  check "and holds its database" "[ -n \"\$(tar -tzf /var/backups/cloudpanel/ce-archive-*.tar.gz | grep 'home/clp/htdocs/app/data/db.sq3')\" ]" "tar -tzf /var/backups/cloudpanel/ce-archive-*.tar.gz | head -5; ls -la /var/backups/cloudpanel"

  heading "living without CE"
  serial=$(served_cert node.test.local -serial)
  check "certbot still renews" "certbot renew --no-verify-ssl --force-renewal --non-interactive --cert-name node.test.local > /var/tmp/renew2.log 2>&1" "tail -15 /var/tmp/renew2.log"
  sleep 2
  check "and nginx follows" "[ \"\$(served_cert node.test.local -serial)\" != '$serial' ]"
  apt-get update -q >/dev/null 2>&1
  check "apt wouldn't downgrade anything" "! LC_ALL=C apt-get -s -q upgrade 2>/dev/null | grep -q DOWNGRADED"
  # shellcheck disable=SC2016
  check "autoremove wouldn't touch what serves sites" "! LC_ALL=C apt-get -s -q autoremove 2>/dev/null | grep -E '^Remv (nginx|libnginx|percona|mysql|mariadb|redis|varnish|proftpd|certbot|fail2ban|ufw|cron) '" "LC_ALL=C apt-get -s -q autoremove | grep '^Remv' | head -30"
  check "a real autoremove runs" "DEBIAN_FRONTEND=noninteractive apt-get -y -q autoremove > /var/tmp/autoremove.log 2>&1" "tail -10 /var/tmp/autoremove.log"
  check "a real upgrade runs" "DEBIAN_FRONTEND=noninteractive apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade > /var/tmp/upgrade.log 2>&1" "tail -10 /var/tmp/upgrade.log"
  check "the databases are still there" "[ \"\$(keep_marker)\" = survived ]"
  check "the panel can still manage MySQL" "api_login 8443 >/dev/null; api 8443 POST /sites/\$(sql \"select id from sites where domain='static.test.local'\")/databases '{\"engine\":\"mariadb\",\"name\":\"newdb\"}' >/dev/null; mysql --defaults-extra-file=/etc/cloudpanel/mysql-admin.cnf -e 'use newdb' 2>/dev/null"
  check "rollback refuses, and says why" "! $MIGRATE rollback --yes > /var/tmp/rb.log 2>&1 && grep -q 'snapshot' /var/tmp/rb.log" "cat /var/tmp/rb.log"
  check "prepare refuses" "! $MIGRATE prepare --binary $BIN --no-php --yes >/dev/null 2>&1"
  check "running remove-ce again is harmless" "$MIGRATE remove-ce --yes 2>&1 | grep -q 'already been removed'"
  exit "$failures"
}

cmd_after_removal_reboot() {
  heading "after a reboot, with CE gone"
  sleep 5
  check "the new panel came back" "[ \"\$(port_owner 8443)\" = cloudpanel ]"
  check "the static site answers" "site_body static.test.local | grep -q static-ok"
  check "with certbot's certificate" "served_cert static.test.local -issuer | grep -qi pebble"
  check "the databases are there" "[ \"\$(keep_marker)\" = survived ]"
  exit "$failures"
}

# After restarting the server, with the migration done.
cmd_after_reboot() {
  heading "after a reboot"
  sleep 5
  check "the new panel came back on the port" "[ \"\$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/api/auth/me)\" = 401 ]"
  check "and owns it" "[ \"\$(port_owner 8443)\" = cloudpanel ]"
  check "CE's panel stayed down" "! systemctl is-active --quiet clp-nginx && ! systemctl is-active --quiet clp-php-fpm && ! systemctl is-active --quiet clp-agent"
  check "the static site answers" "site_body static.test.local | grep -q static-ok"
  check "the PHP site runs PHP and reaches its database" "site_body php.test.local | grep -q 'php-ok.*db=ok'" "site_body php.test.local"
  test_real_upgrade
  exit "$failures"
}

# CE's pin makes apt want to downgrade packages, and apt-get -y upgrade then refuses to run at all.
# Upgrades are the first thing anyone does in the new panel, so run a real one, the way it does.
test_real_upgrade() {
  heading "apt upgrades after migrating"
  apt-get update -q >/dev/null 2>&1
  check "nothing would be downgraded" "! LC_ALL=C apt-get -s -q upgrade 2>/dev/null | grep -q DOWNGRADED" "LC_ALL=C apt-get -s -q upgrade 2>/dev/null | sed -n '/DOWNGRADED/,+2p'"
  check "CE's copy of sgml-base is what was blocked" "grep -q '^Package: sgml-base' /etc/apt/preferences.d/01-cloudpanel-rust.pref" "ls -la /etc/apt/preferences.d/"
  check "CE's builds are still preferred for what serves sites" "[[ \"\$(apt-cache policy nginx)\" == *'Candidate: '*clp* ]]" "apt-cache policy nginx | head -5"
  check "the panel's upgrade command succeeds" "DEBIAN_FRONTEND=noninteractive apt-get -y -q -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold upgrade > /var/tmp/upgrade.log 2>&1" "tail -15 /var/tmp/upgrade.log"
  check "nothing is left to fail next time" "! LC_ALL=C apt-get -s -q upgrade 2>/dev/null | grep -q DOWNGRADED"
  check "CE's panel didn't come back" "! systemctl is-active --quiet clp-nginx && ! systemctl is-enabled --quiet clp-nginx"
  check "the new panel still owns the port" "[ \"\$(port_owner 8443)\" = cloudpanel ]"
  check "the static site answers after upgrading" "site_body static.test.local | grep -q static-ok"
  check "the PHP site still works after upgrading" "site_body php.test.local | grep -q 'php-ok.*db=ok'" "site_body php.test.local"
  check "fix-apt is safe to run again" "$MIGRATE fix-apt > /var/tmp/fix-apt.log 2>&1 && grep -q 'downgrade anything' /var/tmp/fix-apt.log" "cat /var/tmp/fix-apt.log"
  check "and keeps what it blocked" "grep -q '^Package: sgml-base' /etc/apt/preferences.d/01-cloudpanel-rust.pref"
}

# A plain server that never had CE: PHP is opt-in, and works when chosen.
cmd_fresh_no_php() {
  heading "fresh install, PHP not chosen"
  check "PHP is off" "grep -q '^CLOUDPANEL_PHP=0' /etc/cloudpanel/cloudpanel.env"
  check "PHP wasn't installed" "! ls -d /etc/php/*/fpm >/dev/null 2>&1"
  exit "$failures"
}

cmd_fresh_php() {
  local pass out id root code
  heading "fresh install with --with-php"
  check "PHP is on" "grep -q '^CLOUDPANEL_PHP=1' /etc/cloudpanel/cloudpanel.env"
  check "PHP-FPM was installed and runs" "systemctl list-units --type=service --state=running --no-legend | grep -qE 'php[0-9.]+-fpm'"
  pass=$(cat /var/lib/cloudpanel/initial_admin_password)
  rm -f /var/tmp/jar
  code=$(curl -sk -c /var/tmp/jar -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' -H 'X-Requested-With: cloudpanel' \
    -d "{\"username\":\"admin\",\"password\":\"$pass\"}" https://127.0.0.1:8443/api/auth/login)
  check "can sign in" "[ '$code' = 200 ]"
  check "the form offers PHP" "api 8443 GET /sites/options | grep -q '\"php_enabled\":true'"
  out=$(api 8443 POST /sites '{"domain":"fresh.test.local","site_type":"php"}')
  id=$(echo "$out" | json "d['id']" 2>/dev/null)
  check "a PHP site can be created" "[ -n \"$id\" ]" "echo \"\$out\""
  [ -n "$id" ] || exit "$failures"
  root=$(sql "select document_root from sites where id=$id")
  printf '<?php echo "fresh-ok ", posix_getpwuid(posix_geteuid())["name"];' > "$root/index.php"
  chown "$(stat -c %U "$root"):$(stat -c %G "$root")" "$root/index.php"
  rm -f "$root/index.html"
  check "nginx loaded it, and a dotfile isn't served" "wait_until_served fresh.test.local"
  check "PHP runs, as the site's own user" "http_get fresh.test.local | grep -q \"fresh-ok \$(stat -c %U $root)\"" "http_get fresh.test.local | head -c 300"
  # A marker the default server couldn't produce, so a 404 from it can't pass for this.
  echo 'not php <?php echo "executed";' > "$root/upload.txt"
  check "a text file isn't run as PHP" "http_get fresh.test.local /upload.txt | grep -q 'not php <?php'" "http_get fresh.test.local /upload.txt"
  check "a script that doesn't exist is a 404, not a PHP error" "[ \"\$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: fresh.test.local' http://127.0.0.1/nope.php)\" = 404 ]"
  out=$(api 8443 PATCH "/sites/$id" '{"max_body_mb":64}')
  check "unlike an imported site, its settings can be changed" "grep -q 'client_max_body_size 64M' /etc/nginx/sites-available/fresh.test.local.conf" "echo \"\$out\""
  check "and PHP still runs afterwards" "wait_until_served fresh.test.local && http_get fresh.test.local | grep -q fresh-ok"
  exit "$failures"
}

case "${1:-}" in
  after-reboot) cmd_after_reboot ;;
  setup-removal) cmd_setup_removal ;;
  removal) cmd_removal ;;
  after-removal-reboot) cmd_after_removal_reboot ;;
  fresh-no-php) cmd_fresh_no_php ;;
  fresh-php) cmd_fresh_php ;;
  setup) cmd_setup ;;
  with-php) cmd_with_php ;;
  without-php) cmd_without_php ;;
  *) echo "usage: $0 setup|with-php|without-php|after-reboot|fresh-php|fresh-no-php"; exit 2 ;;
esac
