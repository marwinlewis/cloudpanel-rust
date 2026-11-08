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

# After restarting the server, with the migration done.
cmd_after_reboot() {
  heading "after a reboot"
  sleep 5
  check "the new panel came back on the port" "[ \"\$(curl -sk -o /dev/null -w '%{http_code}' https://127.0.0.1:8443/api/auth/me)\" = 401 ]"
  check "and owns it" "[ \"\$(port_owner 8443)\" = cloudpanel ]"
  check "CE's panel stayed down" "! systemctl is-active --quiet clp-nginx && ! systemctl is-active --quiet clp-php-fpm && ! systemctl is-active --quiet clp-agent"
  check "the static site answers" "site_body static.test.local | grep -q static-ok"
  check "the PHP site runs PHP and reaches its database" "site_body php.test.local | grep -q 'php-ok.*db=ok'" "site_body php.test.local"
  exit "$failures"
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
  fresh-no-php) cmd_fresh_no_php ;;
  fresh-php) cmd_fresh_php ;;
  setup) cmd_setup ;;
  with-php) cmd_with_php ;;
  without-php) cmd_without_php ;;
  *) echo "usage: $0 setup|with-php|without-php|after-reboot|fresh-php|fresh-no-php"; exit 2 ;;
esac
