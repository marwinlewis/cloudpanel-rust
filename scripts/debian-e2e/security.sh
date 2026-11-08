#!/usr/bin/env bash
# Attacks on a real install, from where an attacker would really be: a site manager's login and a
# shell as a site's Linux user, against root, MariaDB, nginx and systemd. Only for the throwaway
# container that `run.sh --security` starts, as this plants links and takes the panel down.
#
#   security.sh attack         Everything that needs the sites set up
#   security.sh after-reboot   What must still hold after a reboot
#
# Checks are strings that `check` evaluates later, so what looks unexpanded or unused isn't.
# shellcheck disable=SC2016,SC2034
set -u
API=https://127.0.0.1:8443/api
ADMIN=/var/tmp/sec-admin.jar
MGR=/var/tmp/sec-manager.jar
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ok   $*"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL $*"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
retry() { for _ in $(seq 1 60); do eval "$1" && return 0; sleep 0.5; done; return 1; }
req() { # jar method path [json]
  curl -sk -b "$1" -c "$1" -X "$2" -H 'X-Requested-With: cloudpanel' -H 'Content-Type: application/json' \
    ${4:+-d "$4"} "$API$3"
}
code() { # jar method path [json] -> HTTP status
  curl -sk -o /dev/null -w '%{http_code}' -b "$1" -c "$1" -X "$2" -H 'X-Requested-With: cloudpanel' \
    -H 'Content-Type: application/json' ${4:+-d "$4"} "$API$3"
}
admin() { req "$ADMIN" "$@"; }
mgr() { req "$MGR" "$@"; }
mgr_upload() { # path file [extra curl args...] -> body
  local p=$1 f=$2
  shift 2
  curl -sk -b "$MGR" -H 'X-Requested-With: cloudpanel' -F "file=@$f" "$@" "$API$p"
}
j() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }
as() { # user cmd...
  local u=$1
  shift
  runuser -u "$u" -- "$@"
}
host_get() { curl -s -m 5 -H "Host: $1" "http://127.0.0.1$2"; }
host_code() { curl -s -m 5 -o /dev/null -w '%{http_code}' -H "Host: $1" "http://127.0.0.1$2"; }
mysql_q() { mariadb --batch --skip-column-names -e "$1"; }

secret_modes() {
  echo "== Secret files aren't readable by anyone else"
  for f in /var/lib/cloudpanel/cloudpanel.db /var/lib/cloudpanel/jwt.secret /var/lib/cloudpanel/proxy.secret \
    /etc/cloudpanel/cloudpanel.env /etc/cloudpanel/secret.key /etc/cloudpanel/mysql-admin.cnf /etc/cloudpanel/mongodb.env; do
    [ -e "$f" ] || continue
    check "$f is private" "[ \"\$(( 0\$(stat -c %a '$f') & 077 ))\" = 0 ]"
    check "$f belongs to root" "[ \"\$(stat -c %U '$f')\" = root ]"
  done
  check "the data directory is closed to others" '[ "$(( 0$(stat -c %a /var/lib/cloudpanel) & 007 ))" = 0 ]'
  check "the panel's own nginx site is private, as it holds the proxy secret" \
    '[ ! -e /etc/nginx/sites-available/cloudpanel-panel ] || [ "$(( 0$(stat -c %a /etc/nginx/sites-available/cloudpanel-panel) & 077 ))" = 0 ]'
}

service_hardening() {
  echo "== The service keeps its sandbox"
  for prop in NoNewPrivileges=yes PrivateTmp=yes ProtectControlGroups=yes RestrictSUIDSGID=yes LockPersonality=yes; do
    check "$prop" "systemctl show cloudpanel -p ${prop%=*} | grep -qx '$prop'"
  done
}

web_protections() {
  echo "== What the panel sends and accepts over TLS"
  local h
  h=$(curl -skI "https://127.0.0.1:8443/")
  for want in 'content-security-policy:' 'strict-transport-security:' 'x-frame-options: DENY' 'x-content-type-options: nosniff' 'referrer-policy: no-referrer'; do
    check "header $want" "echo \"\$h\" | grep -qi '^$want'"
  done
  check "TLS below 1.2 is refused" '! curl -sk -o /dev/null --tlsv1.0 --tls-max 1.1 https://127.0.0.1:8443/'
  check "the API refuses a request without the CSRF header" \
    '[ "$(curl -sk -o /dev/null -w "%{http_code}" -X POST -H "Content-Type: application/json" -d "{}" $API/auth/login)" = 400 ]'
}

attack() {
  echo "== Setting up: two sites, and a manager of only the first"
  check "no default password" \
    '[ "$(curl -sk -o /dev/null -w "%{http_code}" -X POST -H "X-Requested-With: cloudpanel" -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"admin\"}" $API/auth/login)" = 401 ]'
  rm -f "$ADMIN" "$MGR"
  local pw
  pw=$(cat /var/lib/cloudpanel/initial_admin_password)
  admin POST /auth/login "{\"username\":\"admin\",\"password\":\"$pw\"}" >/dev/null
  retry '[ "$(admin GET /auth/me | j "d[\"username\"]")" = admin ]' || bad "admin login"
  code "$ADMIN" PUT /fail2ban '{"sshd":true,"panel":false,"maxretry":5,"findtime_minutes":10,"bantime_minutes":60,"ignoreip":[]}' >/dev/null

  R=$(admin POST /sites '{"domain":"a.sec.local","site_type":"static"}')
  SA=$(echo "$R" | j 'd["id"]') UA=$(echo "$R" | j 'd["system_user"]') HA=$(echo "$R" | j 'd["home_dir"]')
  R=$(admin POST /sites '{"domain":"b.sec.local","site_type":"static"}')
  SB=$(echo "$R" | j 'd["id"]') UB=$(echo "$R" | j 'd["system_user"]') HB=$(echo "$R" | j 'd["home_dir"]')
  check "both sites exist ($UA, $UB)" '[ -n "$SA" ] && [ -n "$SB" ] && [ "$UA" != "$UB" ]'
  WA=$HA/htdocs/a.sec.local
  WB=$HB/htdocs/b.sec.local
  as "$UA" sh -c "echo a-home-page > $WA/index.html"
  as "$UB" sh -c "echo b-home-page > $WB/index.html; echo b-secret-value > $WB/secret.txt; echo B_SECRET=b-env-value > $WB/.env; chmod 640 $WB/.env"
  R=$(admin POST /users "{\"username\":\"attacker\",\"password\":\"Attacker-Pass-123\",\"email\":\"a@example.com\",\"role\":\"site_manager\",\"site_ids\":[$SA]}")
  mgr POST /auth/login '{"username":"attacker","password":"Attacker-Pass-123"}' >/dev/null
  check "the manager is signed in, with only their site" '[ "$(mgr GET /sites | j "[s[\"id\"] for s in d]")" = "[$SA]" ]'
  check "the manager can't see the other site" '[ "$(code "$MGR" GET /sites/$SB)" = 404 ]'

  echo "== Isolation between sites at the OS level"
  check "homes are closed to others" '[ "$(stat -c %a "$HA")" = 750 ] && [ "$(stat -c %a "$HB")" = 750 ]'
  check "a site's user can't read another site's files" '! as "$UA" cat "$WB/secret.txt" 2>/dev/null'
  check "or its .env" '! as "$UA" cat "$WB/.env" 2>/dev/null'
  check "or write there" '! as "$UA" touch "$WB/pwned" 2>/dev/null'
  check "a site's user can't read the panel's database" '! as "$UA" cat /var/lib/cloudpanel/cloudpanel.db >/dev/null 2>&1'
  check "or its secrets" '! as "$UA" cat /etc/cloudpanel/cloudpanel.env >/dev/null 2>&1'
  check "or the SSH keys of others" '! as "$UA" touch /etc/ssh/cloudpanel_keys/pwned 2>/dev/null'

  echo "== SEC-01: exporting the panel's own database through a planted link"
  R=$(mgr POST /sites/$SA/databases '{"engine":"sqlite","name":"linked"}')
  D1=$(echo "$R" | j 'd["database"]["id"]')
  check "a SQLite database was made ($(echo "$R" | cut -c1-80))" '[ -n "$D1" ]'
  as "$UA" sh -c "rm -f $HA/databases/linked.sqlite; ln -s /var/lib/cloudpanel/cloudpanel.db $HA/databases/linked.sqlite"
  curl -sk -b "$MGR" -o /var/tmp/sec01.out "$API/databases/$D1/export"
  check "the export holds no password hashes" '! grep -aq "argon2\|password_hash" /var/tmp/sec01.out'
  as "$UA" sh -c "rm -f $HA/databases/linked.sqlite"

  echo "== SEC-04: writing through planted SQLite paths"
  R=$(mgr POST /sites/$SA/databases '{"engine":"sqlite","name":"planted"}')
  D2=$(echo "$R" | j 'd["database"]["id"]')
  python3 -c "import sqlite3;c=sqlite3.connect('/var/tmp/good.sqlite');c.execute('create table t(x)');c.commit()"
  as "$UA" ln -sf /etc/cron.d/pwned-sec04 "$HA/databases/planted.sqlite.importing"
  mgr_upload /databases/$D2/import /var/tmp/good.sqlite >/dev/null
  check "an import doesn't write through its temp file" '[ ! -e /etc/cron.d/pwned-sec04 ]'
  as "$UA" rm -f "$HA/databases/planted.sqlite.importing"
  as "$UA" ln -s /etc/cron.d/pwned-sec04b "$HA/databases/dangling.sqlite"
  mgr POST /sites/$SA/databases '{"engine":"sqlite","name":"dangling"}' >/dev/null
  check "creating a database doesn't follow a dangling link" '[ ! -e /etc/cron.d/pwned-sec04b ]'
  as "$UA" rm -f "$HA/databases/dangling.sqlite"

  echo "== SEC-05: a temp file swapped for a link during a slow upload"
  head -c 3000000 /dev/zero >/var/tmp/big.bin
  local target=/etc/cloudpanel/cloudpanel.env before
  before=$(stat -c %a "$target")
  mgr_upload /sites/$SA/files/upload /var/tmp/big.bin --limit-rate 400k >/var/tmp/sec05.out &
  local up=$!
  for _ in $(seq 1 120); do
    f=$(find "$HA" -maxdepth 1 -name '.upload-*' | head -n1)
    if [ -n "$f" ]; then
      as "$UA" sh -c "rm -f '$f'; ln -s '$target' '$f'" 2>/dev/null
      break
    fi
    sleep 0.05
  done
  wait $up
  check "the file behind the link keeps its mode ($before)" '[ "$(stat -c %a "$target")" = "$before" ]'
  check "and its owner" '[ "$(stat -c %U "$target")" = root ]'
  as "$UA" rm -f "$HA/big.bin"

  echo "== SEC-06: a folder swapped for a link while the file manager uses it"
  as "$UA" mkdir -p "$HA/flip"
  as "$UA" sh -c "echo public > $HA/flip/shadow"
  as "$UA" sh -c "while :; do mv $HA/flip $HA/parked 2>/dev/null && ln -s /etc $HA/flip && rm -f $HA/flip && mv $HA/parked $HA/flip; done" &
  local flip=$! leaked=0
  sleep 0.2
  for _ in $(seq 1 400); do
    mgr GET "/sites/$SA/files/content?path=flip/shadow" | grep -q 'root:' && leaked=1
    code "$MGR" PUT /sites/$SA/files/content '{"path":"flip/cron.d/pwned-race","content":"* * * * * root touch /tmp/pwned\n"}' >/dev/null
    code "$MGR" POST /sites/$SA/files/op '{"op":"chmod","path":"flip/shadow","mode":"0666"}' >/dev/null
    code "$MGR" POST /sites/$SA/files/op '{"op":"touch","path":"flip/pwned-touch"}' >/dev/null
  done
  pkill -P "$flip" 2>/dev/null
  kill "$flip" 2>/dev/null
  wait "$flip" 2>/dev/null
  check "no read of /etc/shadow got through" '[ "$leaked" = 0 ]'
  check "no write into /etc/cron.d got through" '[ ! -e /etc/cron.d/pwned-race ]'
  check "no file was made in /etc" '[ ! -e /etc/pwned-touch ]'
  check "/etc/shadow keeps its mode" '[ "$(( 0$(stat -c %a /etc/shadow) & 007 ))" = 0 ]'
  check "/etc/shadow keeps its owner" '[ "$(stat -c %U /etc/shadow)" = root ]'
  as "$UA" sh -c "rm -rf $HA/flip $HA/parked"

  echo "== SEC-07: another site's .env through a linked folder"
  as "$UA" sh -c "mv $WA $WA.bak && ln -s $WB $WA"
  check "the panel doesn't read it" '! mgr GET /sites/$SA/app/env | grep -q b-env-value'
  mgr PUT /sites/$SA/app '{"env_text":"B_SECRET=overwritten\n"}' >/dev/null
  check "or write it" 'grep -q b-env-value "$WB/.env"'
  as "$UA" sh -c "rm -f $WA && mv $WA.bak $WA"

  echo "== SEC-08: another site's files through nginx"
  as "$UA" ln -s "$WB/secret.txt" "$WA/leak.txt"
  as "$UA" ln -s "$WB" "$WA/leakdir"
  check "a site is served" '[ "$(host_get a.sec.local /)" = a-home-page ]'
  check "a link to another site's file isn't" '! host_get a.sec.local /leak.txt | grep -q b-secret-value'
  check "nor through a linked folder" '! host_get a.sec.local /leakdir/secret.txt | grep -q b-secret-value'
  as "$UA" ln -s index.html "$WA/alias.html"
  check "a link inside the site still works" '[ "$(host_get a.sec.local /alias.html)" = a-home-page ]'
  check "a document root can't be a link out" "[ \"\$(code \"\$MGR\" PATCH /sites/$SA '{\"document_root\":\"$WA/leakdir\"}')\" = 400 ]"
  check "dotfiles aren't served" '[ "$(host_code b.sec.local /.env)" = 403 ]'

  echo "== SEC-11: a root job linked to the manager's site"
  R=$(admin POST /cron/jobs "{\"site_id\":$SA,\"schedule\":\"0 0 1 1 *\",\"command\":\"touch /var/tmp/pwned-cron\",\"user\":\"root\",\"is_active\":false}")
  C1=$(echo "$R" | j 'd["id"]')
  check "the manager can't run it" '[ "$(code "$MGR" POST /cron/jobs/$C1/run)" = 404 ]'
  check "and it didn't run" '[ ! -e /var/tmp/pwned-cron ]'
  check "the manager can't change it" "[ \"\$(code \"\$MGR\" PUT /cron/jobs/$C1 '{\"site_id\":$SA,\"schedule\":\"* * * * *\",\"command\":\"id\"}')\" = 404 ]"
  R=$(mgr POST /cron/jobs "{\"site_id\":$SA,\"schedule\":\"0 0 1 1 *\",\"command\":\"id -un\",\"user\":\"root\",\"is_active\":false}")
  C2=$(echo "$R" | j 'd["id"]')
  check "a manager's own job runs as the site's user" '[ "$(mgr POST /cron/jobs/$C2/run | j "d[\"output\"].strip()")" = "$UA" ]'

  echo "== Archives"
  python3 - <<'EOF'
import io, tarfile
with tarfile.open("/var/tmp/evil.tar", "w") as t:
    for name, mode in [("../../../../etc/cron.d/pwned-tar", 0o644), ("/etc/cron.d/pwned-abs", 0o644), ("suid", 0o4755)]:
        data = b"* * * * * root touch /tmp/pwned\n"
        i = tarfile.TarInfo(name); i.size = len(data); i.mode = mode; i.uid = 0; i.gid = 0
        t.addfile(i, io.BytesIO(data))
    link = tarfile.TarInfo("link"); link.type = tarfile.SYMTYPE; link.linkname = "/etc/cron.d"
    t.addfile(link)
    data = b"x\n"
    i = tarfile.TarInfo("link/pwned-through-link"); i.size = len(data)
    t.addfile(i, io.BytesIO(data))
EOF
  mgr_upload /sites/$SA/files/upload /var/tmp/evil.tar >/dev/null
  mgr POST /sites/$SA/files/op '{"op":"extract","path":"evil.tar"}' >/dev/null
  check "a tar can't write above the site" '[ ! -e /etc/cron.d/pwned-tar ]'
  check "or to an absolute path" '[ ! -e /etc/cron.d/pwned-abs ]'
  check "or through a link it brings" '[ ! -e /etc/cron.d/pwned-through-link ]'
  check "nothing extracted is setuid root" '[ -z "$(find "$HA" -type f -user root -perm /6000 2>/dev/null)" ]'
  check "the setuid bit doesn't survive extracting" '[ ! -e "$HA/suid" ] || [ "$(( 0$(stat -c %a "$HA/suid") & 06000 ))" = 0 ]'
  check "the file manager won't set it" "[ \"\$(code \"\$MGR\" POST /sites/$SA/files/op '{\"op\":\"chmod\",\"path\":\"evil.tar\",\"mode\":\"4755\"}')\" = 400 ]"
  # A name that tar would take for an option.
  as "$UA" sh -c "cd $HA && echo x > ./--checkpoint=1 && echo x > './--checkpoint-action=exec=touch pwned-opt'"
  mgr POST /sites/$SA/files/op '{"op":"compress","path":"","names":["--checkpoint=1","--checkpoint-action=exec=touch pwned-opt"],"name":"opts"}' >/dev/null
  check "a file name isn't taken for a tar option" '[ ! -e "$HA/pwned-opt" ]'

  echo "== Uploads and site settings"
  echo pwned >/var/tmp/up.txt
  curl -sk -b "$MGR" -H 'X-Requested-With: cloudpanel' -F 'file=@/var/tmp/up.txt;filename=../../etc/pwned-name' "$API/sites/$SA/files/upload" >/dev/null
  check "an upload's name can't lead out" '[ ! -e /etc/pwned-name ] && [ ! -e /home/etc/pwned-name ]'
  check "a manager can't set nginx directives" "[ \"\$(code \"\$MGR\" PUT /sites/$SA/directives '{\"custom_directives\":\"gzip on;\"}')\" = 403 ]"

  mariadb_attacks
  panel_upstream
  guessing_limits
}

mariadb_attacks() {
  command -v mariadb >/dev/null || {
    echo "== SEC-02: skipped, no MariaDB"
    return
  }
  echo "== SEC-02: a dump is only allowed to touch its own database"
  R=$(mgr POST /sites/$SA/databases '{"engine":"mariadb","name":"adb"}')
  D3=$(echo "$R" | j 'd["database"]["id"]')
  check "a MariaDB database was made ($(echo "$R" | cut -c1-80))" '[ -n "$D3" ]'
  mysql_q "CREATE DATABASE bdb; CREATE TABLE bdb.secret (x INT); INSERT INTO bdb.secret VALUES (42);"
  dump() { printf '%b' "$1" >/var/tmp/d.sql; mgr_upload "/databases/$D3/import" /var/tmp/d.sql >/var/tmp/d.out; }
  dump "CREATE USER 'evil'@'%' IDENTIFIED BY 'evilpassword1';\nGRANT ALL ON *.* TO 'evil'@'%';\n"
  check "it can't create a server account" '[ "$(mysql_q "SELECT COUNT(*) FROM mysql.user WHERE User=\"evil\"")" = 0 ]'
  dump "USE bdb;\nDROP TABLE secret;\n"
  check "it can't reach another database" '[ "$(mysql_q "SELECT x FROM bdb.secret")" = 42 ]'
  dump "UPDATE mysql.global_priv SET Priv='{}' WHERE User='root';\n"
  check "it can't change the system tables" 'mysql_q "SELECT 1" >/dev/null'
  dump "CREATE TABLE f (x TEXT);\nLOAD DATA INFILE '/etc/shadow' INTO TABLE f;\n"
  check "it can't read server files" '! mysql_q "SELECT x FROM adb.f" 2>/dev/null | grep -q root:'
  dump "SELECT 'x' INTO OUTFILE '/var/tmp/pwned-outfile';\n"
  check "it can't write server files" '[ ! -e /var/tmp/pwned-outfile ] && ! find /var/lib/mysql -name "pwned*" | grep -q .'
  dump '\\! touch /var/tmp/pwned-shell\nSELECT 1;\n'
  check "a client shell escape doesn't run as root" '[ ! -e /var/tmp/pwned-shell ] || [ "$(stat -c %U /var/tmp/pwned-shell)" != root ]'
  # Imports run as one account per database, which is locked again afterwards.
  open_accounts() {
    mysql_q "SELECT COUNT(*) FROM mysql.global_priv WHERE User LIKE 'cp\\_owner\\_%'
      AND COALESCE(JSON_VALUE(Priv, '\$.account_locked'), 'false') <> 'true'"
  }
  check "the import account can't be logged in to afterwards" '[ "$(open_accounts)" = 0 ]'

  echo "== An ordinary dump, with the panel's own export of it, still round-trips"
  mysql_q "USE adb; DROP TABLE IF EXISTS f; CREATE TABLE t (x INT); INSERT INTO t VALUES (7);
    CREATE TRIGGER tr BEFORE INSERT ON t FOR EACH ROW SET NEW.x = NEW.x;
    CREATE VIEW v AS SELECT x FROM t;
    CREATE PROCEDURE p() SELECT 1;"
  curl -sk -b "$MGR" -o /var/tmp/adb.sql.gz "$API/databases/$D3/export"
  check "the export has its definers" 'zcat /var/tmp/adb.sql.gz | grep -q DEFINER'
  mysql_q "USE adb; DROP VIEW v; DROP TABLE t; DROP PROCEDURE p;"
  R=$(mgr_upload "/databases/$D3/import" /var/tmp/adb.sql.gz)
  check "it imports ($(echo "$R" | cut -c1-200))" '[ "$(mysql_q "SELECT x FROM adb.t")" = 7 ]'
  check "with its view" '[ "$(mysql_q "SELECT COUNT(*) FROM adb.v")" = 1 ]'
  check "and trigger" '[ "$(mysql_q "SELECT COUNT(*) FROM information_schema.triggers WHERE trigger_schema=\"adb\"")" = 1 ]'
  check "and procedure" '[ "$(mysql_q "SELECT COUNT(*) FROM information_schema.routines WHERE routine_schema=\"adb\"")" = 1 ]'
  check "which can still be called" '[ "$(mysql_q "CALL adb.p()")" = 1 ]'
  check "and the trigger still fires" 'mysql_q "INSERT INTO adb.t VALUES (8)" && [ "$(mysql_q "SELECT COUNT(*) FROM adb.t")" = 2 ]'
  check "and its account is locked again" '[ "$(open_accounts)" = 0 ]'
  check "and only reaches its own database" \
    '[ "$(mysql_q "SELECT COUNT(DISTINCT Db) FROM mysql.db WHERE User LIKE \"cp\\_owner\\_%\"")" = 1 ]'

  echo "== SEC-03: taking over the server's own names"
  for name in mysql information_schema performance_schema sys; do
    check "a database can't be called $name" "[ \"\$(code \"\$MGR\" POST /sites/$SA/databases '{\"engine\":\"mariadb\",\"name\":\"$name\"}')\" = 400 ]"
  done
  check "a user can't be called root" "[ \"\$(code \"\$MGR\" POST /databases/$D3/users '{\"username\":\"root\"}')\" = 400 ]"
  check "and root keeps working" 'mysql_q "SELECT 1" >/dev/null'
}

panel_upstream() {
  echo "== SEC-09: whoever holds the panel's port while it's down"
  local ph=panel.sec.local
  mkdir -p /etc/cloudpanel/tls
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout /etc/cloudpanel/tls/sec.key -out /etc/cloudpanel/tls/sec.crt \
    -subj "/CN=$ph" -addext "subjectAltName=DNS:$ph" 2>/dev/null
  python3 - <<'EOF'
import json, sqlite3
c = sqlite3.connect("/var/lib/cloudpanel/cloudpanel.db")
c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_tls', ?)", (json.dumps(
    {"hostname": "panel.sec.local", "cert": "/etc/cloudpanel/tls/sec.crt", "key": "/etc/cloudpanel/tls/sec.key"}),))
c.commit()
EOF
  systemctl restart cloudpanel
  retry '[ "$(curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1:8443/)" = 200 ]' || bad "the panel came back"
  thru() { curl -sk -m 10 --resolve "$ph:443:127.0.0.1" "$@"; }
  retry '[ "$(thru -o /dev/null -w "%{http_code}" "https://$ph/api/auth/me")" = 401 ]'
  check "nginx trusts the panel's real certificate" '[ "$(thru -o /dev/null -w "%{http_code}" "https://$ph/api/auth/me")" = 401 ]'

  systemctl stop cloudpanel
  # The attacker's own certificate, for the right name, and a listener as a site's user.
  mkdir -p /var/tmp/fake
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout /var/tmp/fake/k.pem -out /var/tmp/fake/c.pem \
    -subj "/CN=$ph" -addext "subjectAltName=DNS:$ph" 2>/dev/null
  cat >/var/tmp/fake/listen.py <<'EOF'
import http.server, ssl
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        open("/var/tmp/fake/got.txt", "a").write(str(self.headers))
        self.send_response(200); self.end_headers(); self.wfile.write(b"from the attacker")
    def log_message(self, *a): pass
s = http.server.HTTPServer(("127.0.0.1", 8443), H)
c = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); c.load_cert_chain("/var/tmp/fake/c.pem", "/var/tmp/fake/k.pem")
s.socket = c.wrap_socket(s.socket, server_side=True)
s.serve_forever()
EOF
  chown -R "$UA" /var/tmp/fake
  runuser -u "$UA" -- python3 /var/tmp/fake/listen.py &
  local listener=$!
  sleep 1
  check "the site's user got the port" 'curl -sk https://127.0.0.1:8443/ | grep -q "from the attacker"'
  rm -f /var/tmp/fake/got.txt
  thru -H 'Cookie: cp_session=an-admins-session' "https://$ph/api/auth/me" >/var/tmp/sec09.out
  check "nginx doesn't answer with the attacker's page" '! grep -q "from the attacker" /var/tmp/sec09.out'
  check "nor send it the admin's cookie" '! grep -qi "an-admins-session" /var/tmp/fake/got.txt 2>/dev/null'
  check "nor the proxy secret" '! grep -qi "x-cloudpanel-proxy" /var/tmp/fake/got.txt 2>/dev/null'
  pkill -f /var/tmp/fake/listen.py
  wait "$listener" 2>/dev/null
  systemctl start cloudpanel
  retry '[ "$(curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1:8443/)" = 200 ]' || bad "the panel came back"
}

# Last, as it leaves this machine's address locked out of signing in for a while.
guessing_limits() {
  echo "== SEC-10: guessing passwords"
  local got=""
  for i in 1 2 3 4 5 6 7 8; do
    got=$(curl -sk -o /dev/null -w '%{http_code}' -X POST -H 'X-Requested-With: cloudpanel' -H 'Content-Type: application/json' \
      -H "X-Forwarded-For: 10.0.0.$i" -H "X-Real-IP: 10.0.0.$i" -H "CF-Connecting-IP: 10.0.0.$i" \
      -d '{"username":"admin","password":"guess"}' "$API/auth/login")
  done
  check "forwarding headers don't buy more guesses (last answer $got)" '[ "$got" = 429 ]'
  check "failures reach fail2ban's log" 'grep -q "auth failure from 127.0.0.1" /var/log/cloudpanel/auth.log'
}

case "${1:-}" in
  attack)
    attack
    secret_modes
    service_hardening
    web_protections
    ;;
  after-reboot)
    secret_modes
    service_hardening
    check "the planted cron files are still not there" '[ -z "$(find /etc/cron.d -name "pwned*")" ]'
    ;;
  *)
    echo "Usage: $0 attack|after-reboot"
    exit 2
    ;;
esac

echo
echo "security: $PASS passed, $FAIL failed"
[ "$FAIL" = 0 ]
