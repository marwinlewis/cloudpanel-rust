#!/usr/bin/env bash
# End-to-end smoke test against a real install. Run as root on a disposable Debian/Ubuntu
# server or container after install.sh (it creates and deletes *.test.local sites,
# databases, users and firewall rules):  sudo bash scripts/smoke-test.sh
set -u
API=https://127.0.0.1:8443/api
JAR=/tmp/cp.jar
PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  ok   $*"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL $*"; }
check(){ if eval "$2"; then ok "$1"; else bad "$1"; fi; }
# HTTP checks right after an nginx reload can hit an old worker; retry briefly.
retry(){ for _ in 1 2 3 4 5 6 7 8 9 10; do eval "$1" && return 0; sleep 0.5; done; return 1; }
checkr(){ if retry "$2"; then ok "$1"; else bad "$1"; fi; }
call() { # method path [json]
  local m=$1 p=$2 d=${3:-}
  if [ -n "$d" ]; then
    curl -sk -b $JAR -c $JAR -X "$m" -H 'X-Requested-With: cloudpanel' -H 'Content-Type: application/json' -d "$d" "$API$p"
  else
    curl -sk -b $JAR -c $JAR -X "$m" -H 'X-Requested-With: cloudpanel' "$API$p"
  fi
}
job() { # wait for job id, print status
  local id=$1 s
  for _ in $(seq 1 180); do
    s=$(call GET /jobs/$id | python3 -c 'import sys,json;print(json.load(sys.stdin)["status"])')
    [ "$s" != running ] && break
    sleep 1
  done
  echo "$s"
}
j() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }

PW=$(cat /var/lib/cloudpanel/initial_admin_password)
echo "== auth"
call POST /auth/login "{\"username\":\"admin\",\"password\":\"$PW\"}" >/dev/null
check "login" '[ "$(call GET /auth/me | j "d[\"username\"]")" = admin ]'

# Remove leftovers from a previous run.
for id in $(call GET /sites | j '" ".join(str(x["id"]) for x in d if x["domain"].endswith(".test.local"))'); do
  call DELETE "/sites/$id?delete_files=true" >/dev/null
done

echo "== python app site"
R=$(call POST /sites '{"domain":"app.test.local","site_type":"python","target_port":3005,"app_command":"python3 -m http.server $PORT --bind 127.0.0.1"}')
APP=$(echo "$R" | j 'd.get("id","")')
check "create python site ($R)" '[ -n "$APP" ]'
check "site user exists" 'id app-test >/dev/null 2>&1'
check "home layout" '[ -d /home/app-test/htdocs/app.test.local ] && [ "$(stat -c %U /home/app-test/htdocs)" = app-test ]'
sleep 3
check "app unit active" '[ "$(systemctl is-active cloudpanel-app-app-test-local)" = active ]'
check "app runs as site user" '[ "$(ps -o user= -p $(systemctl show -p MainPID --value cloudpanel-app-app-test-local))" = app-test ]'
checkr "nginx proxies to app" '[ "$(curl -s -o /dev/null -w %{http_code} -H "Host: app.test.local" http://127.0.0.1/)" = 200 ]'
check "app status via API" '[ "$(call GET /sites/$APP | j "d[\"app\"][\"active_state\"]")" = active ]'
check "app logs" 'call GET "/sites/$APP/app/logs?lines=20" | grep -q logs'
check "restart app" 'call POST /sites/$APP/app/restart | grep -q active_state'

echo "== static site + basic auth + disable"
S=$(call POST /sites '{"domain":"static.test.local","site_type":"static"}' | j 'd["id"]')
checkr "static site served" 'curl -s -H "Host: static.test.local" http://127.0.0.1/ | grep -q "is ready"'
call POST /sites/$S/basic-auth/users '{"username":"guest","password":"guest-pass-1"}' >/dev/null
call PUT /sites/$S/basic-auth '{"enabled":true,"allow":[]}' >/dev/null
checkr "basic auth 401" '[ "$(curl -s -o /dev/null -w %{http_code} -H "Host: static.test.local" http://127.0.0.1/)" = 401 ]'
checkr "basic auth ok with creds" '[ "$(curl -s -o /dev/null -w %{http_code} -u guest:guest-pass-1 -H "Host: static.test.local" http://127.0.0.1/)" = 200 ]'
call PUT /sites/$S/basic-auth '{"enabled":false,"allow":[]}' >/dev/null
call POST /sites/$S/state '{"active":false}' >/dev/null
checkr "disabled site 503" '[ "$(curl -s -o /dev/null -w %{http_code} -H "Host: static.test.local" http://127.0.0.1/)" = 503 ]'
call POST /sites/$S/state '{"active":true}' >/dev/null
checkr "re-enabled 200" '[ "$(curl -s -o /dev/null -w %{http_code} -H "Host: static.test.local" http://127.0.0.1/)" = 200 ]'
check "bad directives rejected by nginx -t" 'call PUT /sites/$S/directives "{\"custom_directives\":\"not_a_directive on;\"}" | grep -q "nginx configuration test failed"'
checkr "site still serving after rejected change" '[ "$(curl -s -o /dev/null -w %{http_code} -H "Host: static.test.local" http://127.0.0.1/)" = 200 ]'

echo "== SSH / SFTP users"
U=$(call POST /sites/$APP/ssh-users '{"username":"app-deploy","password":"Deploy-pass-123","sftp_only":true}' | j 'd["id"]')
check "sftp user created" 'id app-deploy | grep -q cloudpanel-sftp'
check "sftp user shell nologin" '[ "$(getent passwd app-deploy | cut -d: -f7)" = /usr/sbin/nologin ]'
check "sshd drop-in valid" '[ -f /etc/ssh/sshd_config.d/cloudpanel.conf ] && sshd -t'
KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl test@box"
call POST /sites/$APP/ssh-users/$U/keys "{\"public_key\":\"$KEY\"}" >/dev/null
check "authorized key written" 'grep -q "test@box" /etc/ssh/cloudpanel_keys/app-deploy'
check "sshd resolves keys file" 'sshd -T -C user=app-deploy,host=x,addr=1.2.3.4 | grep -qi "authorizedkeysfile .ssh/authorized_keys /etc/ssh/cloudpanel_keys/%u"'
check "sshd forces sftp" 'sshd -T -C user=app-deploy,host=x,addr=1.2.3.4 | grep -qi "forcecommand internal-sftp"'

echo "== databases"
R=$(call POST /sites/$APP/databases '{"engine":"mariadb","name":"shop","username":"shop"}')
MPW=$(echo "$R" | j 'd.get("password","")')
check "mariadb db+user ($R)" '[ -n "$MPW" ]'
check "mariadb login with new user" 'mysql -ushop -p"$MPW" shop -e "CREATE TABLE t(x INT); INSERT INTO t VALUES (7);"'
MID=$(echo "$R" | j 'd["database"]["id"]')
R=$(call POST /sites/$APP/databases '{"engine":"mongodb","name":"shopmongo","username":"shopm"}')
GPW=$(echo "$R" | j 'd.get("password","")')
check "mongodb db+user ($R)" '[ -n "$GPW" ]'
check "mongodb login with new user" 'mongosh --quiet "mongodb://shopm:$GPW@127.0.0.1:27017/shopmongo?authSource=shopmongo" --eval "db.t.insertOne({x:1}).acknowledged" | grep -q true'
R=$(call POST /sites/$APP/databases '{"engine":"sqlite","name":"local"}')
check "sqlite db ($R)" '[ -f /home/app-test/databases/local.sqlite ]'
check "mariadb export" '[ "$(curl -sk -b $JAR -o /tmp/dump.sql.gz -w %{http_code} $API/databases/$MID/export)" = 200 ] && zcat /tmp/dump.sql.gz | grep -q "CREATE TABLE"'
check "mariadb password reset" 'call POST /databases/$MID/users/shop/password "{}" | grep -q password'

echo "== files"
call PUT /sites/$APP/files/content '{"path":"htdocs/app.test.local/hello.txt","content":"hi"}' >/dev/null
check "file written as site user" '[ "$(stat -c %U /home/app-test/htdocs/app.test.local/hello.txt)" = app-test ]'
check "path escape refused" 'call GET "/sites/$APP/files?path=../../etc" | grep -q "inside the site"'
ln -sf /etc /home/app-test/htdocs/evil
check "symlink escape refused" 'call GET "/sites/$APP/files/content?path=htdocs/evil/shadow" | grep -q "inside the site"'
rm -f /home/app-test/htdocs/evil
check "compress" 'call POST /sites/$APP/files/op "{\"op\":\"compress\",\"path\":\"htdocs/app.test.local\",\"names\":[\"hello.txt\"],\"name\":\"h\"}" | grep -q h.tar.gz'

echo "== backups"
JID=$(call POST /sites/$APP/backups | j 'd["job_id"]')
check "backup job" '[ "$(job $JID)" = succeeded ]'
BID=$(call GET /sites/$APP/backups | j 'd["backups"][0]["id"]')
echo changed > /home/app-test/htdocs/app.test.local/hello.txt
mysql shop -e "DELETE FROM t;"
JID=$(call POST /backups/$BID/restore | j 'd["job_id"]')
check "restore job" '[ "$(job $JID)" = succeeded ]'
check "files restored" '[ "$(cat /home/app-test/htdocs/app.test.local/hello.txt)" = hi ]'
check "mariadb restored" '[ "$(mysql -N shop -e "SELECT x FROM t")" = 7 ]'
check "app running after restore" '[ "$(systemctl is-active cloudpanel-app-app-test-local)" = active ]'

echo "== cron"
C=$(call POST /cron/jobs "{\"site_id\":$APP,\"name\":\"whoami\",\"schedule\":\"*/5 * * * *\",\"command\":\"whoami\"}" | j 'd["id"]')
check "cron file uses cron-run" 'grep -q "cron-run $C" /etc/cron.d/cloudpanel'
check "run now as site user" 'call POST /cron/jobs/$C/run | grep -q "app-test"'
check "cron-run CLI records run" 'bash -c "$(grep CLOUDPANEL_DB_PATH /etc/cron.d/cloudpanel) /usr/local/bin/cloudpanel cron-run $C" && [ "$(call GET /cron/jobs/$C/runs | j "len(d)")" -ge 2 ]'

echo "== firewall / fail2ban / services"
for id in $(call GET /firewall/rules | j '" ".join(str(r["id"]) for r in d)'); do call DELETE /firewall/rules/$id >/dev/null; done
check "rules removed from ufw" '! ufw status | grep -qE "6000:6010|203.0.113.9"'
check "port range rule" 'call POST /firewall/rules "{\"kind\":\"port\",\"port\":\"6000:6010\",\"protocol\":\"udp\"}" | grep -q 6010 && ufw status | grep -q "6000:6010/udp"'
check "source rule" 'call POST /firewall/rules "{\"kind\":\"port\",\"port\":3306,\"source\":\"10.0.0.0/8\"}" | grep -q 3306 && ufw status | grep -q "10.0.0.0/8"'
check "block ip" 'call POST /firewall/rules "{\"kind\":\"block\",\"source\":\"203.0.113.9\"}" | grep -q 203 && ufw status numbered | grep -q "203.0.113.9"'
check "lockout refused" 'call POST /firewall/rules "{\"kind\":\"port\",\"port\":22,\"action\":\"deny\"}" | grep -q Refusing'
curl -sk -X POST -H 'X-Requested-With: cloudpanel' -H 'Content-Type: application/json' -d '{"username":"admin","password":"wrong"}' $API/auth/login >/dev/null
check "auth failure logged for fail2ban" 'fail2ban-regex /var/log/cloudpanel/auth.log /etc/fail2ban/filter.d/cloudpanel.conf | grep -qE "Failregex: [1-9][0-9]* total"'
check "fail2ban status via API" 'call GET /fail2ban | grep -q "\"jail\":\"cloudpanel\""'
check "manual ban/unban" 'call POST /fail2ban/ban "{\"jail\":\"sshd\",\"ip\":\"198.51.100.7\"}" | grep -q ok && fail2ban-client status sshd | grep -q 198.51.100.7 && call POST /fail2ban/unban "{\"jail\":\"sshd\",\"ip\":\"198.51.100.7\"}" | grep -q ok'
check "services list" 'call GET /services | grep -q "\"name\":\"mongod\""'
check "service restart" 'call POST /services/cron/restart | grep -q active'
check "ssh stop refused" 'call POST /services/ssh/stop | grep -q refused'
JID=$(call POST /system/updates/refresh | j 'd["job_id"]')
check "apt update job" '[ "$(job $JID)" = succeeded ]'
check "system info" 'call GET /system/info | grep -q panel_version'
check "panel update status" 'call GET /system/panel-update | grep -q update_available'

echo "== cleanup"
call DELETE "/sites/$S?delete_files=true" >/dev/null
check "delete site with files" 'call DELETE "/sites/$APP?delete_files=true" | grep -q deleted && ! id app-test 2>/dev/null && ! id app-deploy 2>/dev/null && [ ! -d /home/app-test ] && [ ! -f /etc/systemd/system/cloudpanel-app-app-test-local.service ] && ! mysql -e "USE shop" 2>/dev/null'
check "events recorded" '[ "$(call GET "/events?limit=500" | j "len(d)")" -gt 20 ]'
echo
echo "passed=$PASS failed=$FAIL"
