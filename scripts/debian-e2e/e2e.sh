#!/usr/bin/env bash
# The checks behind run.sh. Runs as root inside the container, after install.sh.
#   e2e.sh before-reboot   Everything up to the reboot
#   e2e.sh after-reboot    What must still be true afterwards, then cleanup checks
set -u
API=https://127.0.0.1:8443/api
JAR=/var/tmp/cp.jar
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ok   $*"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL $*"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
retry() { for _ in $(seq 1 40); do eval "$1" && return 0; sleep 0.5; done; return 1; }
checkr() { if retry "$2"; then ok "$1"; else bad "$1"; fi; }
call() { # method path [json]
  local m=$1 p=$2 d=${3:-}
  if [ -n "$d" ]; then
    curl -sk -b $JAR -c $JAR -X "$m" -H 'X-Requested-With: cloudpanel' -H 'Content-Type: application/json' -d "$d" "$API$p"
  else
    curl -sk -b $JAR -c $JAR -X "$m" -H 'X-Requested-With: cloudpanel' "$API$p"
  fi
}
code() { # method path [json] -> HTTP status
  local m=$1 p=$2 d=${3:-}
  curl -sk -o /dev/null -w '%{http_code}' -b $JAR -c $JAR -X "$m" -H 'X-Requested-With: cloudpanel' -H 'Content-Type: application/json' ${d:+-d "$d"} "$API$p"
}
j() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }
run_job() { # path -> status. The output is written to /var/tmp/job.out.
  local r id
  r=$(call POST "$1")
  id=$(echo "$r" | j 'd["job_id"]') || { echo "no job: $r" >/var/tmp/job.out; echo failed; return; }
  job_status=running
  for _ in $(seq 1 600); do
    call GET "/jobs/$id" >/var/tmp/job.json
    job_status=$(j 'd["status"]' </var/tmp/job.json)
    [ "$job_status" != running ] && break
    sleep 1
  done
  j 'd["output"]' </var/tmp/job.json >/var/tmp/job.out
  echo "$job_status"
}
host_get() { curl -s -m 5 -H "Host: $1" "http://127.0.0.1${2:-/}"; }
host_code() { curl -s -m 5 -o /dev/null -w '%{http_code}' -H "Host: $1" "http://127.0.0.1${2:-/}"; }
create() { # json -> id
  call POST /sites "$1" | j 'd.get("id","")'
}
as_user() { # user cmd...
  local u=$1
  shift
  runuser -u "$u" -- env HOME="/home/$u" PM2_HOME="/home/$u/.pm2" PATH=/usr/local/bin:/usr/bin:/bin "$@"
}

write_server() { # dir: a small app that reports what it was started with
  cat >"$1/server.js" <<'EOF'
const http = require('http');
http.createServer((req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.end(JSON.stringify({
    pid: process.pid, port: process.env.PORT, host: process.env.HOST, secret: process.env.E2E_SECRET,
    node_env: process.env.NODE_ENV, user: process.env.USER || process.env.HOME,
  }));
}).listen(process.env.PORT, '127.0.0.1');
EOF
}

login() {
  rm -f $JAR
  local pw
  pw=$(cat /var/lib/cloudpanel/initial_admin_password)
  call POST /auth/login "{\"username\":\"admin\",\"password\":\"$pw\"}" >/dev/null
  retry '[ "$(call GET /auth/me | j "d[\"username\"]")" = admin ]' || bad "login"
}

f2b_settings() { # panel-jail-enabled maxretry -> HTTP status
  code PUT /fail2ban "{\"sshd\":true,\"panel\":$1,\"maxretry\":$2,\"findtime_minutes\":10,\"bantime_minutes\":60,\"ignoreip\":[]}"
}

before_reboot() {
  login
  echo "== fail2ban after installing"
  checkr "fail2ban is running" '[ "$(systemctl is-active fail2ban)" = active ]'
  checkr "with the panel's jail" 'fail2ban-client status cloudpanel | grep -q "Currently banned"'
  # The checks up to panel_bans fail a lot of logins from addresses fail2ban would ban.
  check "the jail can be turned off for now" '[ "$(f2b_settings false 5)" = 200 ]'

  echo "== PM2: new Node.js site, prebuilt layout like a real deploy"
  R=$(call POST /sites '{"domain":"pre.test.local","site_type":"nodejs","target_port":3101}')
  PRE=$(echo "$R" | j 'd.get("id","")')
  check "create site ($R)" '[ -n "$PRE" ]'
  check "new Node.js site defaults to PM2" '[ "$(echo "$R" | j "d[\"app_manager\"]")" = pm2 ]'
  check "new site redirects www by default" '[ "$(echo "$R" | j "d[\"include_www\"] and d[\"www_redirect\"]")" = True ]'
  JOB=$(echo "$R" | j 'd.get("runtime_job_id") or ""')
  if [ -n "$JOB" ]; then
    # The job installs Node.js and PM2. Wait for it before anything else uses them.
    for _ in $(seq 1 600); do
      s=$(call GET "/jobs/$JOB" | j 'd["status"]')
      [ "$s" != running ] && break
      sleep 1
    done
    check "runtime job installs Node.js and PM2 (status $s)" '[ "$s" = succeeded ]'
    [ "$s" = succeeded ] || call GET "/jobs/$JOB" | j 'd["output"]'
  fi
  check "PM2 is installed" '[ -x /usr/bin/pm2 ] || [ -x /usr/local/bin/pm2 ]'

  W=/home/pre-test/htdocs/pre.test.local
  cat >"$W/package.json" <<'EOF'
{"name":"resume","scripts":{"build":"cross-env node scripts/run-next.js build","start":"node server.js"},"dependencies":{"next":"15.0.0"}}
EOF
  write_server "$W"
  mkdir -p "$W/.next" "$W/node_modules/traced" "$W/scripts"
  echo id >"$W/.next/BUILD_ID"
  echo keep >"$W/node_modules/traced/marker"
  echo '#!/bin/sh' >"$W/scripts/remote-deploy.sh"
  chown -R pre-test: "$W"

  echo "== Install on a prebuilt deploy (the production failure)"
  check "project is reported as prebuilt" '[ "$(call GET /sites/$PRE | j "d[\"project\"][\"prebuilt\"]")" = True ]'
  s=$(run_job /sites/$PRE/app/install)
  check "install skips and succeeds (status $s)" '[ "$s" = succeeded ]'
  check "install explains why" 'grep -q "prebuilt deploy" /var/tmp/job.out'
  check "install leaves node_modules alone" '[ -f "$W/node_modules/traced/marker" ] && [ ! -e "$W/node_modules/next" ] && [ ! -e "$W/node_modules/.bin" ]'
  s=$(run_job /sites/$PRE/app/build)
  check "build refuses with the reason (status $s)" '[ "$s" = failed ] && grep -q "prebuilt deploy" /var/tmp/job.out'

  echo "== PM2: start from a script, env comes from .env"
  printf '# my comment\nE2E_SECRET=from-file-1\n\nPORT=9999\n' >"$W/.env"
  chown pre-test: "$W/.env"
  R=$(call GET /sites/$PRE/app/env)
  check "env box shows the raw file, comments included" 'echo "$R" | j "d[\"content\"]" | grep -q "# my comment"'
  check "PORT mismatch is reported" '[ "$(echo "$R" | j "d[\"port_conflict\"]")" = 9999 ]'
  R=$(call PUT /sites/$PRE/app '{"command":"server.js","enabled":true}')
  check "save and start ($(echo "$R" | cut -c1-120))" '[ "$(echo "$R" | j "d[\"app_enabled\"]")" = True ]'
  checkr "nginx reaches the PM2 app" 'host_get pre.test.local | grep -q from-file-1'
  check "site's app port beats PORT in .env" 'host_get pre.test.local | j "d[\"port\"]" | grep -q "^3101$"'
  check "NODE_ENV defaults to production" 'host_get pre.test.local | j "d[\"node_env\"]" | grep -q production'
  check "app runs as the site user" '[ "$(ps -o user= -p "$(host_get pre.test.local | j "d[\"pid\"]")")" = pre-test ]'
  U=cloudpanel-app-pre-test-local
  check "unit is active and enabled" '[ "$(systemctl is-active $U)" = active ] && [ "$(systemctl is-enabled $U)" = enabled ]'
  check "daemon lives in the unit, not a transient one" 'systemctl show -p ControlGroup --value $U | grep -q "$U" && grep -q "$U" "/proc/$(cat /home/pre-test/.pm2/pm2.pid)/cgroup"'
  check "status lists the process" '[ "$(call GET /sites/$PRE | j "d[\"app\"][\"processes\"][0][\"status\"]")" = online ]'
  check "pm2 ls over SSH shows the same app" 'as_user pre-test pm2 jlist | j "d[0][\"name\"]" | grep -q pre.test.local'
  check "panel status shows no environment" '! call GET /sites/$PRE | grep -q from-file-1'
  check "logrotate config is installed" 'grep -q "su pre-test pre-test" /etc/logrotate.d/cloudpanel-pm2-pre-test-local && logrotate -d /etc/logrotate.d/cloudpanel-pm2-pre-test-local >/dev/null 2>&1'

  echo "== .env: the box and the file are the same thing"
  R=$(call PUT /sites/$PRE/app '{"command":"server.js","enabled":true,"env_text":"# my comment\nE2E_SECRET=from-box-2 # note\nQUOTED=\"a b\"\n"}')
  check "box edit lands in the file, comments kept" 'grep -q "^# my comment" "$W/.env" && grep -q "from-box-2" "$W/.env"'
  check "file stays owned by the site user" '[ "$(stat -c %U "$W/.env")" = pre-test ]'
  checkr "box edit reaches the app" 'host_get pre.test.local | grep -q from-box-2'
  sed -i 's/from-box-2/from-editor-3/' "$W/.env"
  check "file edit shows in the box" 'call GET /sites/$PRE/app/env | grep -q from-editor-3'
  check "file edit is flagged as not applied" '[ "$(call GET /sites/$PRE/app/env | j "d[\"pending\"]")" = True ]'
  check "restart applies it" 'call POST /sites/$PRE/app/restart | grep -q active_state'
  checkr "restart picks up the file" 'host_get pre.test.local | grep -q from-editor-3'
  check "nothing pending afterwards" '[ "$(call GET /sites/$PRE/app/env | j "d[\"pending\"]")" = False ]'
  rm -f "$W/.env"
  R=$(call PUT /sites/$PRE/app '{"command":"server.js","enabled":true,"env_text":"E2E_SECRET=new-5\n"}')
  check "new .env is not world-readable" '[ "$(stat -c %a "$W/.env")" = 640 ]'
  checkr "new .env reaches the app" 'host_get pre.test.local | grep -q new-5'

  echo "== .env: secrets stay out of sight"
  check "wrapper config is private" '[ "$(stat -c %a /home/pre-test/.cloudpanel/pm2.config.js)" = 600 ] && [ "$(stat -c %U /home/pre-test/.cloudpanel/pm2.config.js)" = pre-test ]'
  check "secret is not in any command line" '! ps -eo args | grep -v grep | grep -q new-5'
  check "secret is not in the unit" '! systemctl show $U | grep -q new-5 && ! grep -q new-5 /etc/systemd/system/$U.service'
  check "secret is not in the panel log" '! journalctl -u cloudpanel --no-pager | grep -q new-5'

  echo "== .env: symlink to a root-only file"
  cp "$W/.env" /var/tmp/env.bak
  rm -f "$W/.env"
  ln -s /etc/shadow "$W/.env"
  check "reading is refused" '[ "$(code GET /sites/$PRE/app/env)" = 400 ]'
  check "saving is refused" '[ "$(code PUT /sites/$PRE/app "{\"command\":\"server.js\",\"enabled\":true,\"env_text\":\"A=1\"}")" = 400 ]'
  check "shadow is untouched" 'grep -q "^root:" /etc/shadow && [ "$(stat -c %U /etc/shadow)" = root ]'
  call POST /sites/$PRE/app/restart >/dev/null
  sleep 2
  check "shadow never reached the root-only copy" '! grep -q "^root:" /etc/cloudpanel/apps/$U.env'
  check "shadow never reached the app config" '! grep -q "root:" /home/pre-test/.cloudpanel/pm2.config.js'
  rm -f "$W/.env"
  cp /var/tmp/env.bak "$W/.env"
  chown pre-test: "$W/.env"

  echo "== PM2: cluster mode and zero-downtime reload"
  R=$(call PUT /sites/$PRE/app '{"command":"server.js","enabled":true,"pm2":{"instances":"2","max_memory":"256M"}}')
  checkr "two cluster instances online" '[ "$(call GET /sites/$PRE | j "sum(1 for p in d[\"app\"][\"processes\"] if p[\"status\"]==\"online\" and p[\"exec_mode\"]==\"cluster\")")" = 2 ]'
  check "cluster with a shell command is refused" '[ "$(code PUT /sites/$PRE/app "{\"command\":\"npm start\",\"enabled\":true,\"pm2\":{\"instances\":\"2\"}}")" = 400 ]'
  checkr "cluster answers through nginx" '[ "$(host_code pre.test.local)" = 200 ]'
  (
    fails=0
    for _ in $(seq 1 60); do
      [ "$(host_code pre.test.local)" = 200 ] || fails=$((fails + 1))
      sleep 0.1
    done
    echo "$fails" >/var/tmp/reload.fails
  ) &
  LOOP=$!
  sleep 0.5
  R=$(call POST /sites/$PRE/app/reload)
  wait $LOOP
  check "reload succeeded ($(echo "$R" | cut -c1-80))" 'echo "$R" | grep -q active_state'
  check "no failed requests during reload ($(cat /var/tmp/reload.fails) failed)" '[ "$(cat /var/tmp/reload.fails)" = 0 ]'

  echo "== PM2: stop, start, logs, crash recovery"
  check "stop" '[ "$(call POST /sites/$PRE/app/stop | j "d[\"active_state\"]")" = inactive ]'
  check "stopped app answers 502" '[ "$(host_code pre.test.local)" = 502 ]'
  check "the daemon stays up while apps are stopped" '[ "$(systemctl is-active $U)" = active ]'
  check "start" '[ "$(call POST /sites/$PRE/app/start | j "d[\"active_state\"]")" = active ]'
  checkr "started app answers" '[ "$(host_code pre.test.local)" = 200 ]'
  PID=$(host_get pre.test.local | j 'd["pid"]')
  kill -9 "$PID"
  checkr "a killed process is respawned" 'n=$(host_get pre.test.local | j "d[\"pid\"]") && [ -n "$n" ] && [ "$n" != "$PID" ]'
  as_user pre-test sh -c 'echo marker-log-line >> $PM2_HOME/logs/pre.test.local-out.log'
  check "logs come from PM2 log files" 'call GET "/sites/$PRE/app/logs?lines=20" | grep -q marker-log-line'
  check "the Logs tab reads them too" 'call GET "/sites/$PRE/logs?kind=app&lines=20" | grep -q marker-log-line'
  check "flush empties them" 'call POST /sites/$PRE/app/flush | grep -q active_state && ! call GET "/sites/$PRE/app/logs?lines=20" | grep -q marker-log-line'
  check "site stays up after flush" '[ "$(host_code pre.test.local)" = 200 ]'

  echo "== PM2: ecosystem file"
  cat >"$W/ecosystem.config.js" <<'EOF'
module.exports = { apps: [{ name: "eco-app", script: "server.js", instances: 1, exec_mode: "fork", env: { PORT: 1, FROM_ECO: "yes" } }] };
EOF
  chown pre-test: "$W/ecosystem.config.js"
  R=$(call PUT /sites/$PRE/app '{"command":null,"enabled":true,"pm2":{"use_ecosystem":true}}')
  check "ecosystem file needs no start command ($(echo "$R" | cut -c1-120))" '[ "$(echo "$R" | j "d[\"app_enabled\"]")" = True ]'
  checkr "ecosystem app is running" 'call GET /sites/$PRE | j "d[\"app\"][\"processes\"][0][\"name\"]" | grep -q eco-app'
  check "the old app was removed" '! as_user pre-test pm2 jlist | j "[p[\"name\"] for p in d]" | grep -q "pre.test.local"'
  checkr "site's port beats the ecosystem file" 'host_get pre.test.local | j "d[\"port\"]" | grep -q "^3101$"'
  rm -f "$W/ecosystem.config.js"
  R=$(call PUT /sites/$PRE/app '{"command":"server.js","enabled":true,"pm2":{"instances":"1"}}')
  checkr "back to the plain command" 'call GET /sites/$PRE | j "d[\"app\"][\"processes\"][0][\"name\"]" | grep -q pre.test.local'

  echo "== Manager switching"
  R=$(call PUT /sites/$PRE/app '{"command":"node server.js","enabled":true,"manager":"systemd"}')
  check "switch to systemd ($(echo "$R" | cut -c1-120))" '[ "$(echo "$R" | j "d[\"app_manager\"]")" = systemd ]'
  checkr "app runs under systemd" 'host_get pre.test.local | grep -q new-5'
  check "no PM2 daemon left behind" '! pgrep -u pre-test -f "God Daemon" >/dev/null'
  check "unit is the plain kind now" 'grep -q "Type=simple" /etc/systemd/system/$U.service'
  check "systemd has no reload" '[ "$(code POST /sites/$PRE/app/reload)" = 422 ]'
  check "systemd has no log flush" '[ "$(code POST /sites/$PRE/app/flush)" = 400 ]'
  sed -i 's/new-5/systemd-6/' "$W/.env"
  call POST /sites/$PRE/app/restart >/dev/null
  checkr "systemd restart picks up .env" 'host_get pre.test.local | grep -q systemd-6'
  R=$(call PUT /sites/$PRE/app '{"command":"server.js","enabled":true,"manager":"pm2"}')
  check "switch back to PM2" '[ "$(echo "$R" | j "d[\"app_manager\"]")" = pm2 ]'
  checkr "app runs under PM2 again" '[ "$(call GET /sites/$PRE | j "d[\"app\"][\"processes\"][0][\"status\"]")" = online ]'
  check "only one process serves the port" '[ "$(ss -ltnH "sport = :3101" | wc -l)" = 1 ]'

  echo "== Taking over a PM2 daemon started by hand"
  R=$(call POST /sites '{"domain":"hand.test.local","site_type":"nodejs","target_port":3102,"app_manager":"systemd","include_www":false}')
  HAND=$(echo "$R" | j 'd.get("id","")')
  H=/home/hand-test/htdocs/hand.test.local
  write_server "$H"
  printf 'E2E_SECRET=hand-7\n' >"$H/.env"
  chown -R hand-test: "$H"
  # systemd-run keeps it alive after this command returns, like an SSH session would.
  systemd-run --quiet --uid=hand-test --setenv=HOME=/home/hand-test --setenv=PORT=3102 --working-directory="$H" \
    --unit=e2e-hand --remain-after-exit /bin/sh -c 'pm2 start server.js --name old-by-hand && pm2 save'
  checkr "hand-started app is up" '[ "$(host_code hand.test.local)" = 200 ]'
  checkr "panel notices the hand-started daemon" '[ "$(call GET /sites/$HAND | j "d[\"app\"][\"foreign_daemon\"]")" = True ]'
  check "switching without consent is refused" '[ "$(code PUT /sites/$HAND/app "{\"command\":\"server.js\",\"enabled\":true,\"manager\":\"pm2\"}")" = 409 ]'
  check "the refused save changed nothing" '[ "$(call GET /sites/$HAND | j "d[\"app_manager\"]")" = systemd ]'
  R=$(call PUT /sites/$HAND/app '{"command":"server.js","enabled":true,"manager":"pm2","adopt":true}')
  check "takeover works ($(echo "$R" | cut -c1-120))" '[ "$(echo "$R" | j "d[\"app_manager\"]")" = pm2 ]'
  checkr "app is up under the unit" 'host_get hand.test.local | grep -q hand-7'
  check "daemon now belongs to the unit" 'grep -q cloudpanel-app-hand-test-local "/proc/$(cat /home/hand-test/.pm2/pm2.pid)/cgroup"'
  check "panel no longer calls it foreign" '[ "$(call GET /sites/$HAND | j "d[\"app\"][\"foreign_daemon\"]")" = False ]'
  check "old process list is kept" '[ -f /home/hand-test/.pm2/dump.pm2.pre-cloudpanel ]'
  check "the old app did not come back" '! as_user hand-test pm2 jlist | grep -q old-by-hand'
  systemctl stop e2e-hand 2>/dev/null
  systemctl reset-failed e2e-hand 2>/dev/null
  check "app survives the old session ending" '[ "$(host_code hand.test.local)" = 200 ]'

  echo "== Install and build from source"
  R=$(call POST /sites '{"domain":"src.test.local","site_type":"nodejs","target_port":3103}')
  SRC=$(echo "$R" | j 'd.get("id","")')
  S=/home/src-test/htdocs/src.test.local
  write_server "$S"
  mkdir -p "$S/src"
  cat >"$S/package.json" <<'EOF'
{"name":"src-app","version":"1.0.0","scripts":{"build":"node build.js"},"dependencies":{"ms":"2.1.3"},"devDependencies":{"is-odd":"3.0.1"}}
EOF
  cat >"$S/build.js" <<'EOF'
require('is-odd');
require('fs').writeFileSync('built.txt', String(process.env.BUILD_VAR));
EOF
  printf 'BUILD_VAR=visible-at-build\nNODE_ENV=production\n' >"$S/.env"
  chown -R src-test: "$S"
  s=$(run_job /sites/$SRC/app/install)
  check "install from source (status $s)" '[ "$s" = succeeded ] || { tail -20 /var/tmp/job.out; false; }'
  check "devDependencies are installed despite NODE_ENV in .env" '[ -d "$S/node_modules/is-odd" ]'
  check "install does not build" '[ ! -f "$S/built.txt" ]'
  s=$(run_job /sites/$SRC/app/build)
  check "build runs (status $s)" '[ "$s" = succeeded ] || { tail -20 /var/tmp/job.out; false; }'
  check "build sees .env variables" '[ "$(cat "$S/built.txt")" = visible-at-build ]'
  check "build env file is removed" '[ ! -e /home/src-test/.cloudpanel/build.env ]'
  check "build variables stayed off command lines" '! grep -q visible-at-build /var/tmp/job.out'

  echo "== Lockfile out of sync, and deploy"
  check "lockfile exists from the install" '[ -f "$S/package-lock.json" ]'
  python3 - "$S/package.json" <<'EOF'
import json, sys
p = json.load(open(sys.argv[1]))
p["dependencies"]["is-number"] = "7.0.0"
json.dump(p, open(sys.argv[1], "w"))
EOF
  R=$(call PUT /sites/$SRC/app '{"command":"server.js","enabled":true}')
  s=$(run_job /sites/$SRC/app/deploy)
  check "deploy succeeds (status $s)" '[ "$s" = succeeded ] || { tail -20 /var/tmp/job.out; false; }'
  check "fell back to npm install" 'grep -q "falling back to npm install" /var/tmp/job.out && [ -d "$S/node_modules/is-number" ]'
  check "deploy built and restarted" 'grep -q "Build finished" /var/tmp/job.out && grep -q "Deploy finished" /var/tmp/job.out'
  checkr "deployed app answers" '[ "$(host_code src.test.local)" = 200 ]'

  echo "== Text that only looks like a build script"
  cat >"$S/package.json" <<'EOF'
{"name":"src-app","version":"1.0.0","files":["build"],"dependencies":{"ms":"2.1.3"}}
EOF
  chown src-test: "$S/package.json"
  s=$(run_job /sites/$SRC/app/deploy)
  check "\"build\" outside scripts doesn't trigger a build (status $s)" '[ "$s" = succeeded ] && ! grep -q "run build" /var/tmp/job.out'
  s=$(run_job /sites/$SRC/app/build)
  check "build says there is no script (status $s)" '[ "$s" = failed ] && grep -q "no build script" /var/tmp/job.out'

  echo "== A crash loop is visible, and install brings the app back"
  R=$(call POST /sites '{"domain":"dep.test.local","site_type":"nodejs","target_port":3104,"app_command":"server.js"}')
  DEP=$(echo "$R" | j 'd.get("id","")')
  D=/home/dep-test/htdocs/dep.test.local
  cat >"$D/server.js" <<'EOF'
require('ms');
require('http').createServer((q, s) => s.end('dep ok')).listen(process.env.PORT, '127.0.0.1');
EOF
  echo '{"name":"dep","version":"1.0.0","dependencies":{"ms":"2.1.3"}}' >"$D/package.json"
  chown -R dep-test: "$D"
  call POST /sites/$DEP/app/restart >/dev/null
  checkr "the app can't start yet" '[ "$(host_code dep.test.local)" = 502 ]'
  s=$(run_job /sites/$DEP/app/install)
  check "install succeeds (status $s)" '[ "$s" = succeeded ]'
  checkr "install brings the app back with no manual restart" 'host_get dep.test.local | grep -q "dep ok"'

  echo "== Python stays on systemd"
  R=$(call POST /sites '{"domain":"py.test.local","site_type":"python","target_port":3105,"app_command":"python3 -m http.server $PORT --bind 127.0.0.1"}')
  PY=$(echo "$R" | j 'd.get("id","")')
  check "Python defaults to systemd" '[ "$(echo "$R" | j "d[\"app_manager\"]")" = systemd ]'
  check "PM2 is refused for Python" '[ "$(code PUT /sites/$PY/app "{\"command\":\"x\",\"enabled\":true,\"manager\":\"pm2\"}")" = 400 ]'
  checkr "Python app answers" '[ "$(host_code py.test.local)" = 200 ]'
  printf 'E2E_SECRET=py-8\n' >/home/py-test/htdocs/py.test.local/.env
  chown py-test: /home/py-test/htdocs/py.test.local/.env
  call POST /sites/$PY/app/restart >/dev/null
  check "Python gets .env too" 'grep -q py-8 /etc/cloudpanel/apps/cloudpanel-app-py-test-local.env'

  echo "== Upgrade: values only in the database move into .env"
  python3 - <<'EOF'
import sqlite3
c = sqlite3.connect("/var/lib/cloudpanel/cloudpanel.db")
c.execute("UPDATE sites SET app_env = ? WHERE domain = 'py.test.local'", ('{"LEGACY_ONLY":"from db","E2E_SECRET":"loses"}',))
c.commit()
EOF
  R=$(call GET /sites/$PY/app/env)
  check "database-only key appears in the box" 'echo "$R" | j "d[\"content\"]" | grep -q "LEGACY_ONLY=\"from db\""'
  check "and is listed as imported" '[ "$(echo "$R" | j "\",\".join(d[\"imported_keys\"])")" = LEGACY_ONLY ]'
  check ".env wins over the database" '! echo "$R" | j "d[\"content\"]" | grep -q loses'
  TEXT=$(echo "$R" | python3 -c 'import sys,json;print(json.dumps(json.load(sys.stdin)["content"]))')
  call PUT /sites/$PY/app "{\"command\":\"python3 -m http.server \$PORT --bind 127.0.0.1\",\"enabled\":true,\"env_text\":$TEXT}" >/dev/null
  check "first save writes it to .env" 'grep -q LEGACY_ONLY /home/py-test/htdocs/py.test.local/.env'
  check "first save clears the database copy" '[ -z "$(call GET /sites/$PY/app/env | j "d[\"imported_keys\"] or \"\"")" ]'

  echo "== www redirect"
  WWW=$(create '{"domain":"site.test.local","site_type":"static"}')
  C=/var/tmp/cert
  mkdir -p $C
  make_cert() { # name, SANs
    openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$C/$1.key" -out "$C/$1.crt" -subj "/CN=site.test.local" -addext "subjectAltName=$2" 2>/dev/null
  }
  make_cert both "DNS:site.test.local,DNS:www.site.test.local"
  make_cert naked "DNS:site.test.local"
  location() { curl -sk -m 5 -o /dev/null -w '%{http_code} %{redirect_url}' --resolve "$1:80:127.0.0.1" --resolve "$1:443:127.0.0.1" "$2://$1/a/b?c=1"; }

  checkr "http://www redirects without HTTPS" '[ "$(location www.site.test.local http)" = "301 http://site.test.local/a/b?c=1" ]'
  check "the naked domain serves the site" '[ "$(location site.test.local http | cut -d" " -f1)" = 200 ]'
  check "ACME still answers on www" 'mkdir -p /var/www/html/.well-known/acme-challenge && echo tok > /var/www/html/.well-known/acme-challenge/t && [ "$(curl -s -H "Host: www.site.test.local" http://127.0.0.1/.well-known/acme-challenge/t)" = tok ]'
  check "nginx config is valid" 'nginx -t -q 2>/dev/null'

  body=$(python3 -c "import json;print(json.dumps({'custom_cert':open('$C/both.crt').read(),'custom_key':open('$C/both.key').read()}))")
  R=$(call POST /sites/$WWW/ssl "$body")
  check "install a certificate covering www" '[ "$(call GET /sites/$WWW | j "d[\"certificate_covers_www\"]")" = True ]'
  checkr "http://naked goes to https://naked" '[ "$(location site.test.local http)" = "301 https://site.test.local/a/b?c=1" ]'
  checkr "http://www goes straight to https://naked" '[ "$(location www.site.test.local http)" = "301 https://site.test.local/a/b?c=1" ]'
  checkr "https://www goes to https://naked" '[ "$(location www.site.test.local https)" = "301 https://site.test.local/a/b?c=1" ]'
  check "https://naked serves the site" '[ "$(location site.test.local https | cut -d" " -f1)" = 200 ]'
  check "HTTPS www block serves the right certificate" 'echo | openssl s_client -connect 127.0.0.1:443 -servername www.site.test.local 2>/dev/null | openssl x509 -noout -ext subjectAltName | grep -q www.site.test.local'
  check "nginx config is valid with HTTPS" 'nginx -t -q 2>/dev/null'

  body=$(python3 -c "import json;print(json.dumps({'custom_cert':open('$C/naked.crt').read(),'custom_key':open('$C/naked.key').read()}))")
  R=$(call POST /sites/$WWW/ssl "$body")
  check "site reports the certificate lacks www" '[ "$(call GET /sites/$WWW | j "d[\"certificate_covers_www\"]")" = False ]'
  check "no HTTPS www block without coverage" '! call GET /sites/$WWW/vhost | j "d[\"vhost\"]" | grep -q "server_name www.site.test.local;"'
  checkr "http://www still redirects" '[ "$(location www.site.test.local http)" = "301 https://site.test.local/a/b?c=1" ]'
  check "nginx config is valid without coverage" 'nginx -t -q 2>/dev/null'

  R=$(call PATCH /sites/$WWW '{"include_www":true,"www_redirect":false}')
  check "alias mode serves both" 'call GET /sites/$WWW/vhost | j "d[\"vhost\"]" | grep -q "server_name site.test.local www.site.test.local;"'
  check "alias mode keeps the host on redirect" 'call GET /sites/$WWW/vhost | j "d[\"vhost\"]" | grep -q "https://\$host\$request_uri"'
  R=$(call PATCH /sites/$WWW '{"include_www":false}')
  check "off drops www" '! call GET /sites/$WWW/vhost | j "d[\"vhost\"]" | grep -q www.site.test.local'
  check "off clears the redirect" '[ "$(call GET /sites/$WWW | j "d[\"www_redirect\"]")" = False ]'
  check "nginx config is valid when off" 'nginx -t -q 2>/dev/null'

  echo "== www edge cases"
  R=$(call POST /sites '{"domain":"www.prefixed.test.local","site_type":"static"}')
  check "a www. domain gets no www.www." '[ "$(echo "$R" | j "d[\"include_www\"]")" = False ]'
  R=$(call POST /sites '{"domain":"prefixed.test.local","site_type":"static"}')
  check "the naked domain leaves an existing www site alone" '[ "$(echo "$R" | j "d[\"include_www\"]")" = False ]'
  R=$(call POST /sites '{"domain":"taken.test.local","site_type":"static"}')
  check "a www site is refused when the naked site handles it" '[ "$(code POST /sites "{\"domain\":\"www.taken.test.local\",\"site_type\":\"static\"}")" = 409 ]'
  check "nginx config is valid after all of that" 'nginx -t -q 2>/dev/null'

  panel_hostname
  panel_port_closed
  summary
}

# Everything here also runs the panel's real restart, so its session cookie has to survive it.
panel_port_closed() {
  echo "== Closing the panel's own port"
  PH=panel.test.local
  IP=$(hostname -i | cut -d' ' -f1)
  mkdir -p /etc/cloudpanel/tls
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout /etc/cloudpanel/tls/e2e.key -out /etc/cloudpanel/tls/e2e.crt \
    -subj "/CN=$PH" -addext "subjectAltName=DNS:$PH" 2>/dev/null
  python3 - <<'EOF'
import json, sqlite3
c = sqlite3.connect("/var/lib/cloudpanel/cloudpanel.db")
c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_tls', ?)", (json.dumps(
    {"hostname": "panel.test.local", "cert": "/etc/cloudpanel/tls/e2e.crt", "key": "/etc/cloudpanel/tls/e2e.key"}),))
c.commit()
EOF
  systemctl restart cloudpanel
  retry '[ "$(curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1:8443/)" = 200 ]'
  ph() { curl -sk -m 10 --resolve "$PH:443:127.0.0.1" "$@"; }
  J3=/var/tmp/closing.jar
  rm -f $J3
  pxy3() { # method path [json]
    ph -b $J3 -c $J3 -X "$1" -H 'X-Requested-With: cloudpanel' -H 'Content-Type: application/json' -H "Origin: https://$PH" ${3:+-d "$3"} "https://$PH/api$2"
  }
  PW=$(cat /var/lib/cloudpanel/initial_admin_password)
  pxy3 POST /auth/login "{\"username\":\"admin\",\"password\":\"$PW\"}" >/dev/null
  check "the port starts open" '[ "$(call GET /settings/panel-cert | j "d[\"direct\"][\"closed\"]")" = False ]'
  check "the panel knows a session on the port isn't using the hostname" '[ "$(call GET /settings/panel-cert | j "d[\"direct\"][\"on_hostname\"]")" = False ]'
  check "and a session on the hostname is" '[ "$(pxy3 GET /settings/panel-cert | j "d[\"direct\"][\"on_hostname\"]")" = True ]'
  check "closing from the port itself is refused" '[ "$(code PUT /settings/panel-access "{\"open\":false}")" = 400 ]'
  # curl matches stored cookies against the Host header, so this session is sent by hand.
  COOKIE=$(awk 'NF>=7 {print $6"="$7}' $JAR | tail -1)
  check "a faked proxy header doesn't count" '[ "$(curl -sk -o /dev/null -w "%{http_code}" -H "Cookie: $COOKIE" -X PUT -H "X-Requested-With: cloudpanel" -H "Content-Type: application/json" -H "Host: $PH" -H "X-CloudPanel-Proxy: guessed" -d "{\"open\":false}" https://127.0.0.1:8443/api/settings/panel-access)" = 400 ]'
  check "and that left it open" '[ -z "$(python3 -c "import sqlite3;print(sqlite3.connect(\"/var/lib/cloudpanel/cloudpanel.db\").execute(\"select value from settings where key=\x27panel_direct_closed\x27\").fetchone() or \"\")")" ]'
  check "the firewall guard explains what to do instead" 'call POST /firewall/rules "{\"port\":8443,\"protocol\":\"tcp\",\"action\":\"deny\"}" | grep -q "Panel certificate"'
  check "the port answers from outside loopback before closing" '[ "$(curl -sk -m 5 -o /dev/null -w "%{http_code}" https://$IP:8443/)" = 200 ]'

  R=$(pxy3 PUT /settings/panel-access '{"open":false}')
  check "closing from the hostname works ($R)" 'echo "$R" | grep -q restarting'
  checkr "the panel comes back listening on loopback only" '[ "$(ss -ltnH "sport = :8443" | awk "{print \$4}")" = "127.0.0.1:8443" ]'
  check "the port no longer answers from outside loopback" '! curl -sk -m 5 -o /dev/null https://$IP:8443/'
  checkr "the hostname still works, with the same session" '[ "$(pxy3 GET /settings/panel-cert | j "d[\"direct\"][\"closed\"]")" = True ]'
  check "an SSH tunnel's route still works" '[ "$(curl -sk -m 5 -o /dev/null -w "%{http_code}" https://127.0.0.1:8443/)" = 200 ]'
  check "the hostname can't be removed while it's the only way in" '[ "$(pxy3 DELETE /settings/panel-cert | j "\"Reopen\" in d[\"error\"]")" = True ]'
  check "a firewall rule on the closed port is accepted" 'call POST /firewall/rules "{\"port\":8443,\"protocol\":\"tcp\",\"action\":\"deny\"}" | grep -q "\"port\":8443"'
  check "and SSH is still protected" 'call POST /firewall/rules "{\"port\":22,\"protocol\":\"tcp\",\"action\":\"deny\"}" | grep -q "block SSH"'
  RID=$(call GET /firewall/rules | j '[r["id"] for r in d if r["port"]==8443][0]')
  call DELETE "/firewall/rules/$RID" >/dev/null
  # Stays closed for the reboot, which after_reboot checks.
}

panel_port_after_reboot() {
  PH=panel.test.local
  IP=$(hostname -i | cut -d' ' -f1)
  ph() { curl -sk -m 10 --resolve "$PH:443:127.0.0.1" "$@"; }
  echo "== The closed port after a reboot"
  check "the port is still closed" '[ "$(ss -ltnH "sport = :8443" | awk "{print \$4}")" = "127.0.0.1:8443" ]'
  checkr "the hostname still works" '[ "$(ph -o /dev/null -w "%{http_code}" https://$PH/)" = 200 ]'
  check "the panel won't report a fallback" '[ "$(call GET /settings/panel-cert | j "d[\"direct\"][\"fell_back\"]")" = False ]'

  echo "== It fails open if the hostname can't be served"
  mv /etc/cloudpanel/tls/e2e.crt /etc/cloudpanel/tls/e2e.crt.off
  systemctl restart cloudpanel
  checkr "a missing certificate opens the port again" 'ss -ltnH "sport = :8443" | grep -q "0.0.0.0:8443"'
  checkr "so the panel can still be reached" '[ "$(curl -sk -m 5 -o /dev/null -w "%{http_code}" https://$IP:8443/)" = 200 ]'
  check "and it says so" '[ "$(call GET /settings/panel-cert | j "d[\"direct\"][\"fell_back\"]")" = True ]'
  mv /etc/cloudpanel/tls/e2e.crt.off /etc/cloudpanel/tls/e2e.crt
  systemctl restart cloudpanel
  checkr "fixing it closes the port again" '[ "$(ss -ltnH "sport = :8443" | awk "{print \$4}")" = "127.0.0.1:8443" ]'
  retry '[ "$(ph -o /dev/null -w "%{http_code}" https://$PH/)" = 200 ]'

  echo "== Getting back in from the command line"
  /usr/local/bin/cloudpanel panel-access-open >/var/tmp/open.out 2>&1
  check "the command reports it ($(cut -c1-60 /var/tmp/open.out))" 'grep -q "opening again" /var/tmp/open.out'
  checkr "the port is open again" 'ss -ltnH "sport = :8443" | grep -q "0.0.0.0:8443"'
  checkr "the panel answers there" '[ "$(curl -sk -m 5 -o /dev/null -w "%{http_code}" https://$IP:8443/)" = 200 ]'
  check "and it no longer reports closed" '[ "$(call GET /settings/panel-cert | j "d[\"direct\"][\"closed\"]")" = False ]'

  echo "== Closing and reopening from the panel"
  J3=/var/tmp/closing.jar
  rm -f $J3
  pxy3() { ph -b $J3 -c $J3 -X "$1" -H 'X-Requested-With: cloudpanel' -H 'Content-Type: application/json' -H "Origin: https://$PH" ${3:+-d "$3"} "https://$PH/api$2"; }
  PW=$(cat /var/lib/cloudpanel/initial_admin_password)
  pxy3 POST /auth/login "{\"username\":\"admin\",\"password\":\"$PW\"}" >/dev/null
  pxy3 PUT /settings/panel-access '{"open":false}' >/dev/null
  checkr "closed again" '[ "$(ss -ltnH "sport = :8443" | awk "{print \$4}")" = "127.0.0.1:8443" ]'
  retry '[ "$(pxy3 GET /settings/panel-cert | j "d[\"direct\"][\"closed\"]")" = True ]'
  pxy3 PUT /settings/panel-access '{"open":true}' >/dev/null
  checkr "the Open button's route reopens it" 'ss -ltnH "sport = :8443" | grep -q "0.0.0.0:8443"'
  retry '[ "$(curl -sk -m 5 -o /dev/null -w "%{http_code}" https://$IP:8443/)" = 200 ]'
  R=$(call DELETE /settings/panel-cert)
  check "the hostname can be removed once it's open" '[ ! -e /etc/nginx/sites-available/cloudpanel-panel.conf ]'
  rm -f /etc/cloudpanel/tls/e2e.crt /etc/cloudpanel/tls/e2e.key
  # This test restarts far faster than anyone would, which trips systemd's start limit.
  systemctl reset-failed cloudpanel
  systemctl restart cloudpanel
  retry '[ "$(curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1:8443/)" = 200 ]'
}

# Real Let's Encrypt can't run here, so a stored self-signed certificate stands in for one. A
# restart then takes the same path as upgrading a server that already has a panel hostname.
panel_hostname() {
  echo "== The panel's own hostname on port 443"
  PH=panel.test.local
  VHOST=/etc/nginx/sites-available/cloudpanel-panel.conf
  mkdir -p /etc/cloudpanel/tls
  openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout /etc/cloudpanel/tls/e2e.key -out /etc/cloudpanel/tls/e2e.crt \
    -subj "/CN=$PH" -addext "subjectAltName=DNS:$PH" 2>/dev/null
  python3 - <<'EOF'
import json, sqlite3
c = sqlite3.connect("/var/lib/cloudpanel/cloudpanel.db")
c.execute("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_tls', ?)", (json.dumps(
    {"hostname": "panel.test.local", "cert": "/etc/cloudpanel/tls/e2e.crt", "key": "/etc/cloudpanel/tls/e2e.key"}),))
c.commit()
EOF
  systemctl restart cloudpanel
  checkr "upgrading creates the nginx site" '[ -f $VHOST ] && [ -L /etc/nginx/sites-enabled/cloudpanel-panel.conf ]'
  check "the site holding the secret is root-only" '[ "$(stat -c %a $VHOST)" = 600 ] && [ "$(stat -c %U $VHOST)" = root ]'
  check "the secret file is root-only" '[ "$(stat -c %a /var/lib/cloudpanel/proxy.secret)" = 600 ]'
  check "nginx config is valid" 'nginx -t -q 2>/dev/null'
  ph() { curl -sk -m 10 --resolve "$PH:443:127.0.0.1" --resolve "$PH:80:127.0.0.1" "$@"; }
  checkr "the panel answers at https://hostname" '[ "$(ph -o /dev/null -w "%{http_code}" https://$PH/)" = 200 ]'
  check "port 443 serves the panel certificate" 'echo | openssl s_client -connect 127.0.0.1:443 -servername $PH 2>/dev/null | openssl x509 -noout -subject | grep -q $PH'
  check "port 80 redirects to https" '[ "$(ph -o /dev/null -w "%{redirect_url}" "http://$PH/a?b=1")" = "https://$PH/a?b=1" ]'
  check "renewals can still validate on port 80" 'mkdir -p /var/www/html/.well-known/acme-challenge && echo tok > /var/www/html/.well-known/acme-challenge/p && [ "$(ph http://$PH/.well-known/acme-challenge/p)" = tok ]'

  J2=/var/tmp/proxied.jar
  rm -f $J2
  pxy() { # method path [json] [extra curl args]
    local m=$1 p=$2 d=${3:-}
    shift
    shift
    [ $# -gt 0 ] && shift
    ph -b $J2 -c $J2 -X "$m" -H 'X-Requested-With: cloudpanel' -H 'Content-Type: application/json' -H "Origin: https://$PH" ${d:+-d "$d"} "$@" "https://$PH/api$p"
  }
  PW=$(cat /var/lib/cloudpanel/initial_admin_password)
  check "signing in works through nginx" 'pxy POST /auth/login "{\"username\":\"admin\",\"password\":\"$PW\"}" | grep -q admin'
  check "the session cookie is marked Secure" 'pxy POST /auth/login "{\"username\":\"admin\",\"password\":\"$PW\"}" -o /dev/null -D - | grep -i "^set-cookie" | grep -q Secure'
  check "a signed-in change passes the CSRF check through nginx" 'pxy POST /sites/$PRE/app/restart | grep -q active_state'
  check "a request from another site is still refused" '[ "$(ph -o /dev/null -w "%{http_code}" -b $J2 -X POST -H "X-Requested-With: cloudpanel" -H "Origin: https://evil.example" https://$PH/api/sites/$PRE/app/restart)" = 400 ]'
  check "large uploads aren't capped by nginx" 'grep -q "client_max_body_size 0" $VHOST'

  echo "== The client address behind nginx"
  AUTH=/var/log/cloudpanel/auth.log
  failed() { # curl args: one failed login
    curl -sk -m 10 -o /dev/null -X POST -H 'X-Requested-With: cloudpanel' -H 'Content-Type: application/json' \
      -d '{"username":"e2e-probe","password":"wrong"}' "$@"
  }
  : >$AUTH
  failed --interface 127.0.0.2 --resolve "$PH:443:127.0.0.1" "https://$PH/api/auth/login"
  checkr "a client behind nginx is logged with its own address" 'grep -q "from 127.0.0.2 " $AUTH'
  check "and not as the proxy" '! grep -q "from 127.0.0.1 " $AUTH'
  : >$AUTH
  failed -H 'X-Real-IP: 203.0.113.9' https://127.0.0.1:8443/api/auth/login
  checkr "X-Real-IP is ignored without the secret" 'grep -q "from 127.0.0.1 " $AUTH && ! grep -q 203.0.113.9 $AUTH'
  : >$AUTH
  failed -H 'X-Real-IP: 203.0.113.9' -H 'X-CloudPanel-Proxy: guessed' https://127.0.0.1:8443/api/auth/login
  checkr "a wrong secret changes nothing" 'grep -q "from 127.0.0.1 " $AUTH && ! grep -q 203.0.113.9 $AUTH'
  : >$AUTH
  failed -H 'X-Real-IP: 203.0.113.9' --resolve "$PH:443:127.0.0.1" --interface 127.0.0.3 "https://$PH/api/auth/login"
  checkr "a client can't fake its address through nginx" 'grep -q "from 127.0.0.3 " $AUTH && ! grep -q 203.0.113.9 $AUTH'
  check "a site user can't read the secret" '! runuser -u src-test -- cat $VHOST 2>/dev/null && ! runuser -u src-test -- cat /var/lib/cloudpanel/proxy.secret 2>/dev/null'
  for _ in 1 2 3 4 5 6; do failed --interface 127.0.0.4 --resolve "$PH:443:127.0.0.1" "https://$PH/api/auth/login"; done
  check "one client's failures lock out that client" '[ "$(curl -sk -m 10 -o /dev/null -w "%{http_code}" --interface 127.0.0.4 --resolve "$PH:443:127.0.0.1" -X POST -H "X-Requested-With: cloudpanel" -H "Content-Type: application/json" -d "{\"username\":\"e2e-probe\",\"password\":\"wrong\"}" "https://$PH/api/auth/login")" = 429 ]'
  check "and nobody else" 'pxy POST /auth/login "{\"username\":\"admin\",\"password\":\"$PW\"}" | grep -q admin'

  # Behind Cloudflare. A connection really comes from these addresses when they are on this
  # machine, and is not in any way marked as a test.
  EDGE=173.245.48.1
  EDGE6=2606:4700::1
  OTHER=198.51.100.7
  ip addr add $EDGE/32 dev lo
  ip addr add $OTHER/32 dev lo
  sysctl -qw net.ipv6.conf.lo.disable_ipv6=0
  ip -6 addr add $EDGE6/128 dev lo
  via_nginx() { # source-address [curl args]: one failed login on port 443
    local src=$1
    shift
    case $src in *:*) failed --interface "$src" --resolve "$PH:443:[$src]" "$@" "https://$PH/api/auth/login" ;;
      *) failed --interface "$src" --resolve "$PH:443:$src" "$@" "https://$PH/api/auth/login" ;; esac
  }
  via_port() { # source-address [curl args]: one failed login on the panel's own port
    local src=$1
    shift
    failed --interface "$src" "$@" "https://$src:8443/api/auth/login"
  }
  logged() { grep -q "from $1 " $AUTH; }

  check "the nginx site trusts Cloudflare's IPv4 ranges" 'grep -q "set_real_ip_from 173.245.48.0/20;" $VHOST'
  check "and its IPv6 ranges" 'grep -q "set_real_ip_from 2606:4700::/32;" $VHOST'
  check "and reads CF-Connecting-IP" 'grep -q "real_ip_header CF-Connecting-IP;" $VHOST'
  check "nginx accepts that" 'nginx -t -q 2>/dev/null'
  : >$AUTH
  via_nginx $EDGE -H 'CF-Connecting-IP: 203.0.113.50'
  checkr "a visitor through Cloudflare is logged with their own address" 'logged 203.0.113.50'
  check "and not as Cloudflare's" '! logged $EDGE'
  : >$AUTH
  via_nginx $EDGE6 -H 'CF-Connecting-IP: 2001:db8::50'
  checkr "the same for IPv6 on both sides" 'logged 2001:db8::50 && ! logged $EDGE6'
  : >$AUTH
  via_nginx $EDGE -H 'CF-Connecting-IP: 203.0.113.51' -H 'X-Real-IP: 203.0.113.99' -H 'X-CloudPanel-Proxy: guessed'
  checkr "a visitor can't override that with other headers" 'logged 203.0.113.51 && ! logged 203.0.113.99'
  : >$AUTH
  via_nginx $OTHER -H 'CF-Connecting-IP: 203.0.113.9'
  checkr "a forged CF-Connecting-IP through nginx is ignored" 'logged $OTHER && ! logged 203.0.113.9'
  : >$AUTH
  via_nginx 127.0.0.3 -H 'CF-Connecting-IP: 203.0.113.9'
  checkr "also from this machine" 'logged 127.0.0.3 && ! logged 203.0.113.9'
  : >$AUTH
  via_port $EDGE -H 'CF-Connecting-IP: 203.0.113.52'
  checkr "a visitor through Cloudflare on the panel's own port is logged too" 'logged 203.0.113.52 && ! logged $EDGE'
  : >$AUTH
  via_port $OTHER -H 'CF-Connecting-IP: 203.0.113.9'
  checkr "a forged CF-Connecting-IP on the panel's own port is ignored" 'logged $OTHER && ! logged 203.0.113.9'
  : >$AUTH
  failed -H 'CF-Connecting-IP: 203.0.113.9' https://127.0.0.1:8443/api/auth/login
  checkr "also from this machine" 'logged 127.0.0.1 && ! logged 203.0.113.9'

  attempt() { via_nginx "$@" -w '%{http_code}'; }
  for _ in 1 2 3 4 5 6; do via_nginx $EDGE -H 'CF-Connecting-IP: 203.0.113.60'; done
  check "a visitor's failures through Cloudflare lock out that visitor" '[ "$(attempt $EDGE -H "CF-Connecting-IP: 203.0.113.60")" = 429 ]'
  check "and not everybody on the same Cloudflare address" '[ "$(attempt $EDGE -H "CF-Connecting-IP: 203.0.113.61")" = 401 ]'
  for i in 1 2 3 4 5 6; do via_nginx $OTHER -H "CF-Connecting-IP: 203.0.113.$i"; done
  check "changing a forged address on every try doesn't dodge the lockout" '[ "$(attempt $OTHER -H "CF-Connecting-IP: 203.0.113.7")" = 429 ]'

  restart_panel() {
    systemctl restart cloudpanel
    retry '[ "$(curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1:8443/)" = 200 ]'
  }
  cf_status() { call GET /settings/panel-cert | j "d[\"cloudflare\"][\"$1\"]"; }
  checkr "the panel fetched Cloudflare's current list" '[ "$(cf_status built_in)" = False ] && [ "$(cf_status stale)" = False ]'

  # A list served from here shows what a change at Cloudflare does.
  API_DIR=/var/tmp/cf-api
  mkdir -p $API_DIR
  serve_list() { printf '{"success":true,"result":{"ipv4_cidrs":[%s],"ipv6_cidrs":[%s]}}' "$1" "$2" >$API_DIR/ips; }
  serve_list '"198.51.100.0/24"' '"2001:db8::/32"'
  python3 -m http.server --bind 127.0.0.1 --directory $API_DIR 18081 >/dev/null 2>&1 &
  API_PID=$!
  retry 'curl -s -o /dev/null http://127.0.0.1:18081/ips'
  mkdir -p /etc/systemd/system/cloudpanel.service.d
  printf '[Service]\nEnvironment=CLOUDPANEL_CLOUDFLARE_IPS_URL=http://127.0.0.1:18081/ips\n' \
    >/etc/systemd/system/cloudpanel.service.d/e2e-cloudflare.conf
  systemctl daemon-reload
  restart_panel
  checkr "a new list reaches nginx" 'grep -q "set_real_ip_from 198.51.100.0/24;" $VHOST'
  check "and replaces the old one" '! grep -q "173.245.48.0/20" $VHOST'
  check "nginx accepts it" 'nginx -t -q 2>/dev/null'
  checkr "nginx trusts a new Cloudflare address" ': >$AUTH; via_nginx $OTHER -H "CF-Connecting-IP: 203.0.113.70"; logged 203.0.113.70'
  checkr "and no longer an old one" ': >$AUTH; via_nginx $EDGE -H "CF-Connecting-IP: 203.0.113.9"; logged $EDGE && ! logged 203.0.113.9'
  checkr "the panel's own port follows" ': >$AUTH; via_port $OTHER -H "CF-Connecting-IP: 203.0.113.71"; logged 203.0.113.71'
  checkr "in both directions" ': >$AUTH; via_port $EDGE -H "CF-Connecting-IP: 203.0.113.9"; logged $EDGE && ! logged 203.0.113.9'

  LISTED=$(stat -c %Y $VHOST)
  panel_warned() { journalctl -u cloudpanel --since "$SINCE" --no-pager | grep -q "could not refresh Cloudflare"; }
  serve_list '"0.0.0.0/0"' '"::/0"'
  SINCE=$(date '+%F %T')
  sleep 1
  restart_panel
  checkr "a list trusting everyone is refused, with a warning" 'panel_warned'
  check "nginx doesn't get it" '! grep -q "0.0.0.0/0" $VHOST && [ "$(stat -c %Y $VHOST)" = "$LISTED" ]'
  : >$AUTH
  failed -H 'CF-Connecting-IP: 203.0.113.9' https://127.0.0.1:8443/api/auth/login
  checkr "and the panel doesn't believe it" 'logged 127.0.0.1 && ! logged 203.0.113.9'
  kill $API_PID
  wait $API_PID 2>/dev/null
  SINCE=$(date '+%F %T')
  sleep 1
  restart_panel
  checkr "being unable to reach the list gives a warning" 'panel_warned'
  check "and keeps the last good one" 'grep -q "set_real_ip_from 198.51.100.0/24;" $VHOST && [ "$(stat -c %Y $VHOST)" = "$LISTED" ]'

  # Back to the real list, without these addresses.
  rm -f /etc/systemd/system/cloudpanel.service.d/e2e-cloudflare.conf
  rmdir /etc/systemd/system/cloudpanel.service.d 2>/dev/null
  systemctl daemon-reload
  ip addr del $EDGE/32 dev lo
  ip addr del $OTHER/32 dev lo
  ip -6 addr del $EDGE6/128 dev lo
  restart_panel
  checkr "the panel returns to Cloudflare's list" 'grep -q "set_real_ip_from 173.245.48.0/20;" $VHOST && ! grep -q "198.51.100.0/24" $VHOST'
  check "nginx accepts it" 'nginx -t -q 2>/dev/null'

  panel_bans

  echo "== Hostname conflicts and removal"
  check "a site can't take the panel's hostname" '[ "$(code POST /sites "{\"domain\":\"$PH\",\"site_type\":\"static\"}")" = 409 ]'
  check "the panel can't take a site's hostname" '[ "$(code POST /settings/panel-cert "{\"hostname\":\"src.test.local\",\"email\":\"e2e@example.com\",\"skip_dns_check\":true}")" = 409 ]'
  check "or the www of one" '[ "$(call GET /sites | j "[x for x in d if x[\"domain\"]==\"src.test.local\"][0][\"include_www\"]")" = True ] && [ "$(code POST /settings/panel-cert "{\"hostname\":\"www.src.test.local\",\"email\":\"e2e@example.com\",\"skip_dns_check\":true}")" = 409 ]'
  check "the panel reports its address" '[ "$(call GET /settings/panel-cert | j "d[\"url\"]")" = "https://$PH" ]'
  MTIME=$(stat -c %Y $VHOST)
  systemctl restart cloudpanel
  retry '[ "$(curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1:8443/)" = 200 ]'
  check "restarting leaves an unchanged site alone" '[ "$(stat -c %Y $VHOST)" = "$MTIME" ]'
  R=$(call DELETE /settings/panel-cert)
  check "switching back removes the nginx site" '[ ! -e $VHOST ] && [ ! -L /etc/nginx/sites-enabled/cloudpanel-panel.conf ]'
  check "nginx config is valid after removal" 'nginx -t -q 2>/dev/null'
  rm -f /etc/cloudpanel/tls/e2e.crt /etc/cloudpanel/tls/e2e.key
  # Back on the panel's default certificate for whatever runs next.
  systemctl restart cloudpanel
  retry '[ "$(curl -sk -o /dev/null -w "%{http_code}" https://127.0.0.1:8443/)" = 200 ]'
}

# Real fail2ban, fed by real failed logins, on the routes panel_hostname set up. Those functions
# are still defined here, because it calls this.
panel_bans() {
  echo "== fail2ban bans stop a client on every route"
  BANS=/run/cloudpanel-bans
  JAIL=/etc/fail2ban/jail.d/cloudpanel.conf
  ip addr add $EDGE/32 dev lo
  ip addr add $OTHER/32 dev lo
  ip -6 addr add $EDGE6/128 dev lo
  : >$AUTH
  on_443() { via_nginx "$@" -w '%{http_code}'; }
  on_port() { via_port "$@" -w '%{http_code}'; }
  cf() { echo "CF-Connecting-IP: $1"; }
  in_jail() { fail2ban-client status cloudpanel 2>/dev/null | grep 'Banned IP list' | grep -qwF -- "$1"; }
  api_ban() { code POST /fail2ban/ban "{\"jail\":\"cloudpanel\",\"ip\":\"$1\"}"; }
  api_unban() { code POST /fail2ban/unban "{\"jail\":\"cloudpanel\",\"ip\":\"$1\"}"; }

  check "the jail goes back on, banning after 3 failures" '[ "$(f2b_settings true 3)" = 200 ]'
  checkr "it is running" 'fail2ban-client status cloudpanel >/dev/null 2>&1'
  check "it uses the panel's action" 'grep -q "^action = cloudpanel$" $JAIL && [ -f /etc/fail2ban/action.d/cloudpanel.conf ]'
  check "and doesn't name a port for a firewall to close" '! sed -n "/^\[cloudpanel\]/,\$p" $JAIL | grep -q "^port"'
  check "fail2ban accepts that" 'fail2ban-client -t >/dev/null 2>&1'

  VISITOR=203.0.113.80
  check "a visitor through Cloudflare isn't refused to begin with" '[ "$(on_443 $EDGE -H "$(cf $VISITOR)")" = 401 ]'
  via_nginx $EDGE -H "$(cf $VISITOR)"
  via_port $EDGE -H "$(cf $VISITOR)"
  checkr "their failures on both ports get them banned" 'in_jail $VISITOR && [ -e $BANS/$VISITOR ]'
  check "they are refused on 443 through Cloudflare" '[ "$(on_443 $EDGE -H "$(cf $VISITOR)")" = 403 ]'
  check "and on the panel's own port through Cloudflare" '[ "$(on_port $EDGE -H "$(cf $VISITOR)")" = 403 ]'
  check "and through another Cloudflare address" '[ "$(on_443 $EDGE6 -H "$(cf $VISITOR)")" = 403 ]'
  check "the right password doesn't help" '[ "$(curl -sk -m 10 -o /dev/null -w "%{http_code}" --interface $EDGE --resolve "$PH:443:$EDGE" -H "$(cf $VISITOR)" -X POST -H "X-Requested-With: cloudpanel" -H "Content-Type: application/json" -d "{\"username\":\"admin\",\"password\":\"$PW\"}" https://$PH/api/auth/login)" = 403 ]'
  check "they get no pages either" '[ "$(curl -sk -m 10 -o /dev/null -w "%{http_code}" --interface $EDGE --resolve "$PH:443:$EDGE" -H "$(cf $VISITOR)" https://$PH/)" = 403 ]'
  check "the Cloudflare address itself isn't banned" '! in_jail $EDGE && [ ! -e $BANS/$EDGE ]'
  check "another visitor on that address carries on, on 443" '[ "$(on_443 $EDGE -H "$(cf 203.0.113.82)")" = 401 ]'
  check "and on the panel's own port" '[ "$(on_port $EDGE -H "$(cf 203.0.113.82)")" = 401 ]'
  check "hosted sites aren't part of it" '[ "$(curl -s -m 5 -o /dev/null -w "%{http_code}" --interface $OTHER -H "Host: pre.test.local" http://127.0.0.1/)" = 200 ]'

  # fail2ban ignores this machine's own addresses, which is what stands in for a client here.
  fail2ban-client set cloudpanel ignoreself false >/dev/null
  check "a client connecting directly isn't refused to begin with" '[ "$(on_port $OTHER)" = 401 ]'
  via_port $OTHER
  via_nginx $OTHER
  checkr "its failures get it banned" 'in_jail $OTHER && [ -e $BANS/$OTHER ]'
  check "it is refused on 443" '[ "$(on_443 $OTHER)" = 403 ]'
  check "and on the panel's own port" '[ "$(on_port $OTHER)" = 403 ]'
  check "a forged CF-Connecting-IP doesn't get it past 443" '[ "$(on_443 $OTHER -H "$(cf 203.0.113.83)")" = 403 ]'
  check "or past the panel's own port" '[ "$(on_port $OTHER -H "$(cf 203.0.113.83)")" = 403 ]'
  check "a forged X-Real-IP doesn't either" '[ "$(on_443 $OTHER -H "X-Real-IP: 203.0.113.83")" = 403 ] && [ "$(on_port $OTHER -H "X-Real-IP: 203.0.113.83")" = 403 ]'
  check "going through Cloudflare instead doesn't help on 443" '[ "$(on_443 $EDGE -H "$(cf $OTHER)")" = 403 ]'
  check "or on the panel's own port" '[ "$(on_port $EDGE -H "$(cf $OTHER)")" = 403 ]'
  check "and nobody gets refused by forging a banned address" '[ "$(curl -sk -m 10 -o /dev/null -w "%{http_code}" -H "CF-Connecting-IP: $OTHER" -H "X-Real-IP: $OTHER" https://127.0.0.1:8443/api/auth/me)" = 401 ]'

  V6=2001:db8::80
  for _ in 1 2 3; do via_port $EDGE -H "$(cf $V6)"; done
  checkr "an IPv6 visitor gets banned" 'in_jail $V6 && [ -e $BANS/$V6 ]'
  check "and refused on 443 through either family" '[ "$(on_443 $EDGE -H "$(cf $V6)")" = 403 ] && [ "$(on_443 $EDGE6 -H "$(cf $V6)")" = 403 ]'
  check "and on the panel's own port" '[ "$(on_port $EDGE -H "$(cf $V6)")" = 403 ]'

  echo "== A ban can't reach a Cloudflare address"
  : >$AUTH
  via_nginx $EDGE
  via_port $EDGE
  check "failures that name no visitor aren't blamed on the edge" '! logged $EDGE'
  check "the panel won't ban one when asked" '[ "$(api_ban $EDGE)" = 400 ]'
  fail2ban-client set cloudpanel banip $EDGE >/dev/null
  checkr "even if fail2ban is told to" '[ -e $BANS/$EDGE ]'
  check "its visitors aren't refused on 443" '[ "$(on_443 $EDGE -H "$(cf 203.0.113.84)")" = 401 ]'
  check "or on the panel's own port" '[ "$(on_port $EDGE -H "$(cf 203.0.113.84)")" = 401 ]'
  fail2ban-client set cloudpanel unbanip $EDGE >/dev/null
  check "no firewall rules came of any of this" '! { nft list ruleset 2>/dev/null; iptables-save 2>/dev/null; } | grep -q f2b-cloudpanel'

  echo "== Bans end, and last as long as they should"
  check "lifting a ban in the panel works" '[ "$(api_unban $VISITOR)" = 200 ]'
  checkr "straight away, on 443" '[ ! -e $BANS/$VISITOR ] && [ "$(on_443 $EDGE -H "$(cf $VISITOR)")" = 401 ]'
  check "and on the panel's own port" '[ "$(on_port $EDGE -H "$(cf $VISITOR)")" = 401 ]'
  # A jail's ban time also applies to the bans it already has, so nothing else is banned meanwhile.
  fail2ban-client set cloudpanel bantime 3 >/dev/null
  fail2ban-client set cloudpanel banip 203.0.113.86 >/dev/null
  checkr "a ban takes effect" '[ -e $BANS/203.0.113.86 ]'
  checkr "and runs out by itself" '[ ! -e $BANS/203.0.113.86 ] && [ "$(on_443 $EDGE -H "$(cf 203.0.113.86)")" = 401 ]'
  fail2ban-client set cloudpanel bantime 3600 >/dev/null
  check "a ban made in the panel counts straight away" '[ "$(api_ban 203.0.113.85)" = 200 ] && [ "$(on_443 $EDGE -H "$(cf 203.0.113.85)")" = 403 ]'

  fail2ban-client reload >/dev/null
  checkr "reloading fail2ban keeps bans" 'in_jail 203.0.113.85 && [ "$(on_443 $EDGE -H "$(cf 203.0.113.85)")" = 403 ]'
  touch $BANS/203.0.113.87
  systemctl restart fail2ban
  checkr "and so does restarting it" 'in_jail 203.0.113.85 && [ "$(on_443 $EDGE -H "$(cf 203.0.113.85)")" = 403 ]'
  check "which also clears anything that ended while it wasn't running" '[ ! -e $BANS/203.0.113.87 ]'
  check "turning the jail off lets everyone back" '[ "$(f2b_settings false 3)" = 200 ] && [ "$(on_443 $EDGE -H "$(cf 203.0.113.85)")" = 401 ] && [ -z "$(ls -A $BANS)" ]'
  check "turning it on again restores its bans" '[ "$(f2b_settings true 5)" = 200 ]'
  checkr "from where it left off" 'in_jail 203.0.113.85 && [ "$(on_443 $EDGE -H "$(cf 203.0.113.85)")" = 403 ]'

  echo "== A server whose clock isn't on UTC"
  mkdir -p /etc/systemd/system/fail2ban.service.d
  printf '[Service]\nEnvironment=TZ=Asia/Tokyo\n' >/etc/systemd/system/fail2ban.service.d/e2e-tz.conf
  systemctl daemon-reload
  systemctl restart fail2ban
  retry 'fail2ban-client status cloudpanel >/dev/null 2>&1'
  for _ in 1 2 3 4 5; do via_nginx $EDGE -H "$(cf 203.0.113.89)"; done
  checkr "failures still count east of UTC" 'in_jail 203.0.113.89 && [ "$(on_443 $EDGE -H "$(cf 203.0.113.89)")" = 403 ]'
  rm -f /etc/systemd/system/fail2ban.service.d/e2e-tz.conf
  rmdir /etc/systemd/system/fail2ban.service.d
  systemctl daemon-reload
  systemctl restart fail2ban
  retry 'fail2ban-client status cloudpanel >/dev/null 2>&1'

  echo "== Upgrading from a jail that used the firewall"
  sed -i 's/^action = cloudpanel$/port = 8443/' $JAIL
  rm -f /etc/fail2ban/action.d/cloudpanel.conf
  restart_panel
  checkr "starting the panel replaces it" 'grep -q "^action = cloudpanel$" $JAIL && [ -f /etc/fail2ban/action.d/cloudpanel.conf ]'
  checkr "with fail2ban using the new one" '[ -d $BANS ] && fail2ban-client status cloudpanel >/dev/null 2>&1 && fail2ban-client get cloudpanel actions | grep -qw cloudpanel'
  checkr "and bans still apply" 'in_jail 203.0.113.85 && [ "$(on_443 $EDGE -H "$(cf 203.0.113.85)")" = 403 ]'

  # 203.0.113.85 stays banned for the reboot, which after_reboot checks.
  for a in $OTHER $V6; do api_unban $a >/dev/null; done
  ip addr del $EDGE/32 dev lo
  ip addr del $OTHER/32 dev lo
  ip -6 addr del $EDGE6/128 dev lo
}

bans_after_reboot() {
  echo "== fail2ban bans after a reboot"
  local edge=173.245.48.1
  ip addr add $edge/32 dev lo
  visitor() { # address -> status of one failed login on 443, through Cloudflare
    curl -sk -m 10 -o /dev/null -w '%{http_code}' -X POST -H 'X-Requested-With: cloudpanel' -H 'Content-Type: application/json' \
      -d '{"username":"e2e-probe","password":"wrong"}' --interface $edge --resolve "panel.test.local:443:$edge" \
      -H "CF-Connecting-IP: $1" https://panel.test.local/api/auth/login
  }
  checkr "fail2ban came back with the ban" 'fail2ban-client status cloudpanel | grep -qw 203.0.113.85'
  checkr "so the client is still refused" '[ "$(visitor 203.0.113.85)" = 403 ]'
  check "and others aren't" '[ "$(visitor 203.0.113.88)" = 401 ]'
  ip addr del $edge/32 dev lo
}

after_reboot() {
  login
  id_of() { call GET /sites | j "[x['id'] for x in d if x['domain']=='$1'][0]"; }
  PRE=$(id_of pre.test.local)
  HAND=$(id_of hand.test.local)
  SRC=$(id_of src.test.local)
  echo "== After a reboot"
  checkr "PM2 app came back" '[ "$(host_code pre.test.local)" = 200 ]'
  checkr "panel sees it online" '[ "$(call GET /sites/$PRE | j "d[\"app\"][\"processes\"][0][\"status\"]")" = online ]'
  check "its environment came back" 'host_get pre.test.local | grep -q systemd-6'
  checkr "adopted app came back" 'host_get hand.test.local | grep -q hand-7'
  checkr "deployed app came back" '[ "$(host_code src.test.local)" = 200 ]'
  checkr "systemd app came back" '[ "$(host_code py.test.local)" = 200 ]'
  check "the panel came back" '[ "$(systemctl is-active cloudpanel)" = active ]'

  echo "== Disabling a site"
  call POST /sites/$PRE/state '{"active":false}' >/dev/null
  checkr "disabled site shows the maintenance page" '[ "$(host_code pre.test.local)" = 503 ]'
  checkr "disabling stops the daemon" '! pgrep -u pre-test -f "God Daemon" >/dev/null'
  call POST /sites/$PRE/state '{"active":true}' >/dev/null
  checkr "enabling brings it back" '[ "$(host_code pre.test.local)" = 200 ]'

  echo "== Backup and restore with PM2"
  s=$(run_job /sites/$SRC/backups)
  check "backup with a running daemon (status $s)" '[ "$s" = succeeded ] || { tail -20 /var/tmp/job.out; false; }'
  BK=$(call GET "/sites/$SRC/backups" | j 'd["backups"][0]["id"]')
  check "the backup is listed ($BK)" '[ -n "$BK" ]'
  echo changed-after-backup >/home/src-test/htdocs/src.test.local/after.txt
  s=$(run_job "/backups/$BK/restore")
  check "restore with a running daemon (status $s)" '[ "$s" = succeeded ] || { tail -20 /var/tmp/job.out; false; }'
  check "files really were restored" '[ ! -e /home/src-test/htdocs/src.test.local/after.txt ]'
  checkr "app answers after restore" '[ "$(host_code src.test.local)" = 200 ]'
  checkr "the restored daemon belongs to the unit" 'grep -q cloudpanel-app-src-test-local "/proc/$(cat /home/src-test/.pm2/pm2.pid)/cgroup"'
  check "old home was cleaned up" '! ls -d /home/.cloudpanel-old-* >/dev/null 2>&1'

  echo "== Deleting sites leaves nothing behind"
  check "delete PM2 site" 'call DELETE "/sites/$PRE?delete_files=true" | grep -q deleted'
  check "no daemon" '! pgrep -f "/home/pre-test/.pm2" >/dev/null'
  check "no unit" '[ ! -f /etc/systemd/system/cloudpanel-app-pre-test-local.service ]'
  check "no logrotate config" '[ ! -f /etc/logrotate.d/cloudpanel-pm2-pre-test-local ]'
  check "no root-only env file" '[ ! -f /etc/cloudpanel/apps/cloudpanel-app-pre-test-local.env ]'
  check "no user or home" '! id pre-test >/dev/null 2>&1 && [ ! -d /home/pre-test ]'
  check "nothing listens on its port" '[ "$(ss -ltnH "sport = :3101" | wc -l)" = 0 ]'

  # A hand-started daemon must not stop the user from being deleted.
  check "delete a site with a hand-started daemon" '
    systemctl stop cloudpanel-app-hand-test-local
    systemd-run --quiet --uid=hand-test --setenv=HOME=/home/hand-test --working-directory=/home/hand-test \
      --unit=e2e-hand2 --remain-after-exit /bin/sh -c "pm2 ping" >/dev/null 2>&1
    sleep 3
    call DELETE "/sites/$HAND?delete_files=true" | grep -q deleted && ! id hand-test >/dev/null 2>&1'
  systemctl stop e2e-hand2 2>/dev/null
  check "panel is still healthy" '[ "$(systemctl is-active cloudpanel)" = active ]'

  bans_after_reboot
  panel_port_after_reboot
  summary
}

# Sets up what run.sh then tries from a second container. Each case is a rule that would be
# listed as active while doing nothing if it landed in the wrong place. Rules made with ufw
# directly stand in for ones the panel doesn't know about, like the installer's.
firewall_rules() {
  login
  echo "== Firewall rules, for run.sh to try"
  local subnet
  subnet="$(hostname -i | cut -d' ' -f1 | cut -d. -f1-3).0/24"
  ufw default deny incoming >/dev/null
  ufw allow 22/tcp >/dev/null
  ufw allow 8443/tcp >/dev/null
  ufw --force enable >/dev/null
  for p in 19100 19205 19206 19300 19600 19700 19800 19900 19950 19960 20000 20100; do
    systemd-run --quiet --unit="e2e-http-$p" python3 -m http.server "$p" --bind 0.0.0.0
  done
  sleep 2
  rule() { # port protocol action [source]
    local r
    r=$(call POST /firewall/rules "{\"port\":\"$1\",\"protocol\":\"$2\",\"action\":\"$3\"${4:+,\"source\":\"$4\"}}")
    if echo "$r" | grep -q '"id"'; then ok "$3 $1/$2${4:+ from $4}"; else bad "$3 $1/$2${4:+ from $4}: $r"; fi
  }
  # run.sh lists the result it expects for each port.
  ufw allow 19100/tcp >/dev/null
  rule 19100 tcp deny                 # the exact rule, which ufw would otherwise keep
  ufw allow 19200:19210/tcp >/dev/null
  rule 19205 tcp deny                 # one port in an allowed range; 19206 stays open
  ufw allow 19300/tcp >/dev/null
  rule 19300 tcp deny "$subnet"       # a network, against an open port
  ufw allow 19600/tcp >/dev/null
  rule 19600 any deny                 # every protocol, against a TCP allow
  rule 19700 tcp deny
  rule 19700 tcp allow "$subnet"      # "except my office", added after the deny
  rule 19800 tcp allow "$subnet"
  rule 19800 tcp deny                 # "except my office", added before the deny
  ufw allow 19900/tcp >/dev/null
  rule 19900 tcp deny 203.0.113.0/24  # someone else's network leaves this one open
  ufw allow 19950/tcp >/dev/null      # the controls: allowed, and 19960 with no rule at all
  rule 20000 tcp allow
  rule 20000 tcp deny                 # replaces the panel's own allow
  rule 20100 tcp deny
  rule 20100 tcp allow                # and the other way round
  check "the panel lists only the rule that replaced the other" '[ "$(call GET /firewall/rules | j "\",\".join(r[\"action\"] for r in d if r[\"port\"]==20000)")" = deny ]'
  check "in both directions" '[ "$(call GET /firewall/rules | j "\",\".join(r[\"action\"] for r in d if r[\"port\"]==20100)")" = allow ]'
  ufw status numbered | head -30
  summary
}

summary() {
  echo
  echo "Passed $PASS, failed $FAIL"
  [ "$FAIL" = 0 ]
}

case "${1:-}" in
  before-reboot) before_reboot ;;
  after-reboot) after_reboot ;;
  firewall-rules) firewall_rules ;;
  *)
    echo "usage: $0 before-reboot|after-reboot"
    exit 2
    ;;
esac
