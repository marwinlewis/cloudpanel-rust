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

before_reboot() {
  login
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
  summary
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
  MTIME=$(stat -c %Y $VHOST)
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

  echo "== Hostname conflicts and removal"
  check "a site can't take the panel's hostname" '[ "$(code POST /sites "{\"domain\":\"$PH\",\"site_type\":\"static\"}")" = 409 ]'
  check "the panel can't take a site's hostname" '[ "$(code POST /settings/panel-cert "{\"hostname\":\"src.test.local\",\"email\":\"e2e@example.com\",\"skip_dns_check\":true}")" = 409 ]'
  check "or the www of one" '[ "$(call GET /sites | j "[x for x in d if x[\"domain\"]==\"src.test.local\"][0][\"include_www\"]")" = True ] && [ "$(code POST /settings/panel-cert "{\"hostname\":\"www.src.test.local\",\"email\":\"e2e@example.com\",\"skip_dns_check\":true}")" = 409 ]'
  check "the panel reports its address" '[ "$(call GET /settings/panel-cert | j "d[\"url\"]")" = "https://$PH" ]'
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
  *)
    echo "usage: $0 before-reboot|after-reboot"
    exit 2
    ;;
esac
