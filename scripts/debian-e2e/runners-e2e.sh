#!/usr/bin/env bash
# The checks behind run-runners.sh. Runs as root inside a container.
#   runners-e2e.sh installed      After install.sh --with-runners: the release and its libraries
#   runners-e2e.sh ssh            New sites get ~/.ssh, and existing sites get one at startup
#   runners-e2e.sh adopt          A runner installed by hand is found, adopted and sandboxed
#   runners-e2e.sh hook           Its deploy token deploys its own site, and nothing else
#   runners-e2e.sh after-reboot   The adopted runner comes back
#   runners-e2e.sh remove         Removing it here only stops it and deletes its files
#   runners-e2e.sh fresh          A server installed with --no-runners: install from the panel
#
# Registering with GitHub itself needs a real repository and token, so the runner here is a
# stand-in with the files config.sh leaves behind and a runsvc.sh that just waits.
set -u
API=https://127.0.0.1:8443/api
JAR=/var/tmp/cp.jar
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ok   $*"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL $*"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
retry() { for _ in $(seq 1 40); do eval "$1" && return 0; sleep 0.5; done; return 1; }
call() { # method path [json]
  local m=$1 p=$2 d=${3:-}
  if [ -n "$d" ]; then
    curl -sk -b $JAR -c $JAR -X "$m" -H 'X-Requested-With: cloudpanel' -H 'Content-Type: application/json' -d "$d" "$API$p"
  else
    curl -sk -b $JAR -c $JAR -X "$m" -H 'X-Requested-With: cloudpanel' "$API$p"
  fi
}
j() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }
login() {
  rm -f $JAR
  local pw
  pw=$(cat /var/lib/cloudpanel/initial_admin_password)
  call POST /auth/login "{\"username\":\"admin\",\"password\":\"$pw\"}" >/dev/null
  retry '[ "$(call GET /auth/me | j "d[\"username\"]" 2>/dev/null)" = admin ]' || bad "login"
}
job() { # job id -> final status; output in /var/tmp/job.out
  local id=$1 status=running
  for _ in $(seq 1 1800); do
    call GET "/jobs/$id" >/var/tmp/job.json
    status=$(j 'd["status"]' </var/tmp/job.json)
    [ "$status" != running ] && break
    sleep 1
  done
  j 'd["output"]' </var/tmp/job.json >/var/tmp/job.out
  echo "$status"
}
finish() {
  echo "  -- $PASS passed, $FAIL failed"
  [ "$FAIL" = 0 ]
}
DOMAIN=ci.test.local
site_id() { call GET /sites | j "[s['id'] for s in d if s['domain']=='$DOMAIN'][0]"; }
site_user() { call GET "/sites/$(site_id)" | j 'd["system_user"]'; }
unit_user() { ps -o user= -p "$(systemctl show -p MainPID --value "$1")" | tr -d ' '; }

installed() {
  echo "== Installed with --with-runners"
  check "release cached and readable by site users" 'ls /var/cache/cloudpanel/runners/actions-runner-linux-*.tar.gz >/dev/null 2>&1 && [ "$(stat -c %a /var/cache/cloudpanel/runners)" = 755 ] && [ "$(stat -c %a /var/cache/cloudpanel/runners/actions-runner-linux-*.tar.gz)" = 644 ]'
  check "ICU installed for the runner" 'ldconfig -p | grep -q libicu'
  check "choice saved in the env file" 'grep -q "^CLOUDPANEL_RUNNERS=1" /etc/cloudpanel/cloudpanel.env'
  login
  check "panel reports it installed" '[ "$(call GET /runners | j "d[\"installed\"]")" = True ]'
  finish
}

ssh() {
  echo "== ~/.ssh for site users"
  login
  call POST /sites "{\"domain\":\"$DOMAIN\",\"site_type\":\"python\",\"target_port\":3011,\"app_command\":\"python3 -m http.server \$PORT --bind 127.0.0.1\"}" >/dev/null
  local u
  u=$(site_user)
  check "new site has a private ~/.ssh" '[ "$(stat -c "%U %a" "/home/$u/.ssh")" = "$u 700" ]'
  rm -rf "/home/$u/.ssh"
  systemctl restart cloudpanel
  retry 'curl -sk -o /dev/null "$API/auth/me"' || true
  check "an existing site without one gets it at startup" 'retry "[ -d /home/$u/.ssh ]" && [ "$(stat -c "%U %a" "/home/$u/.ssh")" = "$u 700" ]'
  finish
}

adopt() {
  echo "== Adopting a runner installed by hand"
  login
  local u dir
  u=$(site_user)
  dir=/home/$u/actions-runner
  # What config.sh and svc.sh leave behind.
  runuser -u "$u" -- sh -c "mkdir -p $dir/bin && tar -xzf /var/cache/cloudpanel/runners/actions-runner-linux-*.tar.gz -C $dir"
  runuser -u "$u" -- sh -c "printf '\357\273\277{\"agentId\":1,\"agentName\":\"ci-hand\",\"poolId\":1,\"poolName\":\"Default\",\"gitHubUrl\":\"https://github.com/acme/app\",\"workFolder\":\"_work\"}' >$dir/.runner && echo '{}' >$dir/.credentials && printf '#!/bin/bash\nexec sleep infinity\n' >$dir/runsvc.sh && chmod +x $dir/runsvc.sh"
  cat >/etc/systemd/system/actions.runner.acme-app.ci-hand.service <<EOF
[Unit]
Description=GitHub Actions Runner (acme-app.ci-hand)
After=network.target
[Service]
ExecStart=$dir/runsvc.sh
User=$u
WorkingDirectory=$dir
KillMode=process
KillSignal=SIGTERM
TimeoutStopSec=5min
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable --now actions.runner.acme-app.ci-hand.service >/dev/null 2>&1
  # A runner root owns can't be adopted.
  mkdir -p /home/rootrunner/r && cp $dir/.runner $dir/.credentials $dir/runsvc.sh /home/rootrunner/r/

  call GET /runners/scan >/var/tmp/scan.json
  check "scan finds the hand-installed runner" 'j "[f[\"name\"] for f in d[\"runners\"] if f[\"dir\"]==\"$dir\"][0]" </var/tmp/scan.json | grep -qx ci-hand'
  check "linked to the site of its user" 'j "[f[\"site_domain\"] for f in d[\"runners\"] if f[\"dir\"]==\"$dir\"][0]" </var/tmp/scan.json | grep -qx $DOMAIN'
  check "the svc.sh unit is noticed" 'j "[f[\"unit\"] for f in d[\"runners\"] if f[\"dir\"]==\"$dir\"][0]" </var/tmp/scan.json | grep -qx actions.runner.acme-app.ci-hand'
  check "a root-owned runner is listed but refused" 'j "[f[\"problem\"] for f in d[\"runners\"] if f[\"dir\"]==\"/home/rootrunner/r\"][0]" </var/tmp/scan.json | grep -q root'
  check "adopting the root one is refused" '[ "$(curl -sk -o /dev/null -w "%{http_code}" -b $JAR -X POST -H "X-Requested-With: cloudpanel" -H "Content-Type: application/json" -d "{\"dir\":\"/home/rootrunner/r\"}" $API/runners/adopt)" = 400 ]'

  local id status
  id=$(call POST /runners/adopt "{\"dir\":\"$dir\"}" | j 'd["job_id"]')
  status=$(job "$id")
  check "adopt job succeeds" '[ "$status" = succeeded ] || { cat /var/tmp/job.out; false; }'
  check "old unit stopped and set aside" '! systemctl is-active --quiet actions.runner.acme-app.ci-hand && [ -f /etc/systemd/system/actions.runner.acme-app.ci-hand.service.cloudpanel-adopted ] && [ ! -f /etc/systemd/system/actions.runner.acme-app.ci-hand.service ]'
  check "panel unit active and enabled" 'retry "systemctl is-active --quiet cloudpanel-runner-1" && systemctl is-enabled --quiet cloudpanel-runner-1'
  check "runs as the site user" '[ "$(unit_user cloudpanel-runner-1)" = "$u" ]'
  check "sandboxed" 'prop() { systemctl show -p "$1" --value cloudpanel-runner-1; }; [ "$(prop NoNewPrivileges) $(prop ProtectSystem) $(prop ProtectHome)" = "yes strict tmpfs" ] || { systemctl show -p NoNewPrivileges,ProtectSystem,ProtectHome cloudpanel-runner-1; false; }'
  check "can't see other homes" '[ "$(nsenter -t "$(systemctl show -p MainPID --value cloudpanel-runner-1)" -m ls /home | tr "\n" " ")" = "$u " ]'
  check "env file is root-only" '[ "$(stat -c "%U %a" /etc/cloudpanel/runners/1.env)" = "root 600" ]'
  check "deploy token in the runner's environment" 'tr "\0" "\n" </proc/$(systemctl show -p MainPID --value cloudpanel-runner-1)/environ | grep -q "^CLOUDPANEL_DEPLOY_TOKEN=cpr_"'
  check "listed as adopted" '[ "$(call GET /runners | j "d[\"runners\"][0][\"adopted\"]")" = True ]'
  check "no longer offered for adoption" '! call GET /runners/scan | grep -q "\"$dir\""'
  finish
}

hook() {
  echo "== Deploy hook"
  login
  local u token url
  u=$(site_user)
  token=$(sed -n 's/^CLOUDPANEL_DEPLOY_TOKEN=//p' /etc/cloudpanel/runners/1.env)
  url=$(sed -n 's/^CLOUDPANEL_DEPLOY_URL=//p' /etc/cloudpanel/runners/1.env)
  hookcall() { runuser -u "$u" -- curl -sk -o /var/tmp/hook.json -w '%{http_code}' -X POST -H "Authorization: Bearer $1" -H 'Content-Type: application/json' -d "$2" "$url"; }
  check "a wrong token is refused" '[ "$(hookcall cpr_wrong "{}")" = 401 ]'
  check "a panel session is not a deploy token" '[ "$(hookcall "$(sed -n "s/.*cp_session\t//p" $JAR)" "{}")" = 401 ]'
  check "restart through the hook, as the site user" '[ "$(hookcall "$token" "{\"action\":\"restart\",\"wait\":true}")" = 200 ] || { cat /var/tmp/hook.json; false; }'
  check "the job was for the runner's site" '[ "$(call GET /jobs/$(j "d[\"job_id\"]" </var/tmp/hook.json) | j "d[\"target\"]")" = $DOMAIN ]'
  check "app came back" 'retry "systemctl is-active --quiet cloudpanel-app-ci-test-local"'
  sleep 4
  local id old=$token
  call POST /runners/1/deploy-token >/dev/null
  token=$(sed -n 's/^CLOUDPANEL_DEPLOY_TOKEN=//p' /etc/cloudpanel/runners/1.env)
  check "a new token replaces the old one" '[ "$token" != "$old" ] && [ "$(hookcall "$old" "{}")" = 401 ]'
  finish
}

after_reboot() {
  echo "== After a reboot"
  check "runner back as the site user" 'retry "systemctl is-active --quiet cloudpanel-runner-1" && [ "$(unit_user cloudpanel-runner-1)" = "$(login; site_user)" ]'
  check "old unit stayed off" '! systemctl is-active --quiet actions.runner.acme-app.ci-hand'
  finish
}

remove() {
  echo "== Removing it from this server only"
  login
  local u id status
  u=$(site_user)
  check "refused without a token or force" '[ "$(curl -sk -o /dev/null -w "%{http_code}" -b $JAR -X POST -H "X-Requested-With: cloudpanel" -H "Content-Type: application/json" -d "{}" $API/runners/1/remove)" = 400 ]'
  id=$(call POST /runners/1/remove '{"force":true}' | j 'd["job_id"]')
  status=$(job "$id")
  check "remove job succeeds" '[ "$status" = succeeded ] || { cat /var/tmp/job.out; false; }'
  check "unit and env file gone" '[ ! -f /etc/systemd/system/cloudpanel-runner-1.service ] && [ ! -f /etc/cloudpanel/runners/1.env ] && ! systemctl is-active --quiet cloudpanel-runner-1'
  check "its folder deleted" '[ ! -d /home/$u/actions-runner ]'
  check "no longer listed" '[ "$(call GET /runners | j "len(d[\"runners\"])")" = 0 ]'
  finish
}

fresh() {
  echo "== Installed with --no-runners"
  check "nothing downloaded" '! ls /var/cache/cloudpanel/runners/*.tar.gz >/dev/null 2>&1'
  check "choice saved in the env file" 'grep -q "^CLOUDPANEL_RUNNERS=0" /etc/cloudpanel/cloudpanel.env'
  login
  call GET /runners >/var/tmp/r.json
  check "panel offers to install" '[ "$(j "str(d[\"installed\"]) + \" \" + str(d[\"can_install\"])" </var/tmp/r.json)" = "False True" ] || { head -c 300 /var/tmp/r.json; echo; false; }'
  local id status
  id=$(call POST /runners/install | j 'd["job_id"]')
  status=$(job "$id")
  check "installing from the panel succeeds" '[ "$status" = succeeded ] || { tail -20 /var/tmp/job.out; false; }'
  check "release now cached" 'ls /var/cache/cloudpanel/runners/actions-runner-linux-*.tar.gz >/dev/null 2>&1'
  check "panel reports it installed" '[ "$(call GET /runners | j "d[\"installed\"]")" = True ]'
  finish
}

case "${1:-}" in
  installed) installed ;;
  ssh) ssh ;;
  adopt) adopt ;;
  hook) hook ;;
  after-reboot) after_reboot ;;
  remove) remove ;;
  fresh) fresh ;;
  *)
    echo "usage: $0 installed|ssh|adopt|hook|after-reboot|remove|fresh"
    exit 2
    ;;
esac
