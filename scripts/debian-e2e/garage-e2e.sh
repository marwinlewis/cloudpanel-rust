#!/usr/bin/env bash
# The checks behind run-garage.sh. Runs as root inside a container.
#   garage-e2e.sh installed       After install.sh --with-garage: Garage runs, locked down
#   garage-e2e.sh manage          Buckets, keys and grants through the panel, used over real S3
#   garage-e2e.sh after-reboot    Garage and the stored objects come back
#   garage-e2e.sh reinstall       Installing again keeps secrets and data
#   garage-e2e.sh uninstall       install.sh --uninstall removes the service, keeps the data
#   garage-e2e.sh fresh           A server installed without Garage: install it from the panel
set -u
API=https://127.0.0.1:8443/api
S3=http://127.0.0.1:3900
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
code() { # method path [json] -> HTTP status, body in /var/tmp/body
  local m=$1 p=$2 d=${3:-}
  curl -sk -o /var/tmp/body -w '%{http_code}' -b $JAR -c $JAR -X "$m" -H 'X-Requested-With: cloudpanel' \
    -H 'Content-Type: application/json' ${d:+-d "$d"} "$API$p"
}
j() { python3 -c "import sys,json;d=json.load(sys.stdin);print($1)"; }
login() {
  rm -f $JAR
  local pw
  pw=$(cat /var/lib/cloudpanel/initial_admin_password)
  call POST /auth/login "{\"username\":\"admin\",\"password\":\"$pw\"}" >/dev/null
  retry '[ "$(call GET /auth/me | j "d[\"username\"]" 2>/dev/null)" = admin ]' || bad "login"
}
run_job() { # path -> status; output in /var/tmp/job.out
  local r id status=running
  r=$(call POST "$1")
  id=$(echo "$r" | j 'd["job_id"]') || { echo "no job: $r" >/var/tmp/job.out; echo failed; return; }
  for _ in $(seq 1 900); do
    call GET "/jobs/$id" >/var/tmp/job.json
    status=$(j 'd["status"]' </var/tmp/job.json)
    [ "$status" != running ] && break
    sleep 1
  done
  j 'd["output"]' </var/tmp/job.json >/var/tmp/job.out
  echo "$status"
}
# S3 over plain curl, signed with AWS Signature V4: what any SDK would send.
s3() { # method key-id secret path [file] -> HTTP status, body in /var/tmp/s3body
  local m=$1 id=$2 secret=$3 p=$4 f=${5:-}
  curl -s -o /var/tmp/s3body -w '%{http_code}' --aws-sigv4 'aws:amz:us-east-1:s3' --user "$id:$secret" \
    -X "$m" ${f:+-T "$f"} "$S3$p"
}
finish() {
  echo "  -- $PASS passed, $FAIL failed"
  [ "$FAIL" = 0 ]
}
listening_only_on_loopback() {
  local port
  for port in 3900 3901 3903; do
    ss -Hltn "sport = :$port" | grep -q . || return 1
    ss -Hltn "sport = :$port" | awk '{print $4}' | grep -qv '^127\.0\.0\.1:' && return 1
  done
  return 0
}

installed() {
  echo "== Installed with --with-garage"
  check "garage.service active and enabled" 'systemctl is-active --quiet garage && systemctl is-enabled --quiet garage'
  check "runs as the garage user" '[ "$(ps -o user= -p "$(systemctl show -p MainPID --value garage)")" = garage ]'
  check "single-node server" 'systemctl show -p ExecStart --value garage | grep -q -- "--single-node"'
  check "every port on 127.0.0.1 only" 'listening_only_on_loopback'
  check "secrets are root:garage 0640" '[ "$(stat -c "%U:%G %a" /etc/garage/admin.token /etc/garage/rpc.secret | sort -u)" = "root:garage 640" ]'
  check "data owned by garage, closed to others" '[ "$(stat -c "%U %a" /var/lib/garage)" = "garage 750" ]'
  check "choice recorded" 'grep -qx "CLOUDPANEL_GARAGE=1" /etc/cloudpanel/cloudpanel.env'
  check "binary matches the pinned release" '/usr/local/bin/garage --version 2>&1 | grep -q "v2.5.0"'
  check "S3 API refuses unsigned requests" '[ "$(curl -s -o /dev/null -w "%{http_code}" $S3/)" = 403 ]'
  check "admin API refuses requests without the token" '[ "$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3903/v2/ListBuckets)" = 403 ]'
  login
  call GET /storage >/var/tmp/st.json
  check "panel sees it running and healthy" '[ "$(j "d[\"running\"], d[\"health\"][\"status\"], d[\"version\"]" </var/tmp/st.json)" = "True healthy v2.5.0" ]' || head -c 600 /var/tmp/st.json
  check "listed on the Services page" 'call GET /services | grep -q "\"name\":\"garage\""'
  finish
}

manage() {
  echo "== Buckets, keys and grants, used over S3"
  login
  check "bucket created" '[ "$(code POST /storage/buckets "{\"name\":\"media\",\"max_size_mb\":5}")" = 201 ]' || cat /var/tmp/body
  local bid; bid=$(j 'd["id"]' </var/tmp/body)
  check "second bucket created" '[ "$(code POST /storage/buckets "{\"name\":\"private\"}")" = 201 ]'
  local pid; pid=$(j 'd["id"]' </var/tmp/body)
  check "invalid name refused" '[ "$(code POST /storage/buckets "{\"name\":\"Bad_Name\"}")" = 400 ]'
  check "key created with its secret" '[ "$(code POST /storage/keys "{\"name\":\"app\"}")" = 201 ]'
  local kid id secret
  kid=$(j 'd["id"]' </var/tmp/body)
  id=$(j 'd["access_key_id"]' </var/tmp/body)
  secret=$(j 'd["secret_access_key"]' </var/tmp/body)
  echo "$id $secret" >/var/tmp/key
  check "a new key can do nothing" '[ "$(s3 GET "$id" "$secret" /media/)" = 403 ]'
  check "read+write granted" '[ "$(code PUT "/storage/buckets/$bid/keys/$kid" "{\"read\":true,\"write\":true}")" = 200 ]' || cat /var/tmp/body

  head -c 200000 /dev/urandom >/var/tmp/obj
  check "upload" '[ "$(s3 PUT "$id" "$secret" /media/dir/obj.bin /var/tmp/obj)" = 200 ]' || cat /var/tmp/s3body
  check "download is identical" '[ "$(s3 GET "$id" "$secret" /media/dir/obj.bin)" = 200 ] && cmp -s /var/tmp/s3body /var/tmp/obj'
  check "list shows it" '[ "$(s3 GET "$id" "$secret" "/media?list-type=2")" = 200 ] && grep -q "dir/obj.bin" /var/tmp/s3body'
  check "range read" '[ "$(curl -s -o /var/tmp/s3body -w "%{http_code}" --aws-sigv4 aws:amz:us-east-1:s3 --user "$id:$secret" -H "Range: bytes=0-99" $S3/media/dir/obj.bin)" = 206 ] && [ "$(stat -c %s /var/tmp/s3body)" = 100 ]'
  check "no access to the other bucket" '[ "$(s3 GET "$id" "$secret" /private/)" = 403 ]'
  check "wrong secret refused" '[ "$(s3 GET "$id" "not-the-secret" /media/dir/obj.bin)" = 403 ]'
  check "keys can't create buckets" '[ "$(s3 PUT "$id" "$secret" /made-by-app)" = 403 ]'
  head -c 6000000 /dev/urandom >/var/tmp/big
  check "quota refuses going over 5 MB" '[ "$(s3 PUT "$id" "$secret" /media/big.bin /var/tmp/big)" != 200 ]'

  call GET /storage >/var/tmp/st.json
  check "panel shows usage and the grant" '[ "$(j "[b for b in d[\"buckets\"] if b[\"name\"]==\"media\"][0][\"objects\"], [b for b in d[\"buckets\"] if b[\"name\"]==\"media\"][0][\"grants\"][0][\"permissions\"]" </var/tmp/st.json)" = "1 {'"'"'read'"'"': True, '"'"'write'"'"': True, '"'"'owner'"'"': False}" ]' || head -c 800 /var/tmp/st.json
  check "the secret is not in the panel's answer" '! grep -q "$secret" /var/tmp/st.json'
  check "the secret is not in the panel's database" '! grep -aq "$secret" /var/lib/cloudpanel/cloudpanel.db*'
  check "a bucket with objects is not deleted" '[ "$(code DELETE "/storage/buckets/$bid")" = 409 ]'

  check "read-only now" '[ "$(code PUT "/storage/buckets/$bid/keys/$kid" "{\"read\":true}")" = 200 ]'
  check "writes refused after lowering the grant" '[ "$(s3 PUT "$id" "$secret" /media/other.bin /var/tmp/obj)" = 403 ]'
  check "reads still work" '[ "$(s3 GET "$id" "$secret" /media/dir/obj.bin)" = 200 ]'
  check "read+write again" '[ "$(code PUT "/storage/buckets/$bid/keys/$kid" "{\"read\":true,\"write\":true}")" = 200 ]'

  # The panel's own backups can go to it too (on a real server, use storage elsewhere).
  check "backup remote accepts Garage" '[ "$(code PUT /backups/remote "{\"endpoint\":\"$S3\",\"region\":\"us-east-1\",\"bucket\":\"media\",\"access_key\":\"$id\",\"secret_key\":\"$secret\",\"prefix\":\"panel\",\"path_style\":true}")" = 200 ]' || cat /var/tmp/body
  check "empty bucket deleted" '[ "$(code DELETE "/storage/buckets/$pid")" = 200 ]'
  check "audit log has the changes" 'call GET "/events?limit=200" | grep -q "storage.grant"'
  finish
}

after_reboot() {
  echo "== After a reboot"
  local id secret
  read -r id secret </var/tmp/key
  check "garage.service came back" 'retry "systemctl is-active --quiet garage"'
  check "object still there" 'retry "[ \"\$(s3 GET $id $secret /media/dir/obj.bin)\" = 200 ]" && cmp -s /var/tmp/s3body /var/tmp/obj'
  login
  check "panel sees it healthy" '[ "$(call GET /storage | j "d[\"health\"][\"status\"]")" = healthy ]'
  finish
}

reinstall() {
  echo "== Installing again"
  local before; before=$(sha256sum /etc/garage/admin.token /etc/garage/rpc.secret /etc/garage/garage.toml)
  check "garage-install runs again" '/usr/local/bin/cloudpanel garage-install >/var/tmp/reinstall.log 2>&1' || tail -20 /var/tmp/reinstall.log
  check "says it is already installed" 'grep -q "already installed" /var/tmp/reinstall.log'
  check "secrets and config kept" '[ "$(sha256sum /etc/garage/admin.token /etc/garage/rpc.secret /etc/garage/garage.toml)" = "$before" ]'
  local id secret
  read -r id secret </var/tmp/key
  check "old key still works" '[ "$(s3 GET "$id" "$secret" /media/dir/obj.bin)" = 200 ]'
  finish
}

uninstall() {
  echo "== install.sh --uninstall"
  bash /var/tmp/install.sh --uninstall >/var/tmp/uninstall.log 2>&1
  check "service and binary removed" '! systemctl cat garage >/dev/null 2>&1 && [ ! -e /usr/local/bin/garage ]'
  check "data and config left in place" '[ -d /var/lib/garage/data ] && [ -f /etc/garage/garage.toml ]'
  check "says so" 'grep -q "/var/lib/garage" /var/tmp/uninstall.log'
  check "nothing listens on 3900 any more" '! ss -Hltn "sport = :3900" | grep -q .'
  finish
}

fresh() {
  echo "== A server installed without Garage"
  check "installer did not install it without a yes" '[ ! -e /usr/local/bin/garage ] && grep -qx "CLOUDPANEL_GARAGE=0" /etc/cloudpanel/cloudpanel.env'
  login
  call GET /storage >/var/tmp/st.json
  check "panel says not installed, can install" '[ "$(j "d[\"installed\"], d[\"can_install\"]" </var/tmp/st.json)" = "False True" ]'
  check "creating a bucket first is refused" '[ "$(code POST /storage/buckets "{\"name\":\"media\"}")" = 400 ]'
  local s
  s=$(run_job /storage/install)
  check "install job succeeded" '[ "$s" = succeeded ]' || tail -20 /var/tmp/job.out
  check "checksum was verified" 'grep -q "Checksum verified" /var/tmp/job.out'
  check "garage.service active" 'systemctl is-active --quiet garage'
  check "every port on 127.0.0.1 only" 'listening_only_on_loopback'
  check "bucket created" '[ "$(code POST /storage/buckets "{\"name\":\"media\"}")" = 201 ]' || cat /var/tmp/body
  finish
}

case "${1:-}" in
  installed) installed ;;
  manage) manage ;;
  after-reboot) after_reboot ;;
  reinstall) reinstall ;;
  uninstall) uninstall ;;
  fresh) fresh ;;
  *)
    echo "usage: $0 installed|manage|after-reboot|reinstall|uninstall|fresh"
    exit 2
    ;;
esac
