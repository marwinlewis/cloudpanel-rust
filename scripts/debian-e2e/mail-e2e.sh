#!/usr/bin/env bash
# The checks behind run-mail.sh. Runs as root inside a container.
#   mail-e2e.sh installed      After install.sh --with-mail: services, users, ports, Postfix locked down
#   mail-e2e.sh send           Domain, key, forward and webhook; send over 587, 465 and the API;
#                              DKIM, delivery tracking, webhooks, refusals, forwarding with SRS
#   mail-e2e.sh reinstall      Running install.sh again keeps the service, keys and data
#   mail-e2e.sh uninstall      install.sh --uninstall removes the service
#   mail-e2e.sh not-installed  A server installed without --with-mail has none of it
#
# Mail "to the internet" goes to a local sink on 127.0.0.1:2525 (relayhost), which saves each
# message with its envelope in /var/tmp/sink.
set -u
PASS=0
FAIL=0
ok() { PASS=$((PASS + 1)); echo "  ok   $*"; }
bad() { FAIL=$((FAIL + 1)); echo "  FAIL $*"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
retry() { for _ in $(seq 1 60); do eval "$1" && return 0; sleep 0.5; done; return 1; }
finish() {
  echo "  -- $PASS passed, $FAIL failed"
  [ "$FAIL" = 0 ]
}
STATE=/var/tmp/mail-e2e
mkdir -p "$STATE"

listening() { ss -Hltn "sport = :$1" | grep -q .; }
listener_user() { ss -Hltnp "sport = :$1" | grep -o 'pid=[0-9]*' | head -1 | cut -d= -f2 | xargs -r ps -o user= -p; }

start_helpers() {
  mkdir -p /var/tmp/sink /var/tmp/hooks
  cat >/var/tmp/sink.py <<'EOF'
import os, socketserver, time
class H(socketserver.StreamRequestHandler):
    def handle(self):
        w = lambda s: (self.wfile.write((s + "\r\n").encode()), self.wfile.flush())
        w("220 sink ESMTP")
        frm, rcpts = None, []
        while True:
            line = self.rfile.readline()
            if not line:
                return
            cmd = line.decode(errors="replace").strip()
            up = cmd.upper()
            if up.startswith("EHLO") or up.startswith("HELO"):
                w("250 sink")
            elif up.startswith("MAIL FROM:"):
                frm, rcpts = cmd[10:].split()[0], []
                w("250 ok")
            elif up.startswith("RCPT TO:"):
                rcpts.append(cmd[8:].split()[0])
                w("250 ok")
            elif up == "DATA":
                w("354 go")
                data = b""
                while True:
                    l = self.rfile.readline()
                    if l in (b".\r\n", b".\n", b""):
                        break
                    data += l[1:] if l.startswith(b"..") else l
                name = "/var/tmp/sink/%d.eml" % time.time_ns()
                with open(name + ".tmp", "wb") as f:
                    f.write(("X-Sink-From: %s\r\nX-Sink-To: %s\r\n" % (frm, ",".join(rcpts))).encode() + data)
                os.rename(name + ".tmp", name)
                w("250 2.0.0 queued")
            elif up == "QUIT":
                w("221 bye")
                return
            else:
                w("250 ok")
socketserver.ThreadingTCPServer.allow_reuse_address = True
socketserver.ThreadingTCPServer(("127.0.0.1", 2525), H).serve_forever()
EOF
  cat >/var/tmp/hooks.py <<'EOF'
import http.server, json, time
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("content-length", 0))).decode()
        rec = {"headers": {k.lower(): v for k, v in self.headers.items()}, "body": body}
        open("/var/tmp/hooks/%d.json" % time.time_ns(), "w").write(json.dumps(rec))
        self.send_response(200)
        self.end_headers()
    def log_message(self, *a):
        pass
http.server.HTTPServer(("127.0.0.1", 9099), H).serve_forever()
EOF
  systemctl stop e2e-sink e2e-hooks >/dev/null 2>&1 || true
  systemd-run --quiet --unit=e2e-sink python3 /var/tmp/sink.py
  systemd-run --quiet --unit=e2e-hooks python3 /var/tmp/hooks.py
  retry 'listening 2525 && listening 9099' || bad "test helpers started"
}

installed() {
  echo "== Installed with --with-mail"
  check "cloudpanel-mail active and enabled" 'systemctl is-active --quiet cloudpanel-mail && systemctl is-enabled --quiet cloudpanel-mail'
  check "postfix and postsrsd active" 'systemctl is-active --quiet postfix && systemctl is-active --quiet postsrsd'
  check "service runs as cloudpanel-mail" '[ "$(ps -o user= -p "$(systemctl show -p MainPID --value cloudpanel-mail)")" = cloudpanel-mail ]'
  check "587 and 465 served by cloudpanel-mail" 'retry "listening 587 && listening 465" && [ "$(listener_user 587)" = cloudpanel-mail ]'
  check "port 25 served by Postfix" 'listening 25 && [ "$(listener_user 25)" = root ]'
  check "API on 127.0.0.1:2580 only" 'retry "curl -sf http://127.0.0.1:2580/health >/dev/null" && ! ss -Hltn "sport = :2580" | awk "{print \$4}" | grep -qv "^127\.0\.0\.1:"'
  check "API through nginx on the mail hostname" 'curl -sk --resolve mail.test:443:127.0.0.1 https://mail.test/health | grep -q "\"ok\":true"'
  check "database owned by the service, closed to others" '[ "$(stat -c "%U %a" /var/lib/cloudpanel-mail)" = "cloudpanel-mail 750" ] && [ "$(stat -c %U /var/lib/cloudpanel-mail/mail.db)" = cloudpanel-mail ]'
  check "TLS key readable only by the service" '[ "$(stat -c "%U %a" /var/lib/cloudpanel-mail/tls/key.pem)" = "cloudpanel-mail 600" ]'
  check "Postfix never relays" '[ "$(postconf -h smtpd_relay_restrictions)" = reject_unauth_destination ]'
  check "only root and the service may submit locally" '[ "$(postconf -h authorized_submit_users)" = "root, cloudpanel-mail" ]'
  check "SRS only on mail received on port 25" 'postconf -P | grep -q "^smtp/inet/cleanup_service_name = cleanup_srs" && [ -z "$(postconf -h sender_canonical_maps)" ]'
  check "CLOUDPANEL_MAIL=1 recorded" 'grep -q "^CLOUDPANEL_MAIL=1" /etc/cloudpanel/cloudpanel.env'
  check "mail-status runs" 'cloudpanel mail-status | grep "cloudpanel-mail.service  active" >/dev/null'
  finish
}

# python3 smtplib session: mode (starttls|ssl|plain) user password from rcpt [from-header]
smtp_send() {
  python3 - "$@" <<'EOF'
import smtplib, ssl, sys
mode, user, pw, frm, rcpt = sys.argv[1:6]
hdr_from = sys.argv[6] if len(sys.argv) > 6 else frm
ctx = ssl._create_unverified_context()
msg = "From: Tester <%s>\r\nTo: %s\r\nSubject: e2e %s\r\n\r\nHello from the %s test.\r\n" % (hdr_from, rcpt, mode, mode)
try:
    if mode == "ssl":
        s = smtplib.SMTP_SSL("127.0.0.1", 465, context=ctx, timeout=20)
    else:
        s = smtplib.SMTP("127.0.0.1", 587, timeout=20)
        if mode == "starttls":
            s.starttls(context=ctx)
    s.login(user, pw)
    s.sendmail(frm, [rcpt], msg)
    s.quit()
    print("SENT")
except smtplib.SMTPException as e:
    print("REFUSED", e)
EOF
}

sink_has() { grep -l -- "$1" /var/tmp/sink/*.eml 2>/dev/null | head -1; }

send() {
  echo "== Domains, keys and sending"
  start_helpers
  # Everything "outbound" goes to the sink; a container has no route to real mail servers.
  postconf -e 'relayhost = [127.0.0.1]:2525' && postfix reload >/dev/null 2>&1

  check "mail-domain-add prints the DKIM record" 'cloudpanel mail-domain-add --domain example.test >"$STATE/domain.out" && grep -q "cloudpanel._domainkey.example.test" "$STATE/domain.out"'
  check "an unverified domain can't send yet" '! cloudpanel mail-domain-verify --domain example.test >/dev/null 2>&1'
  check "mail-domain-verify --force" 'cloudpanel mail-domain-verify --domain example.test --force >/dev/null'
  cloudpanel mail-key-create --name e2e --domain example.test >"$STATE/key.out"
  KEY=$(grep -o 'cp_[A-Za-z0-9]*_[A-Za-z0-9]*' "$STATE/key.out" | head -1)
  check "mail-key-create prints the key and the Gmail settings" '[ -n "$KEY" ] && grep -q "Username     cloudpanel" "$STATE/key.out"'
  check "the key isn't stored in the clear" '! grep -qa "$KEY" /var/lib/cloudpanel-mail/mail.db'
  check "mail-forward-add" 'cloudpanel mail-forward-add --address me@example.test --to inbox@remote.test >/dev/null && grep -q "me@example.test inbox@remote.test" /etc/postfix/cloudpanel_virtual'
  cloudpanel mail-webhook-add --url http://127.0.0.1:9099/hook >"$STATE/hook.out"
  SECRET=$(grep -o 'whsec_[A-Za-z0-9+/=]*' "$STATE/hook.out" | head -1)
  check "mail-webhook-add prints a signing secret" '[ -n "$SECRET" ]'

  echo "== Sending"
  check "SMTP 587 with STARTTLS" '[ "$(smtp_send starttls cloudpanel "$KEY" me@example.test a@remote.test)" = SENT ]'
  check "SMTP 465 with TLS" '[ "$(smtp_send ssl cloudpanel "$KEY" me@example.test b@remote.test)" = SENT ]'
  check "HTTP API" 'curl -s -o "$STATE/api.json" -w "%{http_code}" -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
    -d "{\"from\":\"Acme <hi@example.test>\",\"to\":\"c@remote.test\",\"subject\":\"e2e api\",\"html\":\"<p>Hi</p>\",\"text\":\"Hi\"}" \
    http://127.0.0.1:2580/emails | grep -q 200'
  API_ID=$(python3 -c 'import json;print(json.load(open("/var/tmp/mail-e2e/api.json"))["id"])' 2>/dev/null)
  check "HTTP API through nginx" 'curl -sk --resolve mail.test:443:127.0.0.1 -H "Authorization: Bearer $KEY" -H "Content-Type: application/json" \
    -d "{\"from\":\"hi@example.test\",\"to\":[\"d@remote.test\"],\"subject\":\"e2e nginx\",\"text\":\"Hi\"}" https://mail.test/emails | grep -q "\"id\""'

  echo "== Refusals"
  check "AUTH without TLS is refused" 'smtp_send plain cloudpanel "$KEY" me@example.test x@remote.test | grep -q "^REFUSED"'
  check "a wrong key is refused" 'smtp_send starttls cloudpanel cp_aaaaaaaaaaaa_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb me@example.test x@remote.test | grep -q "^REFUSED"'
  check "another domain is refused (no open relay)" 'smtp_send starttls cloudpanel "$KEY" someone@gmail.com x@remote.test | grep -q "^REFUSED"'
  check "a forged From header is refused" 'smtp_send starttls cloudpanel "$KEY" me@example.test x@remote.test ceo@bank.test | grep -q "^REFUSED"'
  check "port 25 doesn't relay, even from localhost" 'python3 -c "
import smtplib,sys
s=smtplib.SMTP(\"127.0.0.1\",25,timeout=20); s.ehlo()
try:
    s.sendmail(\"x@outside.test\",[\"victim@elsewhere.test\"],\"Subject: x\r\n\r\nx\"); sys.exit(1)
except smtplib.SMTPRecipientsRefused: sys.exit(0)"'
  check "other local users can't use sendmail" '! printf "Subject: x\n\nx\n" | runuser -u nobody -- /usr/sbin/sendmail -i x@remote.test 2>/dev/null'

  echo "== Delivery"
  check "all four reached the sink" 'retry "[ \$(ls /var/tmp/sink/*.eml 2>/dev/null | wc -l) -ge 4 ]"'
  F=$(sink_has "Subject: e2e starttls")
  check "envelope sender kept (no SRS on sent mail)" '[ -n "$F" ] && grep -q "^X-Sink-From: <me@example.test>" "$F"'
  check "signed with DKIM" '[ -n "$F" ] && grep -q "^DKIM-Signature: v=1;" "$F"'
  P=$(grep -o 'p=[A-Za-z0-9+/=]*' "$STATE/domain.out" | head -1 | cut -c3-)
  for subj in "e2e starttls" "e2e ssl" "e2e api"; do
    f=$(sink_has "Subject: $subj")
    check "DKIM verifies with dkimpy ($subj)" '[ -n "$f" ] && python3 - "$f" "$P" <<EOF
import dkim, sys
raw = open(sys.argv[1], "rb").read()
raw = b"\r\n".join(l for l in raw.split(b"\r\n") if not l.startswith(b"X-Sink-"))
key = ("v=DKIM1; k=rsa; p=" + sys.argv[2]).encode()
sys.exit(0 if dkim.verify(raw, dnsfunc=lambda name, timeout=5: key) else 1)
EOF'
  done
  check "the API email shows as delivered" 'retry "cloudpanel mail-log --id $API_ID | head -1 | grep -q delivered"'
  check "GET /emails/{id} says delivered" '[ "$(curl -s -H "Authorization: Bearer $KEY" http://127.0.0.1:2580/emails/$API_ID | python3 -c "import json,sys;print(json.load(sys.stdin)[\"last_event\"])")" = delivered ]'
  check "mail-log lists the four" '[ "$(cloudpanel mail-log | wc -l)" -ge 4 ]'

  echo "== Webhooks"
  check "email.sent and email.delivered were posted" 'retry "grep -l email.delivered /var/tmp/hooks/*.json >/dev/null 2>&1" && grep -l email.sent /var/tmp/hooks/*.json >/dev/null'
  check "signatures verify with the secret (Svix scheme)" 'python3 - "$SECRET" <<EOF
import base64, glob, hashlib, hmac, json, sys
key = base64.b64decode(sys.argv[1].split("_", 1)[1])
files = glob.glob("/var/tmp/hooks/*.json")
for f in files:
    r = json.load(open(f)); h = r["headers"]
    want = base64.b64encode(hmac.new(key, ("%s.%s.%s" % (h["svix-id"], h["svix-timestamp"], r["body"])).encode(), hashlib.sha256).digest()).decode()
    assert h["svix-signature"] == "v1," + want, f
sys.exit(0 if files else 1)
EOF'

  echo "== Forwarding"
  python3 -c '
import smtplib
s = smtplib.SMTP("127.0.0.1", 25, timeout=20)
s.sendmail("bob@outside.test", ["me@example.test"], "From: bob@outside.test\r\nTo: me@example.test\r\nSubject: e2e inbound\r\n\r\nHi\r\n")
s.quit()'
  check "inbound mail forwarded to the Gmail-style inbox" 'retry "[ -n \"\$(sink_has \"Subject: e2e inbound\")\" ]" && grep -q "^X-Sink-To: <inbox@remote.test>" "$(sink_has "Subject: e2e inbound")"'
  check "forwarded with an SRS envelope sender" 'grep -q "^X-Sink-From: <SRS0[=+-]" "$(sink_has "Subject: e2e inbound")"'
  check "mail for unknown addresses is refused" 'python3 -c "
import smtplib,sys
s=smtplib.SMTP(\"127.0.0.1\",25,timeout=20)
try:
    s.sendmail(\"bob@outside.test\",[\"nobody@example.test\"],\"Subject: x\r\n\r\nx\"); sys.exit(1)
except smtplib.SMTPRecipientsRefused: sys.exit(0)"'
  echo "$KEY" >"$STATE/key"
  finish
}

reinstall() {
  echo "== Second install.sh run (no mail flags)"
  check "the service is still active" 'systemctl is-active --quiet cloudpanel-mail'
  check "the key still sends" '[ "$(smtp_send starttls cloudpanel "$(cat $STATE/key)" me@example.test e@remote.test)" = SENT ]'
  check "domains are kept" 'cloudpanel mail-domain-list | grep -q "example.test *verified"'
  finish
}

uninstall() {
  echo "== install.sh --uninstall"
  check "the unit is gone" '! systemctl cat cloudpanel-mail >/dev/null 2>&1'
  check "587 and 465 are closed" '! listening 587 && ! listening 465'
  check "the API site is gone" '[ ! -e /etc/nginx/sites-enabled/cloudpanel-mail.conf ]'
  check "the data is kept" '[ -f /var/lib/cloudpanel-mail/mail.db ]'
  finish
}

not_installed() {
  echo "== Installed without --with-mail (no terminal)"
  check "no cloudpanel-mail unit" '! systemctl cat cloudpanel-mail >/dev/null 2>&1'
  check "no postfix" '! command -v postfix >/dev/null'
  check "587, 465 and 25 closed" '! listening 587 && ! listening 465 && ! listening 25'
  check "CLOUDPANEL_MAIL=0 recorded" 'grep -q "^CLOUDPANEL_MAIL=0" /etc/cloudpanel/cloudpanel.env'
  check "mail commands explain how to install it" 'cloudpanel mail-domain-list 2>&1 | grep -q "mail-install --hostname"'
  finish
}

case "${1:-}" in
  installed) installed ;;
  send) send ;;
  reinstall) reinstall ;;
  uninstall) uninstall ;;
  not-installed) not_installed ;;
  *)
    echo "usage: $0 installed|send|reinstall|uninstall|not-installed"
    exit 2
    ;;
esac
