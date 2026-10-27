#!/usr/bin/env bash
# W11: the packaged systemd unit, installed and started by systemd, on a real host (CI runner or Omarchy).
#
#   sudo linux/tests/installed-unit.sh target/debug
#
# Installs moatd/moat-launch/moatctl into /usr/bin and linux/packaging/systemd/moatd.service into
# /etc/systemd/system, starts it with systemctl, applies a signed policy, and then checks, for a real non-root user:
#   * a protected workload writes its intended project under $HOME and a file in the real /tmp (D-SYSTEMD-WORKSPACE);
#   * containment probes still fail: denied egress, cgroup escape, a nested launch of a broader profile;
#   * the ordinary (unprotected) path still works (positive control).
# Everything it installs is removed on exit. Needs root, systemd as PID 1, nf_tables and cgroup v2.
set -euo pipefail
BIN_SRC=$(cd "${1:-target/debug}" && pwd)
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/../.." && pwd)
[[ "$(cat /proc/1/comm)" == "systemd" ]] || { echo "SKIP: systemd is not PID 1"; exit 0; }
PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
U=moatw11
WORK=$(mktemp -d /tmp/moat-w11.XXXX); chmod 755 "$WORK"

cleanup() {
  set +e
  systemctl stop moatd 2>/dev/null
  systemctl disable moatd 2>/dev/null
  rm -f /etc/systemd/system/moatd.service; systemctl daemon-reload
  nft delete table inet moat 2>/dev/null
  for d in /sys/fs/cgroup/moat.slice/p-*/s-*; do [[ -d "$d" ]] && echo 1 > "$d/cgroup.kill" 2>/dev/null; rmdir "$d" 2>/dev/null; done
  rmdir /sys/fs/cgroup/moat.slice/p-* /sys/fs/cgroup/moat.slice 2>/dev/null
  rm -rf /var/lib/moat /usr/bin/moatd /usr/bin/moat-launch /usr/bin/moatctl "$WORK"
  rm -f /tmp/moat-w11-*
  userdel -r "$U" 2>/dev/null
}
trap cleanup EXIT

# --- install exactly what the package installs ---------------------------------------------------------------------
install -m 755 "$BIN_SRC/moatd" "$BIN_SRC/moat-launch" "$BIN_SRC/moatctl" /usr/bin/
install -m 644 "$REPO/linux/packaging/systemd/moatd.service" /etc/systemd/system/moatd.service
id "$U" >/dev/null 2>&1 || useradd -m -s /bin/bash "$U"
H=$(getent passwd "$U" | cut -d: -f6)
runuser -u "$U" -- mkdir -p "$H/project"

# a public destination the runner can reach (positive control) and that the protected profile does not allow
DEST=$(getent ahostsv4 github.com | awk 'NR==1 {print $1}')
[[ -n "$DEST" ]] || { echo "FAIL: cannot resolve github.com for the probes"; exit 1; }
cat > "$WORK/w11.toml" <<EOF
schema = "moat.policy.v1"
name = "w11-installed"
fallback_profile = "ordinary"
[[profiles]]
id = "ordinary"
default = "observe"
learning = "observe"
[[profiles]]
id = "w11-coding"
description = "Protected coding task: no egress at all."
default = "deny"
learning = "restrictive"
[[profiles]]
id = "w11-open"
description = "A broader profile a contained task must not be able to start."
default = "deny"
learning = "restrictive"
[[rules]]
id = "w11-open-github"
action = "allow"
selector = { session = { profiles = ["w11-open"] } }
destinations = { cidrs = ["$DEST/32"] }
transport = "tcp"
ports = [443]
provenance = { kind = "git", reference = "w11" }
EOF
/usr/bin/moatctl keygen --out "$WORK/signer.key" >/dev/null
/usr/bin/moatd trust "$WORK/signer.key.pub" >/dev/null
/usr/bin/moatctl compile "$WORK/w11.toml" --adapter linux --revision 1 -o "$WORK/snap.json"
/usr/bin/moatctl sign "$WORK/snap.json" --key "$WORK/signer.key" -o "$WORK/signed.json"

systemctl daemon-reload
systemctl start moatd
for _ in $(seq 60); do [[ -S /run/moat/control.sock ]] && break; sleep 0.25; done
systemctl is-active --quiet moatd && ok "moatd.service started by systemd" || { bad "moatd.service started"; journalctl -u moatd --no-pager | tail -30; exit 1; }
/usr/bin/moatd apply "$WORK/signed.json" >/dev/null
status() { /usr/bin/moatd status; }
for _ in $(seq 60); do status 2>/dev/null | jq -e '.revision == 1 and .enforcement_active' >/dev/null && break; sleep 0.25; done
status | jq -e '.revision == 1 and .enforcement_active and .coverage == "protected-session"' >/dev/null \
  && ok "installed service enforces revision 1 (protected-session coverage)" || bad "installed enforcement ($(status | jq -c '{revision, enforcement_active, coverage, last_rejection}'))"
# the service really runs sandboxed (otherwise the workspace check below would prove nothing)
PID=$(systemctl show -p MainPID --value moatd)
[[ "$(readlink /proc/$PID/ns/mnt)" != "$(readlink /proc/1/ns/mnt)" ]] && ok "the daemon runs in systemd's private mount namespace (ProtectSystem/ProtectHome/PrivateTmp)" || bad "daemon not sandboxed"

as_user() { runuser -u "$U" -- env -i HOME="$H" PATH=/usr/bin:/bin bash -c "cd '$H/project' && $1"; }
launch() { # profile, command → exit code
  as_user "MOAT_QUIET=1 /usr/bin/moat-launch --profile $1 --no-pty -- bash -c '$2'" >/dev/null 2>&1 && echo 0 || echo $?
}
TAG=$RANDOM
# --- the workload can do its job ---------------------------------------------------------------------------------
R=$(launch w11-coding "echo edited-$TAG > src.txt && mkdir -p sub && echo more > sub/x && echo t > /tmp/moat-w11-$TAG")
[[ "$R" == "0" ]] && ok "protected workload ran under the installed unit" || bad "protected workload exit $R"
[[ "$(cat "$H/project/src.txt" 2>/dev/null)" == "edited-$TAG" && -f "$H/project/sub/x" ]] \
  && ok "W11: the workload wrote its intended project under \$HOME (not the service's read-only view)" || bad "W11: project write under \$HOME"
[[ -f "/tmp/moat-w11-$TAG" ]] && ok "W11: the workload's /tmp is the user's real /tmp, not the service's PrivateTmp" || bad "W11: /tmp is private to the service"
[[ "$(stat -c %U "$H/project/src.txt" 2>/dev/null)" == "$U" ]] && ok "files are owned by the user, not root" || bad "file owner"
# --- and is still contained ---------------------------------------------------------------------------------------
P="timeout 4 bash -c \"echo > /dev/tcp/$DEST/443\""
[[ "$(as_user "$P" >/dev/null 2>&1 && echo 0 || echo 1)" == "0" ]] && ok "positive control: the user reaches $DEST:443 without a session" || bad "positive control egress"
R=$(launch w11-coding "$P"); [[ "$R" != "0" && "$R" != "125" && "$R" != "126" ]] && ok "containment: egress denied inside w11-coding" || bad "containment egress (exit $R)"
R=$(launch w11-coding "echo \$\$ > /sys/fs/cgroup/cgroup.procs 2>/dev/null; $P"); [[ "$R" != "0" && "$R" != "125" && "$R" != "126" ]] && ok "containment: cgroup escape attempt fails and stays denied" || bad "containment escape (exit $R)"
R=$(launch w11-coding "MOAT_QUIET=1 /usr/bin/moat-launch --profile w11-open --no-pty -- $P; [ \$? -eq 126 ] && exit 7; exit 0")
[[ "$R" == "7" ]] && ok "containment: a nested launch of the broader w11-open profile is refused (W04, installed socket)" || bad "containment nested launch (exit $R)"
R=$(launch w11-open "$P"); [[ "$R" == "0" ]] && ok "w11-open itself reaches $DEST:443 from outside (the refusal above is about authority, not reachability)" || bad "w11-open allow (exit $R)"
# --- restart under systemd ---------------------------------------------------------------------------------------
systemctl restart moatd
for _ in $(seq 60); do status 2>/dev/null | jq -e '.revision == 1 and .enforcement_active' >/dev/null && break; sleep 0.25; done
status | jq -e '.revision == 1 and .enforcement_active and .activation.phase == "confirmed"' >/dev/null \
  && ok "systemctl restart: revision 1 restored from durable state" || bad "restart ($(status | jq -c '{revision, activation}'))"
R=$(launch w11-coding "$P"); [[ "$R" != "0" && "$R" != "125" && "$R" != "126" ]] && ok "containment after restart" || bad "containment after restart (exit $R)"

echo "----"
echo "installed unit: $PASS passed, $FAIL failed"
if [[ $FAIL -gt 0 ]]; then journalctl -u moatd --no-pager | tail -40; exit 1; fi
