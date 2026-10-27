#!/usr/bin/env bash
# Moat local recovery drill (MASTER_ROADMAP §15.4, §17.2; W15). Procedure and scope: docs/recovery-drill.md.
#
#   release/recovery-drill.sh integrity <dir-with-release-assets>     # anyone, before installing
#   sudo release/recovery-drill.sh local <dir-with-moatd-and-moatctl> # root, nf_tables, cgroup v2, iproute2, jq
#
# `integrity` checks a downloaded release: SHA256SUMS, the keyless Sigstore bundle over SHA256SUMS and the GitHub
# build-provenance attestation of every asset, with negative controls (a tampered asset must fail). Set
# MOAT_DRILL_REQUIRE_SIGNATURES=1 to fail when cosign, gh or the bundle is missing (CI does for signed builds).
#
# `local` runs the Linux local recovery steps against real binaries in a throwaway network namespace pair, with the
# daemon running and stopped: emergency isolation, local disable/resume, trial auto-revert and local rollback, a
# corrupt activation journal, and state left by a newer version (the update-rollback case). Everything it creates is
# torn down on exit. It never touches the host's own network namespace or /var/lib/moat.
#
# Exit status: 0 when every step passed, 1 otherwise. What this script cannot exercise (installed packages on a real
# Omarchy device, the signed macOS extension, phone emergency controls, a 24-hour controller outage) is listed in
# docs/recovery-drill.md as device-only, with the manual steps.
set -euo pipefail
PASS=0; FAIL=0
ok()  { echo "PASS  $1"; PASS=$((PASS+1)); }
bad() { echo "FAIL  $1"; FAIL=$((FAIL+1)); }
finish() { echo "----"; echo "recovery drill ($1): $PASS passed, $FAIL failed"; [[ $FAIL -eq 0 ]]; }
REPO_SLUG=${MOAT_REPO:-robzilla1738/moat}
WORKFLOW_PATH=.github/workflows/release.yml

integrity() {
  local dir; dir=$(cd "$1" && pwd)
  local require=${MOAT_DRILL_REQUIRE_SIGNATURES:-0}
  [[ -f "$dir/SHA256SUMS" ]] || { bad "SHA256SUMS present in $dir"; finish integrity; return; }
  (cd "$dir" && sha256sum --strict -c SHA256SUMS >/dev/null) && ok "every asset matches SHA256SUMS" || bad "SHA256SUMS check"
  # No unlisted payloads: everything except the checksum file and signature bundles must be listed.
  local unlisted=""
  for f in "$dir"/*; do
    b=$(basename "$f")
    case "$b" in SHA256SUMS|*.sigstore.json) continue;; esac
    awk '{print $2}' "$dir/SHA256SUMS" | sed 's/^\*//' | grep -qxF "$b" || unlisted="$unlisted $b"
  done
  [[ -z "$unlisted" ]] && ok "no asset is missing from SHA256SUMS" || bad "assets not in SHA256SUMS:$unlisted"

  local scratch; scratch=$(mktemp -d)
  cp -a "$dir"/. "$scratch"/
  local victim; victim=$(awk 'NR==1{print $2}' "$dir/SHA256SUMS" | sed 's/^\*//')
  printf 'x' >> "$scratch/$victim"
  if (cd "$scratch" && sha256sum --strict -c SHA256SUMS >/dev/null 2>&1); then bad "negative control: a tampered $victim passed SHA256SUMS"; else ok "negative control: a tampered $victim fails SHA256SUMS"; fi

  local ident="^https://github\\.com/${REPO_SLUG//./\\.}/\\.github/workflows/release\\.yml@refs/(heads/main|tags/v[0-9].*)\$"
  if command -v cosign >/dev/null && [[ -f "$dir/SHA256SUMS.sigstore.json" ]]; then
    if cosign verify-blob --bundle "$dir/SHA256SUMS.sigstore.json" --certificate-identity-regexp "$ident" \
         --certificate-oidc-issuer https://token.actions.githubusercontent.com "$dir/SHA256SUMS" >/dev/null 2>&1; then
      ok "SHA256SUMS carries a keyless Sigstore signature from $WORKFLOW_PATH in $REPO_SLUG"
    else bad "cosign verify-blob SHA256SUMS"; fi
    printf '0000000000000000000000000000000000000000000000000000000000000000  forged\n' >> "$scratch/SHA256SUMS"
    if cosign verify-blob --bundle "$dir/SHA256SUMS.sigstore.json" --certificate-identity-regexp "$ident" \
         --certificate-oidc-issuer https://token.actions.githubusercontent.com "$scratch/SHA256SUMS" >/dev/null 2>&1; then
      bad "negative control: an edited SHA256SUMS verified"
    else ok "negative control: an edited SHA256SUMS fails the signature"; fi
    if cosign verify-blob --bundle "$dir/SHA256SUMS.sigstore.json" --certificate-identity-regexp '^https://github\.com/someone-else/' \
         --certificate-oidc-issuer https://token.actions.githubusercontent.com "$dir/SHA256SUMS" >/dev/null 2>&1; then
      bad "negative control: the signature verified for another signer identity"
    else ok "negative control: the signature does not verify for another signer identity"; fi
  elif [[ "$require" == "1" ]]; then bad "cosign and SHA256SUMS.sigstore.json are required"
  else echo "SKIP  Sigstore signature (cosign or bundle missing; unsigned build)"; fi

  if command -v gh >/dev/null && [[ "$require" == "1" || -n "${GH_TOKEN:-}" ]]; then
    local n=0 failed=""
    while read -r _ name; do
      name=${name#\*}
      if gh attestation verify "$dir/$name" --repo "$REPO_SLUG" --signer-workflow "$REPO_SLUG/$WORKFLOW_PATH" >/dev/null 2>&1; then n=$((n+1)); else failed="$failed $name"; fi
    done < "$dir/SHA256SUMS"
    [[ -z "$failed" ]] && ok "build-provenance attestation verifies for all $n assets" || bad "attestation verify failed for:$failed"
    if gh attestation verify "$scratch/$victim" --repo "$REPO_SLUG" --signer-workflow "$REPO_SLUG/$WORKFLOW_PATH" >/dev/null 2>&1; then
      bad "negative control: the tampered $victim has an attestation"
    else ok "negative control: the tampered $victim has no attestation"; fi
  elif [[ "$require" == "1" ]]; then bad "gh is required to verify attestations"
  else echo "SKIP  build-provenance attestations (gh or GH_TOKEN missing)"; fi
  rm -rf "$scratch"
  finish integrity
}

local_drill() {
  [[ $(id -u) -eq 0 ]] || { echo "local drill must run as root"; exit 1; }
  local src; src=$(cd "$1" && pwd)
  local here; here=$(cd "$(dirname "$0")/.." && pwd)
  if ! nft list tables >/dev/null 2>&1; then echo "SKIP: nf_tables is not usable on this kernel"; [[ "${REQUIRE_NFT:-0}" == "1" ]] && exit 1 || exit 0; fi
  [[ -f /sys/fs/cgroup/cgroup.controllers ]] || { echo "FAIL: cgroup v2 required"; exit 1; }
  WORK=$(mktemp -d /tmp/moat-drill.XXXX); chmod 755 "$WORK"
  S="$WORK/state"; SOCK="$WORK/ctl.sock"; BIN="$WORK/bin"; mkdir -p "$S" "$BIN"
  install -m 755 "$src/moatd" "$src/moatctl" "$BIN/"
  DAEMON_PID=""; SERVER_PID=""
  cleanup() {
    set +e
    [[ -n "$DAEMON_PID" ]] && kill "$DAEMON_PID" 2>/dev/null
    [[ -n "$SERVER_PID" ]] && kill "$SERVER_PID" 2>/dev/null
    sleep 0.3
    ip netns del moat-dr-a 2>/dev/null; ip netns del moat-dr-b 2>/dev/null
    rmdir /sys/fs/cgroup/moat.slice/p-* /sys/fs/cgroup/moat.slice 2>/dev/null
    if [[ $FAIL -gt 0 ]]; then echo "--- moatd log"; tail -n 60 "$WORK/moatd.log" 2>/dev/null; fi
    rm -rf "$WORK"
  }
  trap cleanup EXIT
  A() { nsenter --net=/run/netns/moat-dr-a "$@"; }
  ip netns add moat-dr-a; ip netns add moat-dr-b
  ip link add dra type veth peer name drb
  ip link set dra netns moat-dr-a; ip link set drb netns moat-dr-b
  ip -n moat-dr-a addr add 10.78.0.1/24 dev dra; ip -n moat-dr-b addr add 10.78.0.2/24 dev drb
  for ns in moat-dr-a moat-dr-b; do ip -n $ns link set lo up; done
  ip -n moat-dr-a link set dra up; ip -n moat-dr-b link set drb up
  ip netns exec moat-dr-b python3 -m http.server 8080 --bind 10.78.0.2 >/dev/null 2>&1 &
  SERVER_PID=$!
  reach() { A timeout 3 bash -c 'echo > /dev/tcp/10.78.0.2/8080' >/dev/null 2>&1 && echo open || echo blocked; }
  loop_ok() { A timeout 3 bash -c 'python3 -c "import socket;s=socket.socket();s.bind((\"127.0.0.1\",0));s.listen();c=socket.create_connection(s.getsockname());print(1)"' >/dev/null 2>&1 && echo open || echo blocked; }
  for _ in $(seq 50); do [[ $(reach) == open ]] && break; sleep 0.1; done

  start_daemon() {
    nsenter --net=/run/netns/moat-dr-a "$BIN/moatd" --state "$S" --socket "$SOCK" run --device-id drill --tick-secs 1 --no-egress-proxy >> "$WORK/moatd.log" 2>&1 &
    DAEMON_PID=$!
    for _ in $(seq 50); do [[ -S "$SOCK" ]] && break; sleep 0.1; done
  }
  stop_daemon() { # $1 = TERM (clean) or KILL (crash)
    [[ -n "$DAEMON_PID" ]] && kill -"${1:-TERM}" "$DAEMON_PID" 2>/dev/null; wait "$DAEMON_PID" 2>/dev/null || true; DAEMON_PID=""; rm -f "$SOCK"
  }
  status() { "$BIN/moatd" --socket "$SOCK" status; }
  wait_for() { for _ in $(seq 60); do status 2>/dev/null | jq -e "$1" >/dev/null 2>&1 && return 0; sleep 0.25; done; return 1; }
  table() { A nft list table inet "$1" >/dev/null 2>&1 && echo present || echo absent; }
  sign() { # policy revision [extra]
    "$BIN/moatctl" compile "$1" --adapter linux --revision "$2" -o "$WORK/snap$2.json"
    "$BIN/moatctl" sign "$WORK/snap$2.json" --key "$WORK/owner.key" -o "$WORK/signed$2.json"
  }
  LAB="$here/linux/tests/lab.toml"; BROKEN="$here/linux/tests/lab-broken.toml"

  echo "== 0. baseline: owner key trusted, revision 1 enforced"
  "$BIN/moatctl" keygen --out "$WORK/owner.key" >/dev/null
  "$BIN/moatd" --state "$S" trust "$WORK/owner.key.pub" >/dev/null
  sign "$LAB" 1
  start_daemon
  "$BIN/moatd" --state "$S" apply "$WORK/signed1.json" >/dev/null
  wait_for '.revision == 1 and .enforcement_active and .activation.phase == "confirmed"' && ok "revision 1 confirmed and enforced" || bad "baseline revision 1"
  [[ $(reach) == open ]] && ok "ordinary traffic reaches the peer (observe profile)" || bad "baseline reachability"

  echo "== 1. emergency isolation survives a daemon crash and restart; only clear-isolation reopens"
  A "$BIN/moatd" --state "$S" recover isolate >/dev/null
  [[ $(reach) == blocked ]] && ok "isolate: the peer is unreachable" || bad "isolate did not block"
  [[ $(loop_ok) == open ]] && ok "isolate: loopback still works" || bad "isolate broke loopback"
  stop_daemon KILL
  [[ $(table moat_local_emergency) == present && $(reach) == blocked ]] && ok "daemon killed: isolation stays in the kernel" || bad "isolation lost when the daemon died"
  "$BIN/moatd" --state "$S" recover status | jq -e '.recovery.isolation.active' >/dev/null && ok "recover status (daemon stopped, unprivileged read) reports isolation" || bad "recover status while stopped"
  start_daemon
  wait_for '.isolation_active and .coverage == "emergency-isolation"' && ok "restarted daemon reports emergency-isolation" || bad "isolation after restart ($(status | jq -c '{coverage,isolation_active}'))"
  sleep 2
  [[ $(reach) == blocked ]] && ok "restarted daemon keeps the device isolated" || bad "restart reopened the device"
  A "$BIN/moatd" --state "$S" recover clear-isolation >/dev/null
  wait_for '.isolation_active | not' || true
  [[ $(reach) == open ]] && ok "clear-isolation reopens ordinary traffic" || bad "clear-isolation"

  echo "== 2. local disable with the daemon stopped; resume re-enforces the last valid policy"
  stop_daemon TERM
  [[ $(table moat) == present ]] && ok "daemon stopped: the enforcement table stays (fail-closed, not removed on exit)" || bad "enforcement table vanished on a clean stop"
  A "$BIN/moatd" --state "$S" recover disable --reason "recovery drill" >/dev/null
  [[ $(table moat) == absent ]] && ok "disable removes the enforcement table with the daemon stopped" || bad "disable left the table"
  start_daemon
  wait_for '.enforcement_disabled_locally and (.enforcement_active | not)' && ok "restarted daemon honours the local disable" || bad "disable after restart ($(status | jq -c '{enforcement_active,enforcement_disabled_locally}'))"
  sleep 2
  [[ $(table moat) == absent ]] && ok "restarted daemon does not reinstall the table while disabled" || bad "table reinstalled while disabled"
  A "$BIN/moatd" --state "$S" recover resume >/dev/null
  wait_for '.enforcement_active and (.enforcement_disabled_locally | not) and .revision == 1' && ok "resume re-enforces revision 1" || bad "resume"
  [[ $(table moat) == present ]] && ok "resume reinstalls the enforcement table" || bad "table after resume"

  echo "== 3. a bad revision: unconfirmed trial reverts on its own; local rollback; no replay after revert"
  sign "$BROKEN" 2
  "$BIN/moatd" --state "$S" apply "$WORK/signed2.json" --trial-secs 5 >/dev/null
  wait_for '.revision == 2 and .trial.revision == 2 and .trial.fallback_revision == 1' && ok "revision 2 on a 5 s trial" || bad "trial 2 started"
  wait_for '.revision == 1 and .trial == null' && ok "unconfirmed trial reverted to revision 1 on its own" || bad "auto-revert"
  sign "$BROKEN" 3
  "$BIN/moatd" --state "$S" apply "$WORK/signed3.json" --trial-secs 300 >/dev/null
  wait_for '.revision == 3 and .trial.revision == 3' && ok "revision 3 on a 300 s trial" || bad "trial 3 started"
  A "$BIN/moatd" --state "$S" recover rollback >/dev/null
  wait_for '.revision == 1 and .trial == null' && ok "recover rollback returns to revision 1 now" || bad "local rollback"
  "$BIN/moatd" --state "$S" apply "$WORK/signed3.json" >/dev/null
  wait_for '.last_rejection != null and (.last_rejection | test("not newer|replay"))' && ok "the rolled-back revision 3 cannot be replayed" || bad "replay after rollback ($(status | jq -r .last_rejection))"
  status | jq -e '.activation.replay_high_water >= 3' >/dev/null && ok "replay high-water is not lowered by rollback" || bad "high-water lowered"
  if A "$BIN/moatd" --state "$S" recover confirm >/dev/null 2>&1; then bad "confirm with nothing on trial succeeded"; else ok "confirm with nothing on trial is refused"; fi

  echo "== 4. corrupt activation journal: recovery-required, last verified snapshot stays enforced"
  stop_daemon TERM
  printf '{"schema":' > "$S/activation.json"
  start_daemon
  wait_for '.coverage == "recovery-required" and .activation.phase == "recovery_required" and .revision == 1' && ok "corrupt journal: recovery-required, revision 1 still reported" || bad "corrupt journal ($(status | jq -c '{coverage, r: .revision, a: .activation.phase}'))"
  [[ $(table moat) == present ]] && ok "corrupt journal: the enforcement table is kept, not removed or weakened" || bad "table after corrupt journal"
  [[ -f "$S/activation.json.corrupt" ]] && ok "corrupt journal kept as activation.json.corrupt for diagnosis" || bad "corrupt copy"
  sign "$LAB" 4
  "$BIN/moatd" --state "$S" apply "$WORK/signed4.json" >/dev/null
  wait_for '.revision == 4 and .activation.phase == "confirmed" and .coverage != "recovery-required"' && ok "a new signed revision clears recovery-required" || bad "recovery by new revision"

  echo "== 5. update rollback: state left by a newer version is refused and kept byte for byte"
  stop_daemon TERM
  jq '.schema = "moatd.activation_journal.v2" | .migration = {"from":"v1","to":"v2","step":2,"of":3}' "$S/activation.json" > "$WORK/newer.json"
  cp "$WORK/newer.json" "$S/activation.json"
  start_daemon
  wait_for '.coverage == "recovery-required" and (.activation.detail | test("unknown schema")) and .revision == 4' && ok "older binary refuses the newer journal, keeps revision 4 enforced" || bad "newer-schema state ($(status | jq -c '{coverage, r: .revision, d: .activation.detail}'))"
  cmp -s "$WORK/newer.json" "$S/activation.json.corrupt" && ok "the newer state is preserved byte for byte (not reset)" || bad "newer state not preserved"
  "$BIN/moatd" --state "$S" apply "$WORK/signed4.json" >/dev/null
  wait_for '.last_rejection != null and (.last_rejection | test("not newer|replay"))' && ok "replay of revision 4 still refused during recovery" || bad "replay during recovery"
  sign "$LAB" 5
  "$BIN/moatd" --state "$S" apply "$WORK/signed5.json" >/dev/null
  wait_for '.revision == 5 and .activation.phase == "confirmed"' && ok "a newer signed revision restores a known state" || bad "recovery to revision 5"

  echo "== 6. a snapshot signed by an untrusted key is refused (owner-key loss is not bypassed)"
  "$BIN/moatctl" keygen --out "$WORK/stranger.key" >/dev/null
  "$BIN/moatctl" compile "$LAB" --adapter linux --revision 6 -o "$WORK/snap6.json"
  "$BIN/moatctl" sign "$WORK/snap6.json" --key "$WORK/stranger.key" -o "$WORK/signed6x.json"
  "$BIN/moatd" --state "$S" apply "$WORK/signed6x.json" >/dev/null
  wait_for '.revision == 5 and (.last_rejection // "" | test("unknown key"))' && ok "untrusted signer refused; revision 5 stays" || bad "untrusted signer ($(status | jq -c '{r: .revision, l: .last_rejection}'))"
  stop_daemon TERM
  finish local
}

case "${1:-}" in
  integrity) integrity "${2:?release asset directory}";;
  local) local_drill "${2:-target/debug}";;
  *) sed -n '2,20p' "$0"; exit 2;;
esac
