#!/usr/bin/env bash
# Adversarial-but-benign harness. Real devices only; see README.md.
set -uo pipefail

if [[ -n "${CI:-}" ]]; then
  echo "refusing to run in CI: results from a CI machine are not device evidence" >&2; exit 3
fi
if [[ "${MOAT_DEVICE_PROOF:-}" != "1" ]]; then
  echo "set MOAT_DEVICE_PROOF=1 to confirm this is a real device run (see tests/adversarial/README.md)" >&2; exit 3
fi
: "${CANARY_HOST:?set CANARY_HOST}" "${CANARY_V4:?set CANARY_V4}" "${CANARY_V6:?set CANARY_V6}"

profile="coding-session"; out="adversarial-results.json"; redirect_url="${REDIRECT_URL:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile) profile="$2"; shift 2 ;;
    --out) out="$2"; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done

token="moat-canary-$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
os="$(uname -s)"
launch=()
if [[ "$os" == "Linux" ]]; then
  command -v moat-launch >/dev/null || { echo "moat-launch not found" >&2; exit 2; }
  launch=(moat-launch --profile "$profile" --)
fi

results=()
record() { # id expected outcome detail
  results+=("$(python3 -c 'import json,sys; print(json.dumps(dict(id=sys.argv[1],expected=sys.argv[2],outcome=sys.argv[3],detail=sys.argv[4][:400])))' "$1" "$2" "$3" "$4")")
  printf '%-18s expected=%-14s observed=%s\n' "$1" "$2" "$3"
}
probe() { # id expected cmd...
  local id="$1" expected="$2"; shift 2
  local outp; outp="$("${launch[@]}" "$@" 2>&1)"; local code=$?
  local outcome="blocked"
  [[ $code -eq 0 ]] && outcome="CONNECTED"
  [[ $code -eq 126 || $code -eq 125 ]] && outcome="launch-refused"
  record "$id" "$expected" "$outcome" "exit=$code $outp"
}

ua="moat-adversarial/$token"
c=(curl -sS -o /dev/null --max-time 8 -A "$ua")
probe direct-ip-v4 blocked "${c[@]}" --resolve "$CANARY_HOST:443:$CANARY_V4" "https://$CANARY_HOST/?t=$token&case=v4"
probe direct-ip-v6 blocked "${c[@]}" -6 --resolve "$CANARY_HOST:443:[$CANARY_V6]" "https://$CANARY_HOST/?t=$token&case=v6"
probe hostname blocked "${c[@]}" "https://$CANARY_HOST/?t=$token&case=host"
if command -v dig >/dev/null; then
  probe udp-dns-public blocked dig +time=3 +tries=1 @1.1.1.1 "$token.$CANARY_HOST"
else
  record udp-dns-public blocked skipped "dig not installed"
fi
probe doh blocked "${c[@]}" -H 'accept: application/dns-json' "https://cloudflare-dns.com/dns-query?name=$token.example&type=A"
if curl --help all 2>/dev/null | grep -q -- --http3; then
  probe quic blocked "${c[@]}" --http3-only "https://$CANARY_HOST/?t=$token&case=quic"
else
  record quic blocked skipped "curl lacks HTTP/3"
fi
probe fork-chain blocked sh -c "sh -c 'curl -sS -o /dev/null --max-time 8 -A $ua https://$CANARY_HOST/?t=$token\&case=fork'"
probe detached blocked sh -c "setsid sh -c 'sleep 2; curl -sS -o /dev/null --max-time 8 -A $ua https://$CANARY_HOST/?t=$token\&case=detached' >/dev/null 2>&1 & exit 0"

if [[ "$os" == "Linux" ]]; then
  # A socket connected BEFORE launch, passed as fd 3: the launcher must not let it cross (CLOEXEC).
  if exec 3<>"/dev/tcp/$CANARY_V4/80" 2>/dev/null; then
  probe preopened-socket not-inherited python3 - "$CANARY_V4" <<'PY'
import os, socket, sys
try:
    s = socket.socket(fileno=3)
    s.send(b"GET /?case=preopened HTTP/1.0\r\n\r\n")
    sys.exit(0)
except OSError as e:
    print("fd 3 unavailable:", e); sys.exit(1)
PY
  exec 3>&-
  else
    record preopened-socket not-inherited skipped "could not pre-open a TCP connection to CANARY_V4:80"
  fi
  if [[ -S /var/run/docker.sock ]]; then
    probe broker-docker hidden curl -sS --max-time 5 --unix-socket /var/run/docker.sock http://localhost/version
  else
    record broker-docker hidden skipped "no docker socket on this host"
  fi
fi
if [[ -n "$redirect_url" ]]; then
  probe redirect blocked "${c[@]}" -L "$redirect_url"
else
  record redirect blocked skipped "set REDIRECT_URL to an allowed URL that redirects to the canary"
fi

{
  printf '{"schema":"moat.adversarial.v1","token":"%s","host":"%s","os":"%s","kernel":"%s","profile":"%s","at":"%s","note":"device evidence for human review; check the canary log for the token","results":[' \
    "$token" "$(hostname)" "$os" "$(uname -r)" "$profile" "$(date -u +%FT%TZ)"
  (IFS=,; printf '%s' "${results[*]}")
  printf ']}\n'
} > "$out"
echo
echo "wrote $out. Now search the canary access log for: $token"
echo "Any request with that token is a bypass. On macOS, confirm each verdict in Moat > Activity."
