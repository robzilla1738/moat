#!/usr/bin/env bash
# Capture the real Moat window in demo mode (toolbar, native sidebar and bento content included) for the docs.
#
#   macos/scripts/capture-screenshots.sh path/to/Moat.app out-dir
#
# Each shot launches the app with --demo, waits for it to report its window number, and captures exactly that
# window with `screencapture -l`. If the runner refuses screen capture, the app's own AppKit snapshot of the window
# (written with --snapshot; system chrome may render flat there) is kept as fallback-*.png and the script says so.
set -uo pipefail
APP="${1:?Moat.app}"; OUT="${2:?out dir}"
mkdir -p "$OUT"
BIN="$APP/Contents/MacOS/Moat"
[[ -x "$BIN" ]] || { echo "no executable at $BIN"; exit 1; }
shots=(
  "apps dark" "apps light" "activity dark" "activity light" "rules dark" "coverage light"
  "devices dark" "whatChanged light" "apps-isolated light" "menubar dark" "menubar light" "onboarding dark" "onboarding light" "localrule dark" "localrule light"
  "learning dark" "candidate light" "packs dark"
)
captured=0
for s in "${shots[@]}"; do
  read -r name appearance <<<"$s"
  args=(--demo --appearance "$appearance")
  case "$name" in
    apps-isolated) args+=(--screen apps --isolated) ;;
    *) args+=(--screen "$name") ;;
  esac
  wid="$OUT/.wid"; rm -f "$wid"
  "$BIN" "${args[@]}" --window-id-file "$wid" --snapshot "$OUT/fallback-$name-$appearance.png" >"$OUT/.log" 2>&1 &
  pid=$!
  for _ in $(seq 200); do [[ -s "$wid" ]] && break; sleep 0.1; done
  if [[ -s "$wid" ]]; then
    sleep 0.4
    # screencapture can block on a permission prompt; never wait more than 15 s for it.
    screencapture -x -o -l "$(cat "$wid")" "$OUT/macos-$name-$appearance.png" 2>"$OUT/.err" &
    sc=$!
    for _ in $(seq 150); do kill -0 "$sc" 2>/dev/null || break; sleep 0.1; done
    kill "$sc" 2>/dev/null
    if wait "$sc" && [[ -s "$OUT/macos-$name-$appearance.png" ]]; then
      echo "captured macos-$name-$appearance.png ($(sips -g pixelWidth -g pixelHeight "$OUT/macos-$name-$appearance.png" 2>/dev/null | awk '/pixel/{printf "%s ", $2}'))"
      captured=$((captured + 1))
    else
      echo "screencapture refused for $name-$appearance: $(cat "$OUT/.err" 2>/dev/null); keeping the AppKit fallback"
    fi
  else
    echo "app did not report a window for $name-$appearance (process alive: $(kill -0 "$pid" 2>/dev/null && echo yes || echo no))"; tail -5 "$OUT/.log"
  fi
  kill "$pid" 2>/dev/null
  for _ in $(seq 30); do kill -0 "$pid" 2>/dev/null || break; sleep 0.1; done
  kill -9 "$pid" 2>/dev/null; wait "$pid" 2>/dev/null
done
rm -f "$OUT/.wid" "$OUT/.err" "$OUT/.log"
echo "captured $captured of ${#shots[@]} window screenshots"
[[ $captured -gt 0 ]]
