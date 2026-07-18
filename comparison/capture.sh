#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Reproduce the secure-terminal "hostile byte streams" comparison, headless.
## For each installed Debian terminal emulator it feeds two payloads and screen-
## shots the result WITH the window-manager titlebar visible, so the emulator and
## any title hijack are both legible:
##   Case A (random) : head -c 20000 /dev/urandom  -- genuine random data.
##   Case B (crafted): ./hostile-log.sh            -- an OSC-0 title hijack plus a
##                     stuck colour and a DEC line-drawing charset shift, none reset.
## secure-terminal (its real GUI, from ST_REPO) is captured the same way for a
## like-for-like shot. Output PNGs go to ./shots/.
##
## Needs: Xvfb, a window manager that draws titlebars (matchbox-window-manager),
## xdotool, ImageMagick (import), and whichever emulators you want to test. This
## installs NOTHING itself (supply-chain hygiene): install the emulators you want
## first. No root except an optional chmod to undo a hardened exec bit (see NOTE).
##
## Usage:
##   ST_REPO=/path/to/secure-terminal/checkout ./capture.sh
## Deterministic Case B; Case A is random by nature (that is the point).

set -o errexit
set -o nounset
set -o pipefail

here="$(dirname -- "$(readlink --canonicalize -- "$0")")"
out="${here}/shots"
mkdir --parents -- "${out}"

"${here}/hostile-log.sh" > "${here}/crafted.bin"
head --bytes=20000 /dev/urandom > "${here}/random.bin"

W=1000; H=620
export DISPLAY=":101"
runtime_dir="$(mktemp --directory)"
export XDG_RUNTIME_DIR="${runtime_dir}"

xvfb_pid=''; wm_pid=''
cleanup() {
   [ -z "${wm_pid}" ] || kill "${wm_pid}" 2>/dev/null || true
   [ -z "${xvfb_pid}" ] || kill "${xvfb_pid}" 2>/dev/null || true
   rm -rf -- "${runtime_dir}" 2>/dev/null || true
}
trap cleanup EXIT

Xvfb "${DISPLAY}" -screen 0 "${W}x${H}x24" >/dev/null 2>&1 &
xvfb_pid="$!"
sleep 2
matchbox-window-manager -use_titlebar yes >/dev/null 2>&1 &
wm_pid="$!"
sleep 1

## NOTE: on a hardened Kicksecure/Whonix system the permission-hardener may strip
## the exec bit from urxvt (historically setuid for utmp). Restore it for the test:
##   sudo chmod +x /usr/bin/urxvt

launch() {  ## $1=emulator  $2=command-string
   local e="$1" cmd="$2"
   case "$e" in
      xterm)          xterm -fa 'Monospace' -fs 11 -e bash -c "${cmd}" ;;
      urxvt)          urxvt -fn 'xft:Monospace:size=11' -e bash -c "${cmd}" ;;
      st)             st -f 'Monospace:size=11' -e bash -c "${cmd}" ;;
      konsole)        konsole --nofork -e bash -c "${cmd}" ;;
      xfce4-terminal) xfce4-terminal --disable-server -x bash -c "${cmd}" ;;
      mate-terminal)  mate-terminal --disable-factory -x bash -c "${cmd}" ;;
      lxterminal)     lxterminal -e "bash -c '${cmd}'" ;;
      qterminal)      qterminal -e "bash -c '${cmd}'" ;;
      alacritty)      alacritty -o 'font.size=11' -e bash -c "${cmd}" ;;
      kitty)          kitty -o 'font_size=11' bash -c "${cmd}" ;;
   esac
}

clear_windows() {
   local wid
   for wid in $(xdotool search --onlyvisible --name '.*' 2>/dev/null || true); do
      xdotool windowkill "${wid}" 2>/dev/null || true
   done
}

shoot() {  ## $1=emulator  $2=case  $3=payload-file
   local e="$1" case="$2" payload="$3"
   command -v "$e" >/dev/null 2>&1 || { printf 'skip %s (not installed)\n' "$e"; return; }
   launch "$e" "cat '${payload}'; sleep 20" >/dev/null 2>&1 &
   local epid="$!" i
   for i in $(seq 1 60); do
      xdotool search --onlyvisible --name '.*' >/dev/null 2>&1 && break
      sleep 0.25
   done
   sleep 3
   import -window root "${out}/${e}.${case}.png" 2>/dev/null || true
   clear_windows
   kill "${epid}" 2>/dev/null || true
   sleep 1.5
}

for e in xterm urxvt st konsole xfce4-terminal mate-terminal lxterminal qterminal alacritty kitty; do
   shoot "$e" crafted "${here}/crafted.bin"
   shoot "$e" random  "${here}/random.bin"
   printf 'captured %s\n' "$e"
done

st_bin="${ST_REPO:-}/usr/bin/secure-terminal"
st_pkg="${ST_REPO:-}/usr/lib/python3/dist-packages"
if [ -n "${ST_REPO:-}" ] && [ -f "${st_bin}" ]; then
   for case in crafted random; do
      PYTHONPATH="${st_pkg}" python3 "${st_bin}" --new-instance --mode strip \
         -- bash -c "cat '${here}/${case}.bin'; sleep 30" >/dev/null 2>&1 &
      epid="$!"
      for i in $(seq 1 60); do
         xdotool search --onlyvisible --name '.*[Ss]ecure.*' >/dev/null 2>&1 && break
         sleep 0.25
      done
      sleep 3
      import -window root "${out}/secure-terminal.${case}.png" 2>/dev/null || true
      clear_windows
      kill "${epid}" 2>/dev/null || true
      sleep 1.5
   done
   printf 'captured secure-terminal (real GUI)\n'
else
   printf 'skip secure-terminal (set ST_REPO=/path/to/checkout to include it)\n'
fi

printf 'done; shots in %s\n' "${out}"
