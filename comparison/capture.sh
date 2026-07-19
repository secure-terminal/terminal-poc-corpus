#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Reproduce the secure-terminal "hostile byte streams" comparison, headless.
## For each installed Debian terminal emulator it feeds two payloads and screen-
## shots the DECORATED window (title bar included, no desktop background), so the
## emulator and any title hijack are both legible:
##   Case A (random) : head -c 20000 /dev/urandom  -- genuine random data.
##   Case B (crafted): ./hostile-script.sh            -- an OSC-0 title hijack plus a
##                     stuck colour and a DEC line-drawing charset shift, none reset.
## secure-terminal (its real GUI, from ST_REPO) is captured the same way for a
## like-for-like shot. Output PNGs go to ./shots/.
##
## Needs: Xvfb, a window manager that draws title bars (openbox), xdotool,
## ImageMagick (import), and whichever emulators you want to test. This installs
## NOTHING itself (supply-chain hygiene): install the emulators you want first.
## No root except an optional chmod to undo a hardened exec bit (see NOTE).
##
## Usage:
##   ST_REPO=/path/to/secure-terminal/checkout ./capture.sh
## Deterministic Case B; Case A is random by nature (that is the point).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

here="$(dirname -- "$(readlink --canonicalize -- "$0")")"
out="${here}/shots"
mkdir --parents -- "${out}"

## pick a free display number so a stale Xvfb from an earlier run cannot leave a
## half-managed server that fails to decorate windows.
display_num=101
while [ -e "/tmp/.X11-unix/X${display_num}" ] && [ "${display_num}" -lt 160 ]; do
   display_num=$(( display_num + 1 ))
done
export DISPLAY=":${display_num}"
runtime_dir="$(mktemp --directory)"
export XDG_RUNTIME_DIR="${runtime_dir}"
## a clean HOME / config so an emulator's saved profile (e.g. Alacritty's
## dynamic-title setting, themes, geometry) cannot change the result -- the
## capture depends only on defaults, keeping it repeatable.
export HOME="${runtime_dir}/home"
export XDG_CONFIG_HOME="${runtime_dir}/config"
mkdir --parents -- "${HOME}" "${XDG_CONFIG_HOME}"

## write the payloads under the space-free runtime dir (a repo checkout path may
## contain spaces, which would break the nested command strings below).
"${here}/hostile-script.sh" > "${runtime_dir}/crafted.bin"
head --bytes=20000 -- /dev/urandom > "${runtime_dir}/random.bin"

xvfb_pid=''; wm_pid=''
cleanup() {
   [ -z "${wm_pid}" ] || kill "${wm_pid}" 2>/dev/null || true
   [ -z "${xvfb_pid}" ] || kill "${xvfb_pid}" 2>/dev/null || true
   rm -r -f -- "${runtime_dir}" 2>/dev/null || true
}
trap cleanup EXIT

## A generous virtual screen so a normal-sized, decorated window has room around it.
Xvfb "${DISPLAY}" -screen 0 1400x900x24 >/dev/null 2>&1 &
xvfb_pid="$!"
sleep 2
## openbox draws a REAL title bar on every window it manages.
openbox >/dev/null 2>&1 &
wm_pid="$!"
sleep 1
## paint the root a colour no terminal uses, so a screenshot of the whole root
## (where the title bars are genuinely rendered) can be trimmed down to exactly the
## decorated window -- nothing faked, just cropped to what the WM drew.
CHROMA='#ff00ff'
xsetroot -solid "${CHROMA}" 2>/dev/null || true

## NOTE: on a hardened Kicksecure/Whonix system the permission-hardener may strip
## the exec bit from urxvt (historically setuid for utmp). Restore it for the test:
##   sudo chmod +x /usr/bin/urxvt

launch() {  ## $1=emulator  $2=command-string; a normal ~90x28 window where honoured
   local e="$1" cmd="$2"
   case "$e" in
      xterm)          xterm -geometry 90x28 -fa 'Monospace' -fs 11 -e bash -c "${cmd}" ;;
      urxvt)          urxvt -geometry 90x28 -fn 'xft:Monospace:size=11' -e bash -c "${cmd}" ;;
      st)             st -g 90x28 -f 'Monospace:size=11' -e bash -c "${cmd}" ;;
      konsole)        konsole --nofork -e bash -c "${cmd}" ;;
      xfce4-terminal) xfce4-terminal --disable-server --geometry 90x28 -x bash -c "${cmd}" ;;
      mate-terminal)  mate-terminal --disable-factory --geometry 90x28 -x bash -c "${cmd}" ;;
      lxterminal)     lxterminal --geometry 90x28 -e "bash -c '${cmd}'" ;;
      qterminal)      qterminal -e "bash -c '${cmd}'" ;;
      alacritty)      alacritty -o 'window.dimensions.columns=90' -o 'window.dimensions.lines=28' -o 'font.size=11' -e bash -c "${cmd}" ;;
      kitty)          kitty -o 'remember_window_size=no' -o 'initial_window_width=760' -o 'initial_window_height=460' -o 'font_size=11' bash -c "${cmd}" ;;
   esac
}

capture_window() {  ## $1=output-path -- the REAL decorated window (title bar + client)
   local dest="$1" tmp
   xsetroot -solid "${CHROMA}" 2>/dev/null || true
   tmp="$(mktemp --suffix=.png)"
   import -window root "${tmp}" 2>/dev/null || { rm -f -- "${tmp}"; return 1; }
   ## trim the chroma desktop, leaving the decorated window (title bar included)
   convert "${tmp}" -bordercolor "${CHROMA}" -border 1 -trim +repage "${dest}" \
      2>/dev/null || cp -- "${tmp}" "${dest}"
   rm -f -- "${tmp}"
}

clear_windows() {
   local wid
   for wid in $(xdotool search --onlyvisible --name '.*' 2>/dev/null || true); do
      xdotool windowkill "${wid}" 2>/dev/null || true
   done
}

shoot() {  ## $1=emulator  $2=case  $3=payload-file; rc 0 shot, 1 skipped, 2 no window
   local e="$1" case="$2" payload="$3" found=0
   command -v "$e" >/dev/null 2>&1 || { printf 'skip %s (not installed)\n' "$e"; return 1; }
   launch "$e" "cat '${payload}'; sleep 20" >/dev/null 2>&1 &
   local epid="$!"
   for _ in $(seq 1 60); do
      if xdotool search --onlyvisible --name '.*' >/dev/null 2>&1; then found=1; break; fi
      sleep 0.25
   done
   if [ "${found}" -eq 1 ]; then
      sleep 3
      capture_window "${out}/${e}.${case}.png" \
         || printf 'warn %s.%s: screenshot failed\n' "${e}" "${case}"
   else
      printf 'warn %s.%s: window never appeared, no shot\n' "${e}" "${case}"
   fi
   clear_windows
   kill "${epid}" 2>/dev/null || true
   sleep 1.5
   [ "${found}" -eq 1 ]
}

for e in xterm urxvt st konsole xfce4-terminal mate-terminal lxterminal qterminal alacritty kitty; do
   ok=1
   shoot "$e" crafted "${runtime_dir}/crafted.bin" || ok=0
   shoot "$e" random  "${runtime_dir}/random.bin" || ok=0
   if [ "${ok}" -eq 1 ]; then
      printf 'captured %s\n' "$e"
   else
      printf 'incomplete %s (skipped or no window)\n' "$e"
   fi
done

st_bin="${ST_REPO:-}/usr/bin/secure-terminal"
st_pkg="${ST_REPO:-}/usr/lib/python3/dist-packages"
if [ -n "${ST_REPO:-}" ] && [ -f "${st_bin}" ]; then
   for case in crafted random; do
      PYTHONPATH="${st_pkg}" python3 "${st_bin}" --new-instance --mode strip \
         -- bash -c "cat '${runtime_dir}/${case}.bin'; sleep 30" >/dev/null 2>&1 &
      epid="$!"
      for _ in $(seq 1 60); do
         xdotool search --onlyvisible --name '.*[Ss]ecure.*' >/dev/null 2>&1 && break
         sleep 0.25
      done
      sleep 3
      capture_window "${out}/secure-terminal.${case}.png"
      clear_windows
      kill "${epid}" 2>/dev/null || true
      sleep 1.5
   done
   printf 'captured secure-terminal (real GUI)\n'
else
   printf 'skip secure-terminal (set ST_REPO=/path/to/checkout to include it)\n'
fi

printf 'done; shots in %s\n' "${out}"
