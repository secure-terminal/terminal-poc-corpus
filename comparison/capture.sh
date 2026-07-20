#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Reproduce the secure-terminal "hostile byte streams" comparison, headless.
## For each installed Debian terminal emulator it starts an interactive shell,
## TYPES a command into it (so the shot shows the prompt, the command, its output
## and the state of the prompt AFTER it -- what a user actually sees, and how to
## reproduce it), and screenshots the DECORATED window (title bar included, no
## desktop background):
##   Case A (random) : head -c 1200 /dev/urandom  -- genuine random data, sized so
##                     the returned prompt stays visible below the garble.
##   Case B (crafted): cat crafted.log            -- an OSC-0 title hijack plus a
##                     stuck colour and a DEC line-drawing charset shift, none reset
##                     (crafted.log is hostile-script.sh's output).
## secure-terminal (its real GUI, from ST_REPO) is captured the same way for a
## like-for-like shot. Output PNGs go to ./shots/.
##
## The prompt is a fixed "user@host:~$" -- deliberately CONTRASTING with the
## root@prod-db the OSC-0 escape forces into the title bar: the prompt shows who
## you really are, the hijacked title lies.
##
## Decorations come from a real Wayland compositor: weston runs nested (its
## x11-backend puts one window on the host X server) and draws a uniform
## server-side title bar on EVERY window it manages. The minimalist emulators
## (st, urxvt, alacritty, kitty) that a bare X11 WM left undecorated are launched
## as Xwayland clients (forced X11 via the toolkit backend), so weston's xwm
## draws the same real title bar on all -- and an OSC-0 title hijack shows up in
## that bar exactly as it would on a normal desktop. Nothing is painted on; the
## title bar is the compositor's own decoration, captured as rendered.
##
## Needs: an X server on $DISPLAY, weston (>=13) with Xwayland, xdotool,
## ImageMagick (import/convert), and whichever emulators you want to test.
## Installs NOTHING itself (supply-chain hygiene): install the emulators +
## weston + xwayland first.
##
## Usage:
##   ST_REPO=/path/to/secure-terminal/checkout ./capture.sh
## Deterministic Case B; Case A is random by nature (that is the point).
##
## NOTE: on a hardened Kicksecure/Whonix system the permission-hardener strips the
## exec bit from urxvt (historically setuid for utmp), so it fails with
## "env: '_urxvt_': Permission denied" and maps no window. Restore it first:
##   sudo chmod a+x /usr/bin/urxvt

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit
shopt -s shift_verbose

here="$(dirname -- "$(readlink --canonicalize -- "$0")")"
out="${here}/shots"
mkdir --parents -- "${out}"

host_display="${DISPLAY:-:0}"
CHROMA='#ff00ff'
## Case A byte count: small enough that the random garble does not fill the whole
## window, so the shell's returned prompt stays visible below it.
RANDOM_BYTES=1200

runtime_dir="$(mktemp --directory)"
export XDG_RUNTIME_DIR="${runtime_dir}"
## a clean HOME / config so an emulator's saved profile (Alacritty's dynamic
## title, themes, geometry, ...) cannot change the result -- the capture depends
## only on defaults, keeping it repeatable.
export HOME="${runtime_dir}/home"
export XDG_CONFIG_HOME="${runtime_dir}/config"
mkdir --parents -- "${HOME}" "${XDG_CONFIG_HOME}"

## the crafted hostile log, cat'd from the shell (Case B). In HOME so the typed
## "cat crafted.log" is short and reproducible.
"${here}/hostile-script.sh" > "${HOME}/crafted.log"
## a fixed, legible, reproducible interactive prompt.
cat > "${HOME}/.strc" <<'RC'
PS1='user@host:~$ '
RC

## Launch every emulator FROM ${HOME} so the shell's cwd holds crafted.log and a
## plain "cat crafted.log" finds it. Do NOT 'cd "$HOME"' in the rcfile instead:
## st's bash sees a different $HOME (the box's real home), so that cd moved it
## away and "cat crafted.log" failed. All paths below are absolute, so changing
## cwd here is safe; the emulators (and the ST block) inherit it.
cd "${HOME}"

## the command TYPED into each terminal, per case.
cmd_for() {  ## $1=case
   case "$1" in
      crafted) printf 'cat crafted.log' ;;
      random)  printf 'head -c %s /dev/urandom' "${RANDOM_BYTES}" ;;
   esac
}

## weston config: a chroma desktop to trim against, no panel, no animation, a
## real title bar (weston's default decoration) on every managed window.
cat > "${runtime_dir}/weston.ini" <<INI
[core]
xwayland=true
idle-time=0
require-input=false
renderer=pixman
[keyboard]
keymap_layout=us
[shell]
background-color=0xff${CHROMA#\#}
panel-position=none
animation=none
INI

wl_socket='wayland-cmp'
export WAYLAND_DISPLAY="${wl_socket}"
weston_log="${runtime_dir}/weston.log"

wm_pid=''
weston_wid=''
xwl_display=''
base_wids=''
cleanup() {
   stop_weston
   rm -r -f -- "${runtime_dir}" 2>/dev/null || true
}

## A FRESH compositor per emulator: a heavy toolkit (e.g. konsole) can abort a
## nested software-rendered weston, so isolate each one -- a crash costs that
## emulator's shots, not the whole run. Nested on the host X server: one
## 1700x1000 window holds the compositor; Xwayland is spawned for the X11 clients.
start_weston() {
   : > "${weston_log}"
   DISPLAY="${host_display}" weston \
      --backend=x11-backend.so \
      --width=1700 --height=1000 \
      --socket="${wl_socket}" \
      --config="${runtime_dir}/weston.ini" \
      >"${weston_log}" 2>&1 &
   wm_pid="$!"
   weston_wid=''
   xwl_display=''
   local _
   for _ in $(seq 1 60); do
      kill -0 "${wm_pid}" 2>/dev/null || return 1
      [ -n "${weston_wid}" ] || weston_wid="$(grep -oE 'window id [0-9]+' "${weston_log}" 2>/dev/null | grep -oE '[0-9]+' | head -1 || true)"
      [ -n "${xwl_display}" ] || xwl_display="$(grep -oiE 'xserver listening on display :[0-9]+' "${weston_log}" 2>/dev/null | grep -oE ':[0-9]+' | head -1 || true)"
      if [ -n "${weston_wid}" ] && [ -n "${xwl_display}" ]; then
         sleep 1
         ## weston/Xwayland keep a root-ish surface mapped at all times; record it
         ## as the baseline so window-wait only fires on a REAL emulator window.
         base_wids=" $(DISPLAY="${xwl_display}" xdotool search --onlyvisible '' 2>/dev/null | tr '\n' ' ')"
         return 0
      fi
      sleep 0.5
   done
   return 1
}
stop_weston() {
   [ -z "${wm_pid}" ] || kill "${wm_pid}" 2>/dev/null || true
   [ -z "${wm_pid}" ] || wait "${wm_pid}" 2>/dev/null || true
   wm_pid=''
}
trap cleanup EXIT

## start an emulator running an INTERACTIVE shell (so its prompt is visible) as an
## X11 (Xwayland) client, so weston decorates it. Each toolkit is pinned to its X11
## backend; WAYLAND_DISPLAY is dropped so a Wayland-capable emulator does not draw
## its own client-side decoration instead. The command is TYPED in later (inject).
launch() {  ## $1=emulator
   local e="$1"
   local base=(env --unset=WAYLAND_DISPLAY "DISPLAY=${xwl_display}")
   local sh=(bash --rcfile "${HOME}/.strc" -i)
   case "$e" in
      xterm)          "${base[@]}" xterm -geometry 90x28 -fa 'Monospace' -fs 11 -e "${sh[@]}" ;;
      urxvt)          "${base[@]}" urxvt -geometry 90x28 -fn 'xft:Monospace:size=11' -e "${sh[@]}" ;;
      st)             "${base[@]}" st -g 90x28 -f 'Monospace:size=11' -e "${sh[@]}" ;;
      konsole)        "${base[@]}" QT_QPA_PLATFORM=xcb konsole --nofork -e "${sh[@]}" ;;
      qterminal)      "${base[@]}" QT_QPA_PLATFORM=xcb qterminal -e "${sh[@]}" ;;
      xfce4-terminal) "${base[@]}" GDK_BACKEND=x11 xfce4-terminal --disable-server --geometry 90x28 -x "${sh[@]}" ;;
      mate-terminal)  "${base[@]}" GDK_BACKEND=x11 mate-terminal --disable-factory --geometry 90x28 -x "${sh[@]}" ;;
      alacritty)      "${base[@]}" WINIT_UNIX_BACKEND=x11 alacritty -o 'window.dimensions.columns=90' -o 'window.dimensions.lines=28' -o 'font.size=11' -e "${sh[@]}" ;;
      kitty)          "${base[@]}" KITTY_ENABLE_WAYLAND=0 kitty -o 'remember_window_size=no' -o 'initial_window_width=760' -o 'initial_window_height=460' -o 'font_size=11' "${sh[@]}" ;;
   esac
}

## type a command into the focused terminal window and run it, as if a user did.
inject() {  ## $1=window-id  $2=command
   local wid="$1" cmd="$2"
   DISPLAY="${xwl_display}" xdotool windowactivate --sync "${wid}" 2>/dev/null \
      || DISPLAY="${xwl_display}" xdotool windowfocus "${wid}" 2>/dev/null || true
   ## Fix the keymap so xdotool type does not mangle symbols (e.g. '/' -> '&',
   ## turning /dev/urandom into &dev&urandom). Two layers are BOTH needed:
   ## weston.ini's [keyboard] keymap_layout reaches XKB toolkits (Qt) but NOT
   ## xterm, which reads the X11 CORE keyboard map -- and that only setxkbmap
   ## sets. It must run AFTER the emulator has mapped (a connecting Xwayland
   ## client resets the server keymap), so re-apply it here, right before typing.
   DISPLAY="${xwl_display}" setxkbmap us 2>/dev/null || true
   sleep 0.4
   DISPLAY="${xwl_display}" xdotool type --delay 45 -- "${cmd}"
   sleep 0.3
   DISPLAY="${xwl_display}" xdotool key --clearmodifiers Return
}

## capture weston's own window (the whole compositor) off the host X server, then
## trim the chroma desktop -- leaving exactly the decorated emulator window.
## weston's default-theme server-side title bar is this many pixels tall; the
## side/bottom borders are ~1px. Used to crop the frame in with the client.
WESTON_TITLEBAR=26

capture_window() {  ## $1=output-path  $2=xwayland-window-id
   local dest="$1" wid="$2" tmp X='' Y='' WIDTH='' HEIGHT=''
   ## park the host pointer off the compositor surface so no cursor is composited.
   DISPLAY="${host_display}" xdotool mousemove 1919 1079 2>/dev/null || true
   sleep 0.3
   tmp="$(mktemp --suffix=.png)"
   import -display "${host_display}" -window "${weston_wid}" "${tmp}" 2>/dev/null \
      || { rm -f -- "${tmp}"; return 1; }
   ## Crop to the emulator window by its real geometry rather than trimming to the
   ## chroma: an Xwayland client sits at the same coordinates in weston's output,
   ## and weston draws its title bar just above it. Cropping (not trimming) is
   ## immune to where the compositor placed the window and to a stray cursor.
   eval "$(DISPLAY="${xwl_display}" xdotool getwindowgeometry --shell "${wid}" 2>/dev/null \
      | grep -E '^(X|Y|WIDTH|HEIGHT)=' || true)"
   if [ -n "${X}" ] && [ -n "${WIDTH}" ] && [ "${WIDTH}" -gt 0 ]; then
      local cx cy cw ch
      cx=$(( X - 1 )); [ "${cx}" -lt 0 ] && cx=0
      cy=$(( Y - WESTON_TITLEBAR )); [ "${cy}" -lt 0 ] && cy=0
      cw=$(( WIDTH + 2 )); ch=$(( HEIGHT + WESTON_TITLEBAR + 1 ))
      convert "${tmp}" -crop "${cw}x${ch}+${cx}+${cy}" +repage \
         -bordercolor "${CHROMA}" -border 2 -fuzz 25% -trim +repage "${dest}" \
         2>/dev/null || cp -- "${tmp}" "${dest}"
   else
      ## fallback: no geometry -> trim the chroma (with a fuzz for the shadow).
      convert "${tmp}" -bordercolor "${CHROMA}" -border 4 -fuzz 30% -trim +repage "${dest}" \
         2>/dev/null || cp -- "${tmp}" "${dest}"
   fi
   rm -f -- "${tmp}"
}

## kill every Xwayland client so the next emulator starts on an empty desktop.
clear_windows() {
   local wid
   for wid in $(DISPLAY="${xwl_display}" xdotool search --onlyvisible '' 2>/dev/null || true); do
      DISPLAY="${xwl_display}" xdotool windowkill "${wid}" 2>/dev/null || true
   done
}

## the FIRST new (non-baseline) window weston mapped for the emulator.
first_window() {
   local cur
   for cur in $(DISPLAY="${xwl_display}" xdotool search --onlyvisible '' 2>/dev/null || true); do
      case "${base_wids}" in *" ${cur} "*) continue ;; esac
      printf '%s' "${cur}"; return 0
   done
   return 1
}

## the largest NEW window weston placed at the output origin (0,0). qterminal
## opens filling the output and maps BOTH a decorated top-level at 0,0 and a
## nested, undecorated inner surface at an offset; this returns the decorated one.
origin_window() {
   local cur wid='' best=-1 X Y WIDTH HEIGHT area
   for cur in $(DISPLAY="${xwl_display}" xdotool search --onlyvisible '' 2>/dev/null || true); do
      case "${base_wids}" in *" ${cur} "*) continue ;; esac
      X=''; Y=''; WIDTH=''; HEIGHT=''
      eval "$(DISPLAY="${xwl_display}" xdotool getwindowgeometry --shell "${cur}" 2>/dev/null \
         | grep -E '^(X|Y|WIDTH|HEIGHT)=' || true)"
      [ "${X:-9}" = 0 ] && [ "${Y:-9}" = 0 ] || continue
      area=$(( ${WIDTH:-0} * ${HEIGHT:-0} ))
      if [ "${area}" -gt "${best}" ]; then best="${area}"; wid="${cur}"; fi
   done
   printf '%s' "${wid}"
}

## wait (up to ~20s) for the emulator's window to appear, returning its id. For
## qterminal the decorated 0,0 top-level; for the rest the first new window.
find_window() {  ## $1=emulator
   local e="$1" wid='' _
   for _ in $(seq 1 80); do
      kill -0 "${wm_pid}" 2>/dev/null || return 1
      if [ "$e" = qterminal ]; then wid="$(origin_window)"; else wid="$(first_window || true)"; fi
      [ -n "${wid}" ] && { printf '%s' "${wid}"; return 0; }
      sleep 0.25
   done
   return 1
}

shoot() {  ## $1=emulator  $2=case; runs under the CURRENT weston
   local e="$1" case="$2" wid='' ww
   launch "$e" >/dev/null 2>&1 &
   local epid="$!"
   wid="$(find_window "$e" || true)"
   if [ -z "${wid}" ]; then
      printf 'warn %s.%s: window never appeared, no shot\n' "${e}" "${case}"
      clear_windows; kill "${epid}" 2>/dev/null || true; sleep 1
      return 1
   fi
   ## qterminal ignores -geometry (opens filling the output); resize to match the
   ## others so its shot is comparable.
   if [ "$e" = qterminal ]; then
      DISPLAY="${xwl_display}" xdotool windowsize "${wid}" 760 480 2>/dev/null || true
      sleep 1
   fi
   sleep 2                                  # let the shell paint its first prompt
   inject "${wid}" "$(cmd_for "${case}")"
   sleep 3                                  # command runs; output + next prompt paint
   ## random bytes can carry a window-manipulation escape (CSI ... t) that a
   ## terminal honours, shrinking the window to a few pixels; restore a sane size
   ## so its (still corrupted) screen is legible in the shot.
   ww="$(DISPLAY="${xwl_display}" xdotool getwindowgeometry --shell "${wid}" 2>/dev/null | sed -n 's/^WIDTH=//p' || true)"
   if [ -n "${ww}" ] && [ "${ww}" -lt 300 ]; then
      DISPLAY="${xwl_display}" xdotool windowsize "${wid}" 760 480 2>/dev/null || true
      sleep 1.5
   fi
   capture_window "${out}/${e}.${case}.png" "${wid}" \
      || printf 'warn %s.%s: screenshot failed\n' "${e}" "${case}"
   clear_windows
   kill "${epid}" 2>/dev/null || true
   sleep 1
}

## lxterminal is intentionally omitted: it maps no window as an Xwayland client
## under weston (its single-instance startup does not complete headless), so it
## cannot be given the compositor's title bar for a like-for-like shot.
for e in xterm urxvt st konsole xfce4-terminal mate-terminal qterminal alacritty kitty; do
   command -v "$e" >/dev/null 2>&1 || { printf 'skip %s (not installed)\n' "$e"; continue; }
   if ! start_weston; then
      printf 'warn %s: weston did not start; log:\n' "$e"; tail -4 "${weston_log}"
      stop_weston; continue
   fi
   shoot "$e" crafted || true
   shoot "$e" random  || true
   stop_weston
   printf 'captured %s\n' "$e"
done

## secure-terminal (its real GUI) under the same compositor, forced onto Xwayland
## (PyQt6 -> xcb) so it too carries weston's title bar for a like-for-like shot.
st_bin="${ST_REPO:-}/usr/bin/secure-terminal"
st_pkg="${ST_REPO:-}/usr/lib/python3/dist-packages"
if [ -n "${ST_REPO:-}" ] && [ -f "${st_bin}" ] && start_weston; then
   for case in crafted random; do
      env --unset=WAYLAND_DISPLAY "DISPLAY=${xwl_display}" QT_QPA_PLATFORM=xcb \
         PYTHONPATH="${st_pkg}" python3 "${st_bin}" --new-instance --mode strip \
         -- bash --rcfile "${HOME}/.strc" -i >/dev/null 2>&1 &
      epid="$!"
      stwid="$(find_window secure-terminal || true)"
      if [ -n "${stwid}" ]; then
         sleep 2
         inject "${stwid}" "$(cmd_for "${case}")"
         sleep 3
         capture_window "${out}/secure-terminal.${case}.png" "${stwid}"
      else
         printf 'warn secure-terminal.%s: window never appeared\n' "${case}"
      fi
      clear_windows
      kill "${epid}" 2>/dev/null || true
      sleep 1.5
   done
   stop_weston
   printf 'captured secure-terminal (real GUI)\n'
else
   printf 'skip secure-terminal (set ST_REPO=/path/to/checkout to include it)\n'
fi

printf 'done; shots in %s\n' "${out}"
