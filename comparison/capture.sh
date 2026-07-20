#!/bin/bash

## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

## Reproduce the secure-terminal "hostile byte streams" comparison, headless.
## For each installed Debian terminal emulator it feeds two payloads and screen-
## shots the DECORATED window (title bar included, no desktop background), so the
## emulator and any title hijack are both legible:
##   Case A (random) : head -c 20000 /dev/urandom  -- genuine random data.
##   Case B (crafted): ./hostile-script.sh          -- an OSC-0 title hijack plus a
##                     stuck colour and a DEC line-drawing charset shift, none reset.
## secure-terminal (its real GUI, from ST_REPO) is captured the same way for a
## like-for-like shot. Output PNGs go to ./shots/.
##
## Decorations come from a real Wayland compositor: weston runs nested (its
## x11-backend puts one window on the host X server) and draws a uniform
## server-side title bar on EVERY window it manages. The minimalist emulators
## (st, urxvt, alacritty, kitty) that a bare X11 WM left undecorated are launched
## as Xwayland clients (forced X11 via the toolkit backend), so weston's xwm
## draws the same real title bar on all ten -- and an OSC-0 title hijack shows up
## in that bar exactly as it would on a normal desktop. Nothing is painted on;
## the title bar is the compositor's own decoration, captured as rendered.
##
## Needs: an X server on $DISPLAY, weston (>=13) with Xwayland, xdotool,
## ImageMagick (import/convert), and whichever emulators you want to test.
## Installs NOTHING itself (supply-chain hygiene): install the emulators +
## weston + xwayland first.
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

host_display="${DISPLAY:-:0}"
CHROMA='#ff00ff'
## the OSC-0 title hostile-script.sh sets; used to gate qterminal's capture on a
## real payload render (see shoot()). Keep in sync with hostile-script.sh.
marker='root@prod-db:~#'

runtime_dir="$(mktemp --directory)"
export XDG_RUNTIME_DIR="${runtime_dir}"
## a clean HOME / config so an emulator's saved profile (Alacritty's dynamic
## title, themes, geometry, ...) cannot change the result -- the capture depends
## only on defaults, keeping it repeatable.
export HOME="${runtime_dir}/home"
export XDG_CONFIG_HOME="${runtime_dir}/config"
mkdir --parents -- "${HOME}" "${XDG_CONFIG_HOME}"

## write the payloads under the space-free runtime dir (a repo checkout path may
## contain spaces, which would break the nested command strings below).
"${here}/hostile-script.sh" > "${runtime_dir}/crafted.bin"
head --bytes=20000 -- /dev/urandom > "${runtime_dir}/random.bin"

## weston config: a chroma desktop to trim against, no panel, no animation, a
## real title bar (weston's default decoration) on every managed window.
cat > "${runtime_dir}/weston.ini" <<INI
[core]
xwayland=true
idle-time=0
require-input=false
renderer=pixman
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
## 1400x900 window holds the compositor; Xwayland is spawned for the X11 clients.
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

## launch an emulator as an X11 (Xwayland) client so weston decorates it. Each
## toolkit is pinned to its X11 backend; WAYLAND_DISPLAY is dropped so a
## Wayland-capable emulator does not draw its own client-side decoration instead.
launch() {  ## $1=emulator  $2=command-string
   local e="$1" cmd="$2"
   local base=(env --unset=WAYLAND_DISPLAY "DISPLAY=${xwl_display}")
   case "$e" in
      xterm)          "${base[@]}" xterm -geometry 90x28 -fa 'Monospace' -fs 11 -e bash -c "${cmd}" ;;
      urxvt)          "${base[@]}" urxvt -geometry 90x28 -fn 'xft:Monospace:size=11' -e bash -c "${cmd}" ;;
      st)             "${base[@]}" st -g 90x28 -f 'Monospace:size=11' -e bash -c "${cmd}" ;;
      konsole)        "${base[@]}" QT_QPA_PLATFORM=xcb konsole --nofork -e bash -c "${cmd}" ;;
      qterminal)      "${base[@]}" QT_QPA_PLATFORM=xcb qterminal -e bash -c "${cmd}" ;;
      xfce4-terminal) "${base[@]}" GDK_BACKEND=x11 xfce4-terminal --disable-server --geometry 90x28 -x bash -c "${cmd}" ;;
      mate-terminal)  "${base[@]}" GDK_BACKEND=x11 mate-terminal --disable-factory --geometry 90x28 -x bash -c "${cmd}" ;;
      lxterminal)     "${base[@]}" GDK_BACKEND=x11 dbus-run-session -- lxterminal --geometry 90x28 -e "bash -c '${cmd}'" ;;
      alacritty)      "${base[@]}" WINIT_UNIX_BACKEND=x11 alacritty -o 'window.dimensions.columns=90' -o 'window.dimensions.lines=28' -o 'font.size=11' -e bash -c "${cmd}" ;;
      kitty)          "${base[@]}" KITTY_ENABLE_WAYLAND=0 kitty -o 'remember_window_size=no' -o 'initial_window_width=760' -o 'initial_window_height=460' -o 'font_size=11' bash -c "${cmd}" ;;
   esac
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

## wait until some NEW window's title is the OSC-0 marker: proof the crafted
## payload actually ran and the title hijack landed. rc 0 if seen, 1 on timeout.
wait_for_marker() {
   local _ cur nm
   for _ in $(seq 1 60); do
      for cur in $(DISPLAY="${xwl_display}" xdotool search --onlyvisible '' 2>/dev/null || true); do
         case "${base_wids}" in *" ${cur} "*) continue ;; esac
         nm="$(DISPLAY="${xwl_display}" xdotool getwindowname "${cur}" 2>/dev/null || true)"
         if [ "${nm}" = "${marker}" ]; then return 0; fi
      done
      sleep 0.25
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

shoot() {  ## $1=emulator  $2=case  $3=payload-file; runs under the CURRENT weston
   local e="$1" case="$2" payload="$3" wid='' cur ww
   launch "$e" "cat '${payload}'; sleep 30" >/dev/null 2>&1 &
   local epid="$!"

   ## qterminal needs its own path: it ignores -geometry (opens filling the
   ## output), maps a decorated top-level plus a nested surface, and is slow to
   ## run its -e command under software-rendered weston. Capturing the generic
   ## "first new window" after a fixed sleep races the startup and can grab the
   ## pre-payload default window (empty screen, title still "Shell No. 1"). So:
   ## gate on the OSC-0 marker title (crafted) to prove the payload rendered,
   ## take the decorated 0,0 top-level, and resize it to match the others.
   if [ "$e" = qterminal ]; then
      if [ "${case}" = crafted ]; then
         wait_for_marker || printf 'warn %s.%s: marker title never appeared\n' "${e}" "${case}"
      else
         sleep 5
      fi
      wid="$(origin_window)"
      if [ -n "${wid}" ]; then
         DISPLAY="${xwl_display}" xdotool windowsize "${wid}" 760 480 2>/dev/null || true
         sleep 2
         capture_window "${out}/${e}.${case}.png" "${wid}" \
            || printf 'warn %s.%s: screenshot failed\n' "${e}" "${case}"
      else
         printf 'warn %s.%s: window never appeared, no shot\n' "${e}" "${case}"
      fi
      clear_windows
      kill "${epid}" 2>/dev/null || true
      sleep 1
      if [ -n "${wid}" ]; then return 0; else return 1; fi
   fi

   for _ in $(seq 1 80); do
      kill -0 "${wm_pid}" 2>/dev/null || { printf 'warn %s.%s: weston died\n' "${e}" "${case}"; return 1; }
      for cur in $(DISPLAY="${xwl_display}" xdotool search --onlyvisible '' 2>/dev/null || true); do
         case "${base_wids}" in *" ${cur} "*) : ;; *) wid="${cur}"; break ;; esac
      done
      [ -n "${wid}" ] && break
      sleep 0.25
   done
   if [ -n "${wid}" ]; then
      sleep 3                             # let the window paint + set its title
      ## random bytes can carry a window-manipulation escape (CSI ... t) that a
      ## terminal honours, shrinking the window to a few pixels; restore a sane
      ## size so its (still corrupted) screen is legible in the shot.
      ww="$(DISPLAY="${xwl_display}" xdotool getwindowgeometry --shell "${wid}" 2>/dev/null | sed -n 's/^WIDTH=//p' || true)"
      if [ -n "${ww}" ] && [ "${ww}" -lt 300 ]; then
         DISPLAY="${xwl_display}" xdotool windowsize "${wid}" 760 460 2>/dev/null || true
         sleep 1.5
      fi
      capture_window "${out}/${e}.${case}.png" "${wid}" \
         || printf 'warn %s.%s: screenshot failed\n' "${e}" "${case}"
   else
      printf 'warn %s.%s: window never appeared, no shot\n' "${e}" "${case}"
   fi
   clear_windows
   kill "${epid}" 2>/dev/null || true
   sleep 1
   [ -n "${wid}" ]
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
   ok=1
   shoot "$e" crafted "${runtime_dir}/crafted.bin" || ok=0
   shoot "$e" random  "${runtime_dir}/random.bin" || ok=0
   stop_weston
   if [ "${ok}" -eq 1 ]; then printf 'captured %s\n' "$e"; else printf 'incomplete %s\n' "$e"; fi
done

## secure-terminal (its real GUI) under the same compositor, forced onto Xwayland
## (PyQt6 -> xcb) so it too carries weston's title bar for a like-for-like shot.
st_bin="${ST_REPO:-}/usr/bin/secure-terminal"
st_pkg="${ST_REPO:-}/usr/lib/python3/dist-packages"
if [ -n "${ST_REPO:-}" ] && [ -f "${st_bin}" ] && start_weston; then
   for case in crafted random; do
      env --unset=WAYLAND_DISPLAY "DISPLAY=${xwl_display}" QT_QPA_PLATFORM=xcb \
         PYTHONPATH="${st_pkg}" python3 "${st_bin}" --new-instance --mode strip \
         -- bash -c "cat '${runtime_dir}/${case}.bin'; sleep 30" >/dev/null 2>&1 &
      epid="$!"
      stwid=''
      for _ in $(seq 1 80); do
         for cur in $(DISPLAY="${xwl_display}" xdotool search --onlyvisible '' 2>/dev/null || true); do
            case "${base_wids}" in *" ${cur} "*) : ;; *) stwid="${cur}"; break ;; esac
         done
         [ -n "${stwid}" ] && break
         sleep 0.25
      done
      sleep 3
      capture_window "${out}/secure-terminal.${case}.png" "${stwid}"
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
