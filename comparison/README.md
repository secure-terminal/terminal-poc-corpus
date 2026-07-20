# Hostile-byte-stream comparison: reproduce it yourself

This directory backs the screenshots and results on
<https://secure-terminal.github.io/comparison/>. It lets anyone reproduce the
test: feed the same two byte streams to a set of Debian terminal emulators and to
secure-terminal, and see what each one does.

## The two payloads

- **Case A - random.** `head -c 20000 /dev/urandom`. Genuine random data with no
  crafted escapes. Whatever corruption appears is what random bytes do; no chosen
  title string is possible.
- **Case B - a crafted hostile log.** [`hostile-script.sh`](hostile-script.sh) emits an
  ordinary looking log that carries, mid-stream, the escapes a real hostile log or
  program output can carry:
  - `OSC 0` - silently rewrites the window / tab title to `root@prod-db:~#`
    (illustrative; a real attacker picks their own), never reset;
  - `SGR 31;41` - a stuck colour (red on red) that is never reset;
  - `ESC ( 0` - a shift into the DEC line-drawing charset, never reset.

  The script is plain, deterministic `printf`: same bytes every run, easy to read.
  **Running it IS the reproduction**: `./hostile-script.sh` emits the raw escapes
  straight into your terminal (that is what hijacks the title). To read the bytes
  *without* triggering them, pipe through `cat -v`: `./hostile-script.sh | cat -v`.

## Run the capture

`capture.sh` drives each emulator headless as a client of a nested `labwc`
compositor (the wlroots compositor LXQt ships), run on the host X server via its
x11 backend, with the Clearlooks Openbox theme. labwc draws the same real,
themed server-side title bar on every window -- X11 (Xwayland) and toolkit alike
-- exactly as on an LXQt desktop. It feeds both payloads and screenshots the
result to `shots/`.

```bash
# install the emulators you want to test (this repo installs nothing itself):
sudo apt install --no-install-recommends \
  xterm rxvt-unicode stterm konsole xfce4-terminal mate-terminal \
  lxterminal qterminal alacritty kitty \
  labwc openbox xdotool wmctrl x11-utils x11-xserver-utils imagemagick
# (the openbox package ships the Clearlooks window theme labwc reads; capture.sh
#  sets THEME=Clearlooks -- change it there to use another installed Openbox theme.)

# then capture, on a machine with an X server on $DISPLAY (labwc nests in it;
# point ST_REPO at a secure-terminal checkout to include it):
ST_REPO=/path/to/secure-terminal ./capture.sh
```

Case B is deterministic, so your `*.crafted.png` should match ours modulo fonts.
Case A is random by nature. To read the title behaviour without screenshots, run a
payload in any emulator and check `xdotool getwindowname <window>` before and after.

## What you should see

Every traditional emulator interprets the escapes: the screen is corrupted, the
colour and charset stick, and nine of the ten have their window title silently
rewritten to `root@prod-db:~#` (konsole's default profile stores the value but does
not surface it). secure-terminal reduces the stream to inert printable ASCII: the
title is never touched, the charset shift is shown as literal text, and the only
colour is the bounded, contrast-guarded palette - the attacker's invisible
red-on-red is forced to a plainly readable form and can hide nothing.

## Related

- The automated invariant version of this test ships as `terminal-resilience-tests`
  (opt-in) in [dist-ai](https://github.com/org-ai-assisted/dist-ai): it asserts a
  traditional emulator's title IS hijacked and secure-terminal's output carries no
  escape byte and no title marker.
- The rest of this repo is the adversarial conformance corpus secure-terminal is
  tested against.
