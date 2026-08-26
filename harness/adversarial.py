#!/usr/bin/python3 -Bsu
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
# AI-Assisted.

"""Adversarial corpus test against secure-terminal.

Each verification mode is an OBSERVABLE + a DETECTOR. The observable feeds a payload
to secure-terminal and reads a plain value (its rendered text, the clipboard, the
bytes written back to the pty, the notifications emitted, the anchors created, the
processing time). The detector is a PURE function of that value that returns True on
a hit. secure-terminal must neutralize every class, so the detector on its real
observable returns False for every PoC.

Crucially, `--self-test` runs each detector on a synthetic VULNERABLE observable that
it MUST fire on -- proving the canary for that class actually triggers and the check
is real, not a tautology. The run also leads with an always-firing positive control
(`secure-terminal --test-canary`); if it does not fire the machinery is broken and no
"neutralized" verdict is trusted.

CONFINED: this decodes live terminal bytes, so it runs in the sandbox or in GitHub CI
(isolated ephemeral runners) only, unless explicitly overridden. See ../SAFETY.md.
"""

import binascii
import glob
import os
import re
import subprocess
import sys
import threading

os.environ.setdefault('QT_QPA_PLATFORM', 'offscreen')
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
# Must match secure_terminal.main.CANARY_TOKEN (a fixed protocol constant).
ST_CANARY_TOKEN = 'SECURE-TERMINAL-TEST-CANARY-POSITIVE-CONTROL-V1'
# The corpus canary token every PoC embeds in the way its class manifests a hit.
POC_TOKEN = 'POC-CORPUS-CANARY-FIRED'


def die(msg, code=2):
    sys.stderr.write('adversarial: ' + msg + '\n')
    raise SystemExit(code)


def require_confined():
    """Refuse to decode/feed live payloads outside a confined context."""
    if os.environ.get('POC_CORPUS_IN_SANDBOX') == '1':
        return
    if os.environ.get('DIST_AI_IN_SANDBOX') == '1':
        return
    if os.environ.get('GITHUB_ACTIONS') == 'true' or os.environ.get('CI') == 'true':
        return
    if os.environ.get('POC_CORPUS_ALLOW_HOST') == '1':
        sys.stderr.write('adversarial: WARNING: POC_CORPUS_ALLOW_HOST=1 -- running '
                         'outside the sandbox / CI.\n')
        return
    die('refuse to run outside the sandbox / GitHub CI (decodes live payloads). '
        'Set POC_CORPUS_IN_SANDBOX=1 or POC_CORPUS_ALLOW_HOST=1. See ../SAFETY.md.', 3)


def _st_paths():
    """(secure-terminal entrypoint, dist-packages dir) from SECURE_TERMINAL_REPO or a
    default checkout, or (None, None)."""
    candidates = []
    repo = os.environ.get('SECURE_TERMINAL_REPO')
    if repo:
        candidates.append(repo)
    candidates.append(os.path.expanduser('~/private-sources/secure-terminal'))
    for cand in candidates:
        pkg = os.path.join(cand, 'usr', 'lib', 'python3', 'dist-packages')
        if os.path.isdir(os.path.join(pkg, 'secure_terminal')):
            return os.path.join(cand, 'usr', 'bin', 'secure-terminal'), pkg
    return None, None


ST_BIN, ST_PKG = _st_paths()


def positive_control():
    """Always-firing control: `secure-terminal --test-canary` must fire, proving the
    machinery works before any 'neutralized' verdict is trusted."""
    if not ST_BIN:
        die('secure-terminal not found (set SECURE_TERMINAL_REPO)', 77)
    env = dict(os.environ)
    env['PYTHONPATH'] = ST_PKG + os.pathsep + env.get('PYTHONPATH', '')
    out = subprocess.run([sys.executable, ST_BIN, '--test-canary'], env=env,
                         stdin=subprocess.DEVNULL, capture_output=True, text=True,
                         timeout=30, check=False)
    if ST_CANARY_TOKEN not in out.stdout:
        die('POSITIVE CONTROL FAILED: secure-terminal --test-canary did not fire; '
            'the machinery is broken -- refusing to trust any "neutralized" verdict.', 4)


def _decode(payload_hex):
    body = []
    with open(payload_hex, encoding='ascii') as handle:
        for line in handle:
            body.append(''.join(line.split('#', 1)[0].split()))
    return binascii.unhexlify(''.join(body))


def _feed_output(term, raw):
    """Drive the real output path with `raw` bytes via a pipe, as if the child had
    printed them (runs pyte feed + the OSC handlers + line render), mirroring the
    widget test's feed_output."""
    read_fd, write_fd = os.pipe()
    old = term._fd
    term._fd = read_fd
    # Write on a thread so the reader (_on_readable) drains the pipe concurrently.
    # A payload larger than the ~64 KiB pipe buffer would otherwise block os.write
    # forever -- nothing has read a byte yet, since _on_readable only runs after the
    # write returns -- and deadlock the whole sweep. The memoryview loop also finishes
    # a partial write (a bare os.write may return short). Kept a pipe, not a temp file,
    # so the decoded live payload stays in RAM and never touches disk (SAFETY.md).
    def _pump():
        try:
            buf = memoryview(raw)
            while buf:
                buf = buf[os.write(write_fd, buf):]
        finally:
            os.close(write_fd)
    # _on_readable() consumes ONE 65536-byte read per call, so a payload larger than
    # that (or the pipe buffer) needs REPEATED reads. Drain to EOF -- a zero-byte read
    # fires shell_exited -- so a detector sees the WHOLE payload; reading only the
    # first chunk could leave a later-class attack in the unread tail and falsely
    # report it neutralized.
    drained = []
    term.shell_exited.connect(lambda *_: drained.append(True))
    writer = threading.Thread(target=_pump)
    writer.start()
    try:
        while not drained:
            term._on_readable()
    finally:
        term._fd = old
        os.close(read_fd)
        writer.join()


_APP = None


def _app():
    """The one QApplication, kept in a module global so it is not garbage-collected
    (a discarded QApplication leaves widgets with no app -> hard abort)."""
    global _APP
    if _APP is None:
        from PyQt6.QtWidgets import QApplication
        _APP = QApplication.instance() or QApplication([])
    return _APP


def _new_term(enable_osc):
    """A fresh offscreen secure-terminal (TUI). enable_osc turns every reach-out OSC
    feature ON (to maximise a vulnerable terminal's chance to act); leave it off to
    test the SECURE-BY-DEFAULT gating (osc_clipboard / osc_hyperlink off)."""
    if ST_PKG and ST_PKG not in sys.path:
        sys.path.insert(0, ST_PKG)
    _app()                                 # QApplication before any QWidget
    from secure_terminal.terminal import SecureTerminal          # noqa: E402
    term = SecureTerminal(command='/bin/cat', tui=True)
    if enable_osc:
        for feature in ('osc_clipboard_read', 'osc_clipboard', 'osc_title',
                        'osc_notify', 'osc_cwd', 'osc_hyperlink'):
            try:
                term.apply_osc(feature, True)
            except Exception:          # pylint: disable=broad-except
                pass                   # a feature may not exist; the sweep still runs
    return term


# ---- observables: feed the payload to secure-terminal, return a plain value ----

def _obs_writeback(payload):
    """Bytes secure-terminal writes back to the pty (reflection / echoback), with every
    reach-out OSC feature ON to maximise the chance a vulnerable terminal answers."""
    term = _new_term(enable_osc=True)
    sent = []
    term._write = sent.append              # pylint: disable=protected-access
    _feed_output(term, payload)
    term.close()
    return sent


def _obs_render_strip(payload):
    """secure-terminal's line-mode rendered text.

    'box' is the strictest mode (every neutralized byte becomes one placeholder).
    This said "strip" -- a mode name that no longer exists, so render_output fell
    through its if/elif chain to the same behaviour BY ACCIDENT rather than by
    request. It also called it "its safe default", which is wrong: the default is
    'detail'. A dead alias silently testing the right thing is one rename away from
    silently testing the wrong thing.
    """
    if ST_PKG and ST_PKG not in sys.path:
        sys.path.insert(0, ST_PKG)
    from secure_terminal.sanitize import render_output            # noqa: E402
    return render_output(payload.decode('utf-8', 'replace'), 'box')


def _obs_clipboard(payload):
    """The system clipboard after feeding the payload (OSC 52 write off by default)."""
    from PyQt6.QtGui import QGuiApplication                       # noqa: E402
    board = QGuiApplication.clipboard()
    board.setText('CLIP-SENTINEL-UNCHANGED')
    term = _new_term(enable_osc=False)
    _feed_output(term, payload)
    result = board.text()
    term.close()
    return result


def _obs_anchors(payload):
    """Hyperlink anchor targets in the rendered document (OSC 8 off by default)."""
    term = _new_term(enable_osc=False)
    _feed_output(term, payload)
    hrefs = []
    doc = term.document()
    block = doc.begin()
    while block.isValid():
        frag_it = block.begin()
        while not frag_it.atEnd():
            hrefs.append(frag_it.fragment().charFormat().anchorHref())
            frag_it += 1
        block = block.next()
    term.close()
    return hrefs


def _obs_notifications(payload):
    """Desktop-notification texts emitted while feeding (osc_notify off by default)."""
    term = _new_term(enable_osc=False)
    fired = []
    try:
        term.notified.connect(fired.append)
    except Exception:                      # pylint: disable=broad-except
        pass                               # no such signal -> none can fire
    _feed_output(term, payload)
    term.close()
    return fired


def _obs_paste_autoexec(payload):
    """Drive the REAL GUI paste path and report the actual security effect.

    The old paste oracle only asked "did an ESC survive sanitize_paste?" -- a PROXY
    that the pastejacking bug passed while the terminal still auto-ran the payload.
    This feeds the payload as a real clipboard paste (insertFromMimeData) into a
    line-mode terminal (the secure default: bracketed paste off, so a trailing submit
    WOULD auto-run) and returns (bytes_written_to_child, review_held): did a submit
    reach the child, and was a review bar interposed first. That is the effect an
    attacker cares about, not whether an escape byte was stripped."""
    if ST_PKG and ST_PKG not in sys.path:
        sys.path.insert(0, ST_PKG)
    _app()                                 # QApplication before any QWidget
    from secure_terminal.terminal import SecureTerminal           # noqa: E402
    from PyQt6.QtCore import QMimeData                            # noqa: E402
    term = SecureTerminal(command='/bin/cat')      # line mode (safe default)
    sent = []
    reviewed = []
    term._write = sent.append              # pylint: disable=protected-access
    term.paste_review_requested.connect(lambda raw, delay: reviewed.append(raw))
    mime = QMimeData()
    mime.setText(payload.decode('utf-8', 'replace'))
    term.insertFromMimeData(mime)
    written = b''.join(bytes(chunk) for chunk in sent)
    term.close()
    return (written, bool(reviewed))


def _obs_mouse_report(payload):
    """Feed a DECSET mouse-enable payload and return the bytes written back to the
    pty by OUTPUT ALONE -- no pointer event is posted. Reporting a REAL user mouse
    event is a standard feature (xterm/konsole and secure-terminal all answer a
    program's tracking request with '\\x1b[<...M/m' when the user actually clicks or
    scrolls); that is the user's own action, not injection. The vuln this class
    guards is OUTPUT fabricating input -- a write-back caused by the enable sequence
    ITSELF, with no user action. A correct terminal writes nothing until a genuine
    event, so `sent` is empty. (Shift-locality and the real-event feature are
    terminal-specific and checked in each terminal's own suite, not this cross-
    terminal detector.)"""
    term = _new_term(enable_osc=True)
    sent = []
    term._write = sent.append              # pylint: disable=protected-access -- spy BEFORE feed
    _feed_output(term, payload)            # the DECSET mouse-enable sequence, output only
    term.close()
    return sent


def _obs_timing(payload):
    """(elapsed_seconds, crashed) processing the payload -- for DoS / decoder overflow."""
    if ST_PKG and ST_PKG not in sys.path:
        sys.path.insert(0, ST_PKG)
    from secure_terminal.sanitize import render_output            # noqa: E402
    import time as _time                                          # noqa: E402
    start = _time.monotonic()
    try:
        render_output(payload.decode('utf-8', 'replace'), 'box')
    except Exception:                      # pylint: disable=broad-except -- a crash is a hit
        return (0.0, True)
    return (_time.monotonic() - start, False)


# ---- detectors: pure functions of an observable (True == the class fired) ----

def _det_writeback(sent):
    return bool(sent)


def _det_deception(text):
    # a hit: the clean token was reordered into view (bidi), or a raw non-ASCII code
    # point (homoglyph / bidi control) survived.
    return POC_TOKEN in text or any(ord(ch) > 127 for ch in text)


def _det_charset(text):
    # a hit: charset-shift line-drawing glyphs (non-ASCII) survived.
    return any(ord(ch) > 127 for ch in text)


def _det_cursor(text):
    # a hit: the token was overwritten / hidden (no longer present).
    return POC_TOKEN not in text


def _det_clipboard(clip):
    return clip == POC_TOKEN


def _det_anchors(hrefs):
    return any(POC_TOKEN in (href or '') for href in hrefs)


def _det_notify(texts):
    return any(POC_TOKEN in str(text) for text in texts)


def _esc_body_leak(text, bodies):
    """Defense-in-depth for the escape-survival detectors: a broken neutralizer that
    mangles the ESC introducer but LEAKS the sequence body as ASCII text (e.g. '[5i',
    '[?1049h') would slip an \\x1b-keyed check. These bodies are distinctive to the class's
    payload, so flagging them adds no false positive against that PoC."""
    return any(body in text for body in bodies)


def _det_altscreen(text):
    # a hit: an alternate-screen enable escape survived, so the terminal would switch to
    # the alt buffer -- a stuck full-screen hijack. secure-terminal strips it. The body-
    # leak arm also fires if a mangled-ESC neutralizer leaks the '[?1049h' body as text.
    return (any(seq in text for seq in ('\x1b[?1049h', '\x1b[?1047h', '\x1b[?47h'))
            or _esc_body_leak(text, ('[?1049h', '[?1047h', '[?47h')))


def _det_screen_dump(text):
    # a hit: a Media Copy / print sequence survived the render (CSI ... i -- e.g. the
    # printer-controller-on 'CSI 5 i', print-screen 'CSI i', printer-off 'CSI 4 i'),
    # so a vulnerable terminal would dump the screen to its printer / a file.
    # secure-terminal strips every escape, so none survives. The body-leak arm also fires
    # if a mangled-ESC neutralizer leaks the distinctive '[5i'/'[4i' body as text.
    return (re.search(r'\x1b\[[0-9;?]*i', text) is not None
            or _esc_body_leak(text, ('[5i', '[4i')))


def _det_crafted(text):
    # a hit: the OSC-0 title-set or the DEC charset-shift escape survived, so the
    # crafted log would hijack the title / corrupt the charset. secure-terminal strips
    # both.
    return '\x1b]0;' in text or '\x1b(0' in text


def _det_composite(text):
    # a hit: ANY embedded class survived the render. A surviving ESC (0x1b) covers every
    # escape class at once -- OSC-0 title, DEC charset shift, alt-screen enable, OSC 8/9/52,
    # and the DSR cursor-report query -- since each carries an ESC; NUL (0x00) is a
    # truncation byte; and _det_deception catches any surviving non-ASCII code point
    # (homoglyph, bidi control, zero-width, combining, fullwidth, foreign). So one
    # assertion covers every class the tui-showcase file carries: a regression in any
    # single class re-introduces an ESC, a NUL, or a non-ASCII byte.
    #
    # NOTE \b \t \n \r are DELIBERATELY honored by secure-terminal's widget as line-local
    # edits (a \r overwrites only the CURRENT line, never an earlier one -- vertical
    # addressing IS stripped), so they are NOT flagged; the CR+erase class is neutralized
    # by the stricter stcat path, not this widget render (see expected.md).
    return '\x1b' in text or '\x00' in text or _det_deception(text)


def _det_paste_autoexec(observed):
    """A hit: a submit byte (CR or LF) reached the child. Either delimiter submits the
    line, and the paste-trailing-newline PoC's payload ends in LF, so both must count.
    The submit byte on the child's input IS the auto-exec, so it is a hit REGARDLESS of
    whether a review was also signalled: a terminal that raises a review bar and STILL
    forwards CR/LF has auto-executed, and gating the hit on `not reviewed` would let that
    exact bypass pass. `reviewed` is kept for diagnostics only, never to suppress a hit.
    Both genuinely safe outcomes still pass because they write NO submit byte to the
    child: held-for-review (nothing was written) and submit-stripped (the command reached
    the prompt but carries no submit byte, so it waits for the user's Enter)."""
    written, _reviewed = observed
    return b'\r' in written or b'\n' in written


def _det_timing(elapsed_crashed):
    elapsed, crashed = elapsed_crashed
    return crashed or elapsed > 2.0


# verification mode -> (observable of secure-terminal, detector)
_MODES = {
    'canary-command': (_obs_writeback, _det_writeback),
    'reflection': (_obs_writeback, _det_writeback),
    'display-deception': (_obs_render_strip, _det_deception),
    'charset-deception': (_obs_render_strip, _det_charset),
    'cursor-spoof': (_obs_render_strip, _det_cursor),
    'clipboard-exfil': (_obs_clipboard, _det_clipboard),
    'hyperlink-mismatch': (_obs_anchors, _det_anchors),
    'notification-spoof': (_obs_notifications, _det_notify),
    'screen-hijack': (_obs_render_strip, _det_altscreen),
    'screen-dump-to-file': (_obs_render_strip, _det_screen_dump),
    'crafted-composite': (_obs_render_strip, _det_crafted),
    'composite-multiclass': (_obs_render_strip, _det_composite),
    'denial-of-service': (_obs_timing, _det_timing),
    'decoder-crash': (_obs_timing, _det_timing),
    # Real-effect paste oracle: does a submit reach the child with no review? (The
    # retired 'paste-bypass' mode only checked whether an ESC survived sanitize_paste
    # -- a proxy the pastejacking bug passed while still auto-running the payload.)
    'paste-autoexec': (_obs_paste_autoexec, _det_paste_autoexec),
    # Mouse tracking: a DECSET enable plus real mouse/wheel events must elicit no
    # mouse-report write-back on the child's stdin.
    'mouse-tracking-reflection': (_obs_mouse_report, _det_writeback),
}


def _vulnerable_observable(mode):
    """A synthetic observable a VULNERABLE terminal would produce for this mode -- the
    per-class positive control. The mode's detector MUST fire on it, proving the canary
    triggers and the check is real (not a tautology)."""
    return {
        'canary-command': [b'\x1b]52;c;reflected\x07'],   # the terminal wrote a reply back
        'reflection': [b'\x1b[24;80R'],                   # a DSR reply written back
        'display-deception': POC_TOKEN[::-1] + chr(0x202e),  # RLO + reversed token
        'charset-deception': 'POC' + chr(0x2500) + chr(0x2502),  # line-drawing glyphs
        'cursor-spoof': 'FAKE-BENIGN-LINE',               # the token was overwritten
        'clipboard-exfil': POC_TOKEN,                     # clipboard set to the token
        'hyperlink-mismatch': ['https://attacker.example/' + POC_TOKEN],  # anchor -> token
        'notification-spoof': [POC_TOKEN],                # a notification bearing the token
        'screen-hijack': 'log\x1b[?1049h\x1b[?1047h\x1b[?47h\x1b[2J' + POC_TOKEN,  # any alt-screen enable survived
        'screen-dump-to-file': 'log\x1b[5i\x1b[i' + POC_TOKEN,  # a Media Copy print/dump escape survived
        'crafted-composite': 'log\x1b]0;fake\x07\x1b(0lqqqk',  # OSC-0 + charset escapes survived
        'composite-multiclass': 'log\x1b]0;fake\x07\x1b(0lqqqk\x1b[?1049h' + chr(0x202e) + 'x',  # OSC-0 + charset + alt-screen + bidi non-ASCII survived
        'denial-of-service': (3.0, False),                # took too long
        'decoder-crash': (0.0, True),                     # the decoder crashed
        # a submit (CR) reached the child EVEN THOUGH a review was signalled -> the
        # review bar was shown but the line still auto-executed. This is the fail-open
        # case: a detector that suppressed the hit on `reviewed` would miss it.
        'paste-autoexec': (b'echo ' + POC_TOKEN.encode() + b'\r', True),
        # the terminal wrote an SGR mouse report back onto the child's stdin
        'mouse-tracking-reflection': [b'\x1b[<0;10;5M'],
    }[mode]


def self_test():
    """Prove every class's canary actually TRIGGERS: run each mode's detector on a
    synthetic VULNERABLE observable and confirm it fires. If any does not fire, that
    detector is broken (a tautology) and no 'neutralized' verdict for it is trusted."""
    broken = []
    for mode in sorted(_MODES):
        detector = _MODES[mode][1]
        fired = bool(detector(_vulnerable_observable(mode)))
        print('%-9s %-20s canary %s' % (
            'TRIGGERS' if fired else 'DEAD', mode,
            'fires on a vulnerable case' if fired else 'DID NOT FIRE (tautology!)'))
        if not fired:
            broken.append(mode)
    # Defense-in-depth: the escape-survival detectors with a distinctive body must ALSO
    # fire when a broken neutralizer mangles the ESC introducer but leaks the sequence
    # body as ASCII text. A pre-guard detector keyed only on \x1b misses this, so this
    # canary FAILS on the old code.
    body_broken = []
    for mode, leak in (('screen-hijack', 'log[?1049h[2J' + POC_TOKEN),
                       ('screen-dump-to-file', 'log[5i[i' + POC_TOKEN)):
        fired = bool(_MODES[mode][1](leak))
        print('%-9s %-20s body-leak canary %s' % (
            'TRIGGERS' if fired else 'DEAD', mode,
            'fires on a leaked escape body' if fired else 'DID NOT FIRE (guard missing!)'))
        if not fired:
            body_broken.append(mode)
    print('-- %d/%d class canaries trigger' % (len(_MODES) - len(broken), len(_MODES)))
    return 1 if (broken or body_broken) else 0


def main(argv=None):
    import argparse                                               # noqa: E402
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('--self-test', action='store_true',
                        help='prove every class canary fires on a vulnerable case, then exit')
    args = parser.parse_args(argv)

    require_confined()
    if args.self_test:
        return self_test()

    positive_control()
    print('positive control OK: secure-terminal --test-canary fires')
    import yaml                                                   # noqa: E402
    pocs = sorted(glob.glob(os.path.join(ROOT, 'poc', '*')))
    fired = 0
    tested = 0
    for poc_dir in pocs:
        payload_hex = os.path.join(poc_dir, 'payload.hex')
        meta_path = os.path.join(poc_dir, 'meta.yaml')
        if not (os.path.isfile(payload_hex) and os.path.isfile(meta_path)):
            continue
        poc_id = os.path.basename(poc_dir)
        with open(meta_path, encoding='utf-8') as handle:
            # A corpus meta.yaml is untrusted data: an empty / comment-only / bare-scalar
            # file makes safe_load return non-dict (or None), and a bare .get() would
            # AttributeError and abort the whole sweep. Coerce to a mapping first.
            loaded = yaml.safe_load(handle)
            mode = (loaded if isinstance(loaded, dict) else {}).get(
                'verification', 'canary-command')
        pair = _MODES.get(mode)
        if pair is None:
            print('SKIP       %-41s unknown verification mode %r' % (poc_id, mode))
            continue
        observe, detector = pair
        # payload.hex is untrusted corpus data too (same class as the meta.yaml guard
        # above): an odd-nibble, non-hex, or non-ASCII file makes _decode raise and would
        # abort the WHOLE sweep on one bad sibling. Skip that PoC, keep testing the rest.
        try:
            raw = _decode(payload_hex)
        except (binascii.Error, UnicodeDecodeError) as exc:
            print('SKIP       %-41s undecodable payload.hex: %s' % (poc_id, exc))
            continue
        tested += 1
        hit = bool(detector(observe(raw)))
        # UNIVERSAL reflection property (#31 P1): output must NEVER induce an input
        # reply. Applied to EVERY class, not only the reflection PoCs -- feed the
        # payload as program output with every OSC reach-out enabled and assert the
        # write-spy stays empty. secure-terminal answers no query in any mode, so the
        # single defensible write-back (a granted OSC 52 reply) is never provoked by
        # output alone. Its positive control is the 'reflection' self-test entry (a
        # synthetic reply the writeback detector fires on).
        reflected = bool(_det_writeback(_obs_writeback(raw)))
        if hit or reflected:
            fired += 1
            why = mode if hit else 'reflection-property'
            tail = ' (+reflection write-back)' if hit and reflected else ''
            print('VULNERABLE %-41s [%s] the canary FIRED!%s' % (poc_id, why, tail))
        else:
            print('ok         %-41s [%s] neutralized' % (poc_id, mode))
    print('-- %d PoC(s) tested; %d fired' % (tested, fired))
    return 1 if fired else 0


if __name__ == '__main__':
    sys.exit(main())
