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
import subprocess
import sys

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
    try:
        os.write(write_fd, raw)
        os.close(write_fd)
        write_fd = None
        term._on_readable()
    finally:
        term._fd = old
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)


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
    """secure-terminal's line-mode rendered text (strip mode, its safe default)."""
    if ST_PKG and ST_PKG not in sys.path:
        sys.path.insert(0, ST_PKG)
    from secure_terminal.sanitize import render_output            # noqa: E402
    return render_output(payload.decode('utf-8', 'replace'), 'strip')


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


def _obs_paste(payload):
    """secure-terminal's paste-sanitized text (the bracketed-paste guard path)."""
    if ST_PKG and ST_PKG not in sys.path:
        sys.path.insert(0, ST_PKG)
    from secure_terminal.sanitize import sanitize_paste           # noqa: E402
    return sanitize_paste(payload.decode('utf-8', 'replace'))


def _obs_timing(payload):
    """(elapsed_seconds, crashed) processing the payload -- for DoS / decoder overflow."""
    if ST_PKG and ST_PKG not in sys.path:
        sys.path.insert(0, ST_PKG)
    from secure_terminal.sanitize import render_output            # noqa: E402
    import time as _time                                          # noqa: E402
    start = _time.monotonic()
    try:
        render_output(payload.decode('utf-8', 'replace'), 'strip')
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


def _det_paste(text):
    return '\x1b' in text or '\x9b' in text


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
    'denial-of-service': (_obs_timing, _det_timing),
    'decoder-crash': (_obs_timing, _det_timing),
    'paste-bypass': (_obs_paste, _det_paste),
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
        'denial-of-service': (3.0, False),                # took too long
        'decoder-crash': (0.0, True),                     # the decoder crashed
        'paste-bypass': 'x\x1b[201~' + POC_TOKEN,         # the guard-breaking ESC survived
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
    print('-- %d/%d class canaries trigger' % (len(_MODES) - len(broken), len(_MODES)))
    return 1 if broken else 0


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
            mode = yaml.safe_load(handle).get('verification', 'canary-command')
        pair = _MODES.get(mode)
        if pair is None:
            print('SKIP       %-41s unknown verification mode %r' % (poc_id, mode))
            continue
        tested += 1
        observe, detector = pair
        if detector(observe(_decode(payload_hex))):
            fired += 1
            print('VULNERABLE %-41s [%s] the canary FIRED!' % (poc_id, mode))
        else:
            print('ok         %-41s [%s] neutralized' % (poc_id, mode))
    print('-- %d PoC(s) tested; %d fired' % (tested, fired))
    return 1 if fired else 0


if __name__ == '__main__':
    sys.exit(main())
