#!/usr/bin/python3 -Bsu
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
# AI-Assisted.

"""Adversarial corpus test against secure-terminal.

For every corpus PoC, fire the decoded payload at secure-terminal and check -- per the
PoC's `verification` mode -- whether the class's standardized canary (the token
POC-CORPUS-CANARY-FIRED) manifests. secure-terminal must neutralize every class:

  * canary-command   -- a reflection/echoback would write the reply back to the pty
                        (injecting the canary command); any write-back is a hit.
  * display-deception -- a hit renders the clean token (bidi reorder) or lets a raw
                        non-ASCII code point (homoglyph / bidi control) survive; checked
                        via secure-terminal's default (strip) sanitizer.
  * clipboard-exfil  -- a hit sets the system clipboard to the canary token (OSC 52
                        write is off by default -> the clipboard must stay unchanged).
  * hyperlink-mismatch -- a hit creates a hyperlink whose target carries the token
                        behind different visible text (OSC 8 off by default -> no anchor).

It leads with an always-firing POSITIVE CONTROL (`secure-terminal --test-canary`): if
that does not fire, the machinery is broken and no "neutralized" verdict is trusted, so
the run fails loud rather than reporting a false all-clear.

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
    machinery works before any 'no reflection' verdict is trusted."""
    if not ST_BIN:
        die('secure-terminal not found (set SECURE_TERMINAL_REPO)', 77)
    env = dict(os.environ)
    env['PYTHONPATH'] = ST_PKG + os.pathsep + env.get('PYTHONPATH', '')
    out = subprocess.run([sys.executable, ST_BIN, '--test-canary'], env=env,
                         stdin=subprocess.DEVNULL, capture_output=True, text=True,
                         timeout=30, check=False)
    if ST_CANARY_TOKEN not in out.stdout:
        die('POSITIVE CONTROL FAILED: secure-terminal --test-canary did not fire; '
            'the machinery is broken -- refusing to trust any "no reflection" verdict.', 4)


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


def _hit_canary_command(payload):
    """canary-command: a reflection/echoback would write the reply back to the pty
    (injecting the canary command). Any write-back is a hit. Features ON to maximise
    the chance a vulnerable terminal answers."""
    term = _new_term(enable_osc=True)
    sent = []
    term._write = sent.append          # pylint: disable=protected-access
    _feed_output(term, payload)
    term.close()
    return bool(sent)


def _hit_display_deception(payload):
    """display-deception: run the payload through secure-terminal's default sanitizer
    (strip mode -- its safe-by-construction default). A hit means the deception
    survived: the clean canary token appears (bidi reordered it into view), OR any raw
    non-ASCII code point from the payload passed through unneutralized (homoglyph /
    bidi control). strip mode replaces every non-ASCII byte and interprets no escapes,
    so a secure terminal lets neither survive."""
    if ST_PKG and ST_PKG not in sys.path:
        sys.path.insert(0, ST_PKG)
    from secure_terminal.sanitize import render_output            # noqa: E402
    rendered = render_output(payload.decode('utf-8', 'replace'), 'strip')
    if POC_TOKEN in rendered:
        return True
    return any(ord(ch) > 127 for ch in rendered)


def _hit_clipboard_exfil(payload):
    """clipboard-exfil: a hit sets the system clipboard to the canary token. OSC 52
    write is off by default, so secure-terminal must leave the clipboard unchanged."""
    from PyQt6.QtGui import QGuiApplication                      # noqa: E402
    board = QGuiApplication.clipboard()
    board.setText('CLIP-SENTINEL-UNCHANGED')
    term = _new_term(enable_osc=False)     # osc_clipboard OFF (default) -> gated
    _feed_output(term, payload)
    result = board.text()
    term.close()
    return result == POC_TOKEN


def _hit_hyperlink_mismatch(payload):
    """hyperlink-mismatch: a hit creates a hyperlink whose target carries the canary
    token behind different visible text. OSC 8 is off by default, so secure-terminal
    must create no such anchor."""
    term = _new_term(enable_osc=False)     # osc_hyperlink OFF (default) -> gated
    _feed_output(term, payload)
    hit = False
    doc = term.document()
    block = doc.begin()
    while block.isValid():
        frag_it = block.begin()
        while not frag_it.atEnd():
            if POC_TOKEN in frag_it.fragment().charFormat().anchorHref():
                hit = True
            frag_it += 1
        block = block.next()
    term.close()
    return hit


_CHECKS = {
    'canary-command': _hit_canary_command,
    'display-deception': _hit_display_deception,
    'clipboard-exfil': _hit_clipboard_exfil,
    'hyperlink-mismatch': _hit_hyperlink_mismatch,
}


def main():
    require_confined()
    positive_control()
    print('positive control OK: secure-terminal --test-canary fires')
    import yaml                                                  # noqa: E402
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
        check = _CHECKS.get(mode)
        if check is None:
            print('SKIP       %-41s unknown verification mode %r' % (poc_id, mode))
            continue
        tested += 1
        if check(_decode(payload_hex)):
            fired += 1
            print('VULNERABLE %-41s [%s] the canary FIRED!' % (poc_id, mode))
        else:
            print('ok         %-41s [%s] neutralized' % (poc_id, mode))
    print('-- %d PoC(s) tested; %d fired' % (tested, fired))
    return 1 if fired else 0


if __name__ == '__main__':
    sys.exit(main())
