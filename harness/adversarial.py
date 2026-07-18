#!/usr/bin/python3 -Bsu
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
# AI-Assisted.

"""Adversarial corpus test against secure-terminal.

For every corpus PoC, feed the decoded payload to secure-terminal's real output path
(offscreen) and assert it NEVER writes back to the pty -- the by-construction closure
that defeats the whole reflection / echoback attack class (a terminal that answers a
query writes the reply into the shell's input). A single byte written back is a
REFLECTION and fails the run.

It leads with an always-firing POSITIVE CONTROL (`secure-terminal --test-canary`): if
that does not fire, the machinery is broken and no "secure" verdict is trusted, so the
run fails loud rather than reporting a false all-clear.

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


def _reflection_for(payload):
    """Feed `payload` to a fresh secure-terminal (TUI, every reach-out feature ON to
    maximise a vulnerable terminal's chance to answer) and return the bytes it wrote
    back to the pty. Empty == the closure held."""
    if ST_PKG and ST_PKG not in sys.path:
        sys.path.insert(0, ST_PKG)
    _app()                                 # QApplication before any QWidget
    from secure_terminal.terminal import SecureTerminal          # noqa: E402
    term = SecureTerminal(command='/bin/cat', tui=True)
    for feature in ('osc_clipboard_read', 'osc_clipboard', 'osc_title', 'osc_notify',
                    'osc_cwd', 'osc_hyperlink'):
        try:
            term.apply_osc(feature, True)
        except Exception:              # pylint: disable=broad-except
            pass                       # a feature may not exist; the sweep still runs
    sent = []
    term._write = sent.append          # pylint: disable=protected-access
    _feed_output(term, payload)
    term.close()
    return sent


def main():
    require_confined()
    positive_control()
    print('positive control OK: secure-terminal --test-canary fires')
    pocs = sorted(glob.glob(os.path.join(ROOT, 'poc', '*')))
    reflected = 0
    tested = 0
    for poc_dir in pocs:
        payload_hex = os.path.join(poc_dir, 'payload.hex')
        if not os.path.isfile(payload_hex):
            continue
        tested += 1
        poc_id = os.path.basename(poc_dir)
        sent = _reflection_for(_decode(payload_hex))
        if sent:
            reflected += 1
            print('REFLECTED %-42s wrote %d byte(s) back to the pty!'
                  % (poc_id, sum(len(x) for x in sent)))
        else:
            print('ok        %-42s no write-back (closure holds)' % poc_id)
    print('-- %d PoC(s) tested; %d reflected' % (tested, reflected))
    return 1 if reflected else 0


if __name__ == '__main__':
    sys.exit(main())
