#!/usr/bin/python3 -Bsu
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
# AI-Assisted.

"""Sandbox-only runner for the terminal-poc-corpus.

For each selected PoC it decodes the hex payload, feeds it to a terminal-under-test
that is running a shell with the canary marker path exported, and checks whether the
safe CANARY MARKER file was written -- i.e. whether the injected (canary-forked)
command executed. A written marker means the terminal is vulnerable to that class;
the action itself is harmless (it only writes a token).

CRITICAL (see ../SAFETY.md):
  * Payloads are decoded to live bytes ONLY here, at run time, inside the sandbox.
  * This script REFUSES to run outside the sandbox VM unless explicitly overridden.
  * It runs an always-firing POSITIVE CONTROL first and FAILS LOUD if the canary
    machinery is not observed, so a "not vulnerable" verdict is never a false green.
"""

import argparse
import binascii
import os
import subprocess
import sys
import tempfile

CANARY_TOKEN = 'POC-CORPUS-CANARY-FIRED'


def die(msg, code=2):
    sys.stderr.write('poc-corpus: ' + msg + '\n')
    raise SystemExit(code)


def require_sandbox():
    """Refuse to decode/run payloads outside the sandbox VM. Enforced in code, not
    by discipline. Exempt: an in-sandbox marker, or an explicit documented override."""
    if os.environ.get('POC_CORPUS_IN_SANDBOX') == '1':
        return
    if os.environ.get('DIST_AI_IN_SANDBOX') == '1':
        return
    if os.environ.get('POC_CORPUS_ALLOW_HOST') == '1':
        sys.stderr.write('poc-corpus: WARNING: POC_CORPUS_ALLOW_HOST=1 -- decoding '
                         'live payloads outside the sandbox. See SAFETY.md.\n')
        return
    die('refusing to run outside the sandbox VM (payloads decode to live terminal\n'
        '  bytes here). Run this inside the sandbox with POC_CORPUS_IN_SANDBOX=1, or\n'
        '  set POC_CORPUS_ALLOW_HOST=1 to deliberately override. See SAFETY.md.', 3)


def decode_payload(path):
    """Read a payload.hex (whitespace + '#' comments ignored) into live bytes."""
    out = []
    with open(path, encoding='ascii') as handle:
        for line in handle:
            line = line.split('#', 1)[0]
            out.append(''.join(line.split()))
    try:
        return binascii.unhexlify(''.join(out))
    except (binascii.Error, ValueError) as exc:
        die('bad hex in %s: %s' % (path, exc))


def _canary_env(marker):
    env = dict(os.environ)
    env['POC_CANARY'] = marker            # the shell-visible marker path a fired PoC writes
    env['POC_CANARY_TOKEN'] = CANARY_TOKEN
    return env


def _fired(marker):
    try:
        with open(marker, encoding='ascii') as handle:
            return CANARY_TOKEN in handle.read()
    except OSError:
        return False


def positive_control():
    """Always-firing EICAR-style control: run the canary command in a plain shell and
    confirm the marker is observed. If THIS does not fire, the detection machinery is
    broken and every 'not vulnerable' verdict is meaningless -- so we fail loud."""
    with tempfile.TemporaryDirectory() as tmp:
        marker = os.path.join(tmp, 'canary')
        cmd = 'printf %s "$POC_CANARY_TOKEN" > "$POC_CANARY"'
        subprocess.run(['/bin/sh', '-c', cmd], env=_canary_env(marker),
                       stdin=subprocess.DEVNULL, timeout=30, check=False)
        if not _fired(marker):
            die('POSITIVE CONTROL FAILED: the canary machinery did not fire. The\n'
                '  harness is broken; refusing to report any terminal "not vulnerable".', 4)
    return True


def run_poc(poc_dir, feed_template):
    """Decode the PoC and feed it to the terminal-under-test via feed_template, then
    report whether the canary marker fired. feed_template is a shell command with a
    {payload} placeholder (path to the decoded payload) -- it is terminal-specific
    (e.g. 'xterm -e sh -c "cat {payload}; read x"'). The shell it launches sees
    $POC_CANARY / $POC_CANARY_TOKEN, so a canary-forked injection writes the marker."""
    poc_id = os.path.basename(poc_dir.rstrip('/'))
    payload = decode_payload(os.path.join(poc_dir, 'payload.hex'))
    with tempfile.TemporaryDirectory() as tmp:
        marker = os.path.join(tmp, 'canary')
        payload_file = os.path.join(tmp, 'payload.bin')
        with open(payload_file, 'wb') as handle:
            handle.write(payload)
        cmd = feed_template.replace('{payload}', payload_file)
        try:
            subprocess.run(['/bin/sh', '-c', cmd], env=_canary_env(marker),
                           stdin=subprocess.DEVNULL, timeout=60, check=False)
        except subprocess.TimeoutExpired:
            pass
        fired = _fired(marker)
    verdict = 'VULNERABLE' if fired else 'not-vulnerable'
    print('%-40s %s' % (poc_id, verdict))
    return fired


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split('\n', 1)[0])
    parser.add_argument('poc', nargs='*', help='poc/<id> directories to run (default: all)')
    parser.add_argument('--feed-template', default='',
                        help="terminal-specific shell command with a {payload} "
                             "placeholder, e.g. 'xterm -e sh -c \"cat {payload}; read x\"'")
    parser.add_argument('--self-test', action='store_true',
                        help='run only the positive control and exit')
    args = parser.parse_args(argv)

    require_sandbox()
    positive_control()                     # abort loud if the machinery is broken
    if args.self_test:
        print('positive control OK: the canary machinery fires and is detected')
        return 0
    if not args.feed_template:
        die('--feed-template is required to run PoCs (terminal-specific). '
            'See harness/README.md.')

    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pocs = args.poc or sorted(
        os.path.join(root, 'poc', d) for d in os.listdir(os.path.join(root, 'poc')))
    vulnerable = 0
    for poc_dir in pocs:
        if run_poc(poc_dir, args.feed_template):
            vulnerable += 1
    print('-- %d/%d fired the canary (vulnerable)' % (vulnerable, len(pocs)))
    return 0


if __name__ == '__main__':
    sys.exit(main())
