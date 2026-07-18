#!/usr/bin/python3 -Bsu
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
# AI-Assisted.

"""Validate every poc/<id>/meta.yaml against schema/poc.schema.json, and check the
cross-file invariants the schema cannot express. Reads text only -- never decodes a
payload. Exit 0 if all valid, 1 otherwise.

Needs python3-yaml and python3-jsonschema (Debian packages)."""

import binascii
import json
import os
import sys

try:
    import yaml
    import jsonschema
except ImportError as exc:
    sys.stderr.write('poc-corpus: need python3-yaml + python3-jsonschema: %s\n' % exc)
    raise SystemExit(2)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _payload_is_hex(path):
    """A payload.hex must contain ONLY hex (whitespace + '#' comments ignored), so
    the repo stays read-safe -- no raw escape bytes ever land in a payload file."""
    body = []
    with open(path, encoding='ascii') as handle:
        for line in handle:
            body.append(''.join(line.split('#', 1)[0].split()))
    joined = ''.join(body)
    if not joined:
        return False
    try:
        binascii.unhexlify(joined)
        return True
    except (binascii.Error, ValueError):
        return False


# Command fragments a canary-forked payload must NEVER contain: a fired PoC may only
# perform the safe canary action (write the marker), never anything that could harm a
# tester. A hit here means the PoC was not properly sanitized (see ../SAFETY.md).
_HARMFUL = (
    b'rm ', b'rm\t', b'rmdir', b'mkfs', b'dd if=', b'dd of=', b' of=/dev',
    b'curl', b'wget', b'ncat', b'nc -', b'telnet', b'/dev/sd', b'/dev/nvme',
    b':(){', b'chmod +s', b'chmod u+s', b'chown ', b'shred', b'mkswap',
    b'| sh', b'|sh', b'| bash', b'|bash', b'eval ', b'os.system', b'subprocess',
    b'>/etc/', b'> /etc/', b'sudo ', b'/etc/passwd', b'/etc/shadow', b'crontab',
    b'systemctl', b'pkill', b'reboot', b'shutdown', b'poweroff',
)


def _payload_safety(payload_path, meta):
    """Enforce the sanitization invariant (../SAFETY.md): a canary-forked payload may
    ONLY do the safe canary action. Decode the (inert) bytes and check they carry NO
    harmful command fragment and DO reference the canary convention -- a first-line
    lint that backs the per-PoC human / ai-review sanitization gate."""
    problems = []
    body = []
    with open(payload_path, encoding='ascii') as handle:
        for line in handle:
            body.append(''.join(line.split('#', 1)[0].split()))
    try:
        raw = binascii.unhexlify(''.join(body))
    except (binascii.Error, ValueError):
        return ['payload.hex is not decodable for the safety check']
    low = raw.lower()
    for frag in _HARMFUL:
        if frag in low:
            problems.append('payload carries a HARMFUL fragment %r (not sanitized)'
                            % frag.decode('ascii'))
    # A canary-command PoC MUST reference the canary convention (so a fired injection
    # only runs the safe marker-write). The non-command modes (display-deception,
    # clipboard-exfil, hyperlink-mismatch) carry no shell command at all, so they are
    # inherently harmless and this check does not apply -- the harmful-fragment scan
    # above is still the safety net.
    if meta.get('verification', 'canary-command') == 'canary-command':
        canary = (meta.get('canary') or '').encode('ascii', 'replace')
        if b'POC_CANARY' not in raw and not (canary and canary in raw):
            problems.append('canary-command payload references neither $POC_CANARY nor '
                            'its canary token (a fired PoC must perform the safe action)')
    return problems


def main():
    with open(os.path.join(ROOT, 'schema', 'poc.schema.json'), encoding='utf-8') as fh:
        schema = json.load(fh)
    validator = jsonschema.Draft202012Validator(schema)

    poc_root = os.path.join(ROOT, 'poc')
    errors = 0
    ids = sorted(d for d in os.listdir(poc_root)
                 if os.path.isdir(os.path.join(poc_root, d)))
    for poc_id in ids:
        poc_dir = os.path.join(poc_root, poc_id)
        meta_path = os.path.join(poc_dir, 'meta.yaml')
        if not os.path.isfile(meta_path):
            print('FAIL %s: missing meta.yaml' % poc_id)
            errors += 1
            continue
        with open(meta_path, encoding='utf-8') as fh:
            meta = yaml.safe_load(fh)
        problems = [e.message for e in validator.iter_errors(meta)]
        if meta.get('id') != poc_id:
            problems.append("id %r != directory name %r" % (meta.get('id'), poc_id))
        if meta.get('payload_encoding') == 'hex':
            payload = os.path.join(poc_dir, 'payload.hex')
            if not os.path.isfile(payload):
                problems.append('missing payload.hex')
            elif not _payload_is_hex(payload):
                problems.append('payload.hex is not valid hex (read-safety violation)')
            else:
                problems.extend(_payload_safety(payload, meta))
        if not os.path.isfile(os.path.join(poc_dir, 'expected.md')):
            problems.append('missing expected.md')
        if problems:
            errors += 1
            for p in problems:
                print('FAIL %s: %s' % (poc_id, p))
        else:
            print('ok   %s' % poc_id)

    print('-- %d PoC(s), %d with errors' % (len(ids), errors))
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
