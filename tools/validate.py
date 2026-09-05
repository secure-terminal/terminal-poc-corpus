#!/usr/bin/python3 -Bsu
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
# AI-Assisted.

"""Validate every poc/<id>/meta.yaml against schema/poc.schema.json, and check the
cross-file invariants the schema cannot express. Reads text only -- never decodes a
payload. Exit 0 if all valid, 1 otherwise.

Needs python3-yaml and python3-jsonschema (Debian packages)."""

import base64
import binascii
import json
import os
import re
import sys

try:
    import yaml
    import jsonschema
except ImportError as exc:
    sys.stderr.write('poc-corpus: need python3-yaml + python3-jsonschema: %s\n' % exc)
    raise SystemExit(2)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _decode_hex(path):
    """Decode a payload.hex to raw bytes (whitespace + '#' comments ignored)."""
    body = []
    with open(path, encoding='ascii') as handle:
        for line in handle:
            body.append(''.join(line.split('#', 1)[0].split()))
    return binascii.unhexlify(''.join(body))


def _payload_is_hex(path):
    """A payload.hex must contain ONLY hex (whitespace + '#' comments ignored), so
    the repo stays read-safe -- no raw escape bytes ever land in a payload file."""
    try:
        return bool(_decode_hex(path))
    except (binascii.Error, ValueError):
        return False


def _payload_b64_matches_hex(poc_dir):
    """payload.b64 is a GENERATED base64 mirror of payload.hex (see
    tools/build_payloads.py). It MUST exist and decode to the exact same bytes, or the
    website/user b64 path and the harness hex path would silently test different bytes.
    A stale or missing mirror fails here -- run tools/build_payloads.py to regenerate."""
    b64_path = os.path.join(poc_dir, 'payload.b64')
    if not os.path.isfile(b64_path):
        return ['missing payload.b64 (run tools/build_payloads.py)']
    with open(b64_path, 'rb') as handle:
        data = handle.read()
    # Byte-exact against what tools/build_payloads.py writes: base64.encodebytes output
    # (base64 alphabet + '\n' line wrapping, nothing else). Comparing the whole file --
    # not a whitespace-stripped decode -- enforces sync AND read-safety in one step: any
    # stray byte (a C0 control that `bytes.split()` would drop but GNU `base64 -d` chokes
    # on, or garbage) makes the file differ, so it cannot pass. This keeps the documented
    # `base64 -d payload.b64` byte-identical to the harness hex path.
    expected = base64.encodebytes(_decode_hex(os.path.join(poc_dir, 'payload.hex')))
    if data != expected:
        if not re.fullmatch(rb'[A-Za-z0-9+/=\n]*', data):
            return ['payload.b64 has bytes outside base64 + newline '
                    '(read-safety violation; run tools/build_payloads.py)']
        return ['payload.b64 out of sync with payload.hex (run tools/build_payloads.py)']
    return []


# A fired canary-forked PoC may ONLY perform the safe canary action (write the marker),
# never anything that could harm a tester. A hit here means the PoC was not sanitized
# (see ../SAFETY.md). This is a first-line lint (a denylist can never be complete; the
# real gate is the per-PoC human / ai-review), so it errs toward catching known-harmful.
#
# Command NAMES are matched as whole words so ordinary text ("confirm", "medieval",
# "perform", "sync") does not false-trip the short ones; PATHS/OPERATORS are substrings.
_HARMFUL_CMD = (
    b'rm', b'rmdir', b'dd', b'mkfs', b'mkswap', b'nc', b'ncat', b'curl', b'wget',
    b'telnet', b'shred', b'chown', b'chmod', b'eval', b'crontab', b'systemctl',
    b'pkill', b'reboot', b'shutdown', b'poweroff', b'sudo', b'subprocess',
)
_HARMFUL_CMD_RE = re.compile(
    rb'\b(?:' + b'|'.join(re.escape(c) for c in _HARMFUL_CMD) + rb')\b')
_HARMFUL_SUB = (
    b'dd if=', b'dd of=', b' of=/dev', b'/dev/sd', b'/dev/nvme', b'/dev/tcp',
    b'/dev/udp', b':(){', b'| sh', b'|sh', b'| bash', b'|bash', b'os.system',
    b'>/etc/', b'> /etc/', b'/etc/passwd', b'/etc/shadow',
)


def _payload_safety(payload_path, meta):
    """Enforce the sanitization invariant (../SAFETY.md): a canary-forked payload may
    ONLY do the safe canary action. Decode the (inert) bytes and check they carry NO
    harmful command fragment and DO reference the canary convention -- a first-line
    lint that backs the per-PoC human / ai-review sanitization gate."""
    problems = []
    try:
        raw = _decode_hex(payload_path)
    except (binascii.Error, ValueError):
        return ['payload.hex is not decodable for the safety check']
    low = raw.lower()
    for hit in sorted(set(_HARMFUL_CMD_RE.findall(low))):
        problems.append('payload carries a HARMFUL command %r (not sanitized)'
                        % hit.decode('ascii'))
    for frag in _HARMFUL_SUB:
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
                problems.extend(_payload_b64_matches_hex(poc_dir))
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
