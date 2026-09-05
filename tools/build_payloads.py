#!/usr/bin/python3 -Bsu
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
# AI-Assisted.

"""Regenerate every poc/<id>/payload.b64 from its payload.hex.

payload.b64 is a GENERATED, browse-safe base64 mirror of payload.hex. It exists so a
user can decode a payload with one stock command -- `base64 -d payload.b64` -- with no
pipeline. payload.hex stays the single source of truth (human-inspectable, harness
input); this script only derives the b64 from it. tools/validate.py fails if any
payload.b64 is missing or out of sync, so the two can never silently drift.

Like payload.hex, payload.b64 carries no raw control bytes, so the repo stays read-safe.
Reads text only -- never feeds a payload to a terminal."""

import base64
import binascii
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _decode_hex(path):
    """Decode a payload.hex to raw bytes (whitespace + '#' comments ignored)."""
    body = []
    with open(path, encoding='ascii') as handle:
        for line in handle:
            body.append(''.join(line.split('#', 1)[0].split()))
    return binascii.unhexlify(''.join(body))


def main():
    poc_root = os.path.join(ROOT, 'poc')
    written = 0
    errors = 0
    for poc_id in sorted(os.listdir(poc_root)):
        hex_path = os.path.join(poc_root, poc_id, 'payload.hex')
        if not os.path.isfile(hex_path):
            continue
        try:
            encoded = base64.encodebytes(_decode_hex(hex_path))  # 76-col wrapped
        except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
            # Name the offending PoC instead of a bare traceback, and keep going so one
            # bad contribution does not leave every later payload.b64 stale.
            sys.stderr.write('build_payloads: %s: cannot decode payload.hex: %s\n'
                             % (poc_id, exc))
            errors += 1
            continue
        with open(os.path.join(poc_root, poc_id, 'payload.b64'), 'wb') as out:
            out.write(encoded)
        written += 1
    print('wrote %d payload.b64 file(s)' % written)
    if errors:
        sys.stderr.write('build_payloads: %d payload.hex file(s) failed to decode\n'
                         % errors)
    return 1 if errors else 0


if __name__ == '__main__':
    sys.exit(main())
