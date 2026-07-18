#!/usr/bin/python3 -Bsu
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
# AI-Assisted.

"""Regenerate index.json: a flat manifest of every PoC (Exploit-DB style), so
tooling can search the corpus without reading each meta.yaml. Prints JSON to stdout.
Reads text only -- never decodes a payload.

Needs python3-yaml (Debian package). Usage: python3 tools/build_index.py > index.json"""

import json
import os
import sys

try:
    import yaml
except ImportError as exc:
    sys.stderr.write('poc-corpus: need python3-yaml: %s\n' % exc)
    raise SystemExit(2)

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FIELDS = ('id', 'title', 'class', 'cve', 'author', 'source_url', 'archive_url',
          'date', 'severity', 'mechanism', 'modified')


def main():
    poc_root = os.path.join(ROOT, 'poc')
    rows = []
    for poc_id in sorted(os.listdir(poc_root)):
        meta_path = os.path.join(poc_root, poc_id, 'meta.yaml')
        if not os.path.isfile(meta_path):
            continue
        with open(meta_path, encoding='utf-8') as fh:
            meta = yaml.safe_load(fh)
        rows.append({k: meta.get(k) for k in FIELDS})
    index = {
        'schema': 'schema/poc.schema.json',
        'count': len(rows),
        'pocs': rows,
    }
    print(json.dumps(index, indent=2, ensure_ascii=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
