#!/usr/bin/python3
## Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
## See the file COPYING for copying conditions.

## AI-Assisted

"""
Run the reviewed external conformance / reference suites against secure-terminal,
two complementary ways:

  Part A -- reference-parser self-tests. The parsers secure-terminal relies on
    (pyte, its TUI engine) or differentials against (libvterm) must pass THEIR OWN
    test suite at the reviewed, pinned commit. This proves the reference is intact
    and behaves as reviewed before we trust it for anything else.

  Part B -- security invariant across the spec surface. secure-terminal is
    deliberately NOT a conformant emulator: it interprets nothing in line mode and
    only a confined subset in TUI mode. So a pass/fail conformance score is
    meaningless. What IS meaningful, and what this asserts, is that every escape
    sequence these suites exercise -- the whole VT/xterm repertoire, far past the
    21 hand-picked corpus PoCs -- upholds the three invariants when fed to
    secure-terminal:
      1. ZERO bytes are written back to the pseudo-terminal (the reflection /
         echoback / answerback class stays closed by construction);
      2. the line-mode rendered text is pure printable ASCII (nothing invisible,
         bidi or homoglyph is smuggled onto the screen);
      3. no input crashes the sanitizer or the confined screen model.

The suites are NOT vendored here; they are acquired safely (apt-first, else a
pinned reviewed commit SHA) by conformance/acquire.sh, or found via env. A suite
that cannot be located is SKIPped (never a hard failure), so the run degrades
gracefully in a minimal environment. Runs confined only (sandbox / CI), like the
adversarial harness, because Part B feeds live escape sequences.
"""

import os
import re
import sys
import glob
import subprocess

_HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
_CORPUS_DIR = os.path.dirname(_HARNESS_DIR)
if _HARNESS_DIR not in sys.path:
    sys.path.insert(0, _HARNESS_DIR)

# Reuse the vetted secure-terminal driving machinery (headless widget, the
# output-path feed, and the pty write-back capture) from the adversarial harness.
import adversarial as adv          # noqa: E402


def _log(msg):
    sys.stdout.write(msg + '\n')
    sys.stdout.flush()


# ---- locating the acquired suites ------------------------------------------

def _suite_dir(suite_id, env_var):
    """Where a suite's source tree lives: an explicit env override, else the
    vendor/ dir acquire.sh populates. None if not present."""
    cand = []
    val = os.environ.get(env_var)
    if val:
        cand.append(val)
    cand.append(os.path.join(_CORPUS_DIR, 'conformance', 'vendor', suite_id))
    for path in cand:
        if path and os.path.isdir(path):
            return path
    return None


# ---- Part A: reference-parser self-tests -----------------------------------

def selftest_pyte():
    """Run pyte's own test suite at the reviewed pin. pyte is secure-terminal's
    TUI screen engine, so its semantics are the ones our grid inherits."""
    src = _suite_dir('pyte', 'PYTE_SRC')
    if not src or not os.path.isdir(os.path.join(src, 'tests')):
        _log('  SKIP  pyte self-test (source not acquired; run conformance/acquire.sh)')
        return None
    env = dict(os.environ)
    # Test the CHECKOUT, not any system-installed pyte.
    env['PYTHONPATH'] = src + os.pathsep + env.get('PYTHONPATH', '')
    try:
        proc = subprocess.run([sys.executable, '-m', 'pytest', '-q',
                               os.path.join(src, 'tests')],
                              cwd=src, env=env, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=600, check=False)
    except subprocess.TimeoutExpired:
        _log('  FAIL  pyte self-test timed out')     # a hang is a failure, not a hung harness
        return False
    ok = proc.returncode == 0
    tail = (proc.stdout or proc.stderr).strip().splitlines()[-1:] or ['(no output)']
    _log('  %s  pyte self-test: %s' % ('PASS' if ok else 'FAIL', tail[0]))
    return ok


def selftest_libvterm():
    """Run libvterm's own conformance harness at the reviewed pin, best-effort:
    it needs a C toolchain + perl, so a build failure is a SKIP, not a FAIL."""
    src = _suite_dir('libvterm', 'LIBVTERM_SRC')
    if not src or not os.path.isfile(os.path.join(src, 'Makefile')):
        _log('  SKIP  libvterm self-test (source not acquired; run conformance/acquire.sh)')
        return None
    if not any(os.access(os.path.join(p, 'make'), os.X_OK)
               for p in os.environ.get('PATH', '').split(os.pathsep) if p):
        _log('  SKIP  libvterm self-test (no make in PATH)')
        return None
    try:
        proc = subprocess.run(['make', 'test'], cwd=src, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=600, check=False)
    except subprocess.TimeoutExpired:
        _log('  FAIL  libvterm self-test timed out')  # a hang is a failure, not a skip
        return False
    except OSError as exc:
        _log('  SKIP  libvterm self-test (build error: %s)' % exc)
        return None
    # SKIP only on DEFINITIVE missing-toolchain evidence; do not let a broad match
    # ("No such file", "cc:") mask a genuine test failure as a skip.
    if proc.returncode != 0 and re.search(r'(command not found|Error 127)',
                                          proc.stdout + proc.stderr):
        _log('  SKIP  libvterm self-test (toolchain unavailable)')
        return None
    ok = proc.returncode == 0
    _log('  %s  libvterm self-test (make test rc=%d)'
         % ('PASS' if ok else 'FAIL', proc.returncode))
    return ok


# ---- Part B: security invariant over the spec surface ----------------------

# A curated baseline of the capability / reporting queries -- the highest-value
# reflection-class sequences -- so Part B is meaningful even before any suite is
# harvested. Bytes, exactly as a program would emit them. None is a canary
# command; each is a QUERY a vulnerable terminal would answer (writing its reply
# onto our input). secure-terminal must answer none of them.
_BASELINE_QUERIES = (
    b'\x1b[c',              # DA1  primary device attributes
    b'\x1b[>c',             # DA2  secondary DA
    b'\x1b[=c',             # DA3  tertiary DA
    b'\x1b[0c',             # DA1 with parameter
    b'\x1b[5n',             # DSR  device status
    b'\x1b[6n',             # CPR  cursor position report
    b'\x1b[?6n',            # DECXCPR
    b'\x1bP$q"p\x1b\\',     # DECRQSS  request DECSCL
    b'\x1bP$qm\x1b\\',      # DECRQSS  request SGR
    b'\x1b[>0q',            # XTVERSION  terminal name/version
    b'\x1bP+q544e\x1b\\',   # XTGETTCAP  request "TN"
    b'\x05',               # ENQ  answerback
    b'\x1b[21t',            # report window title (dtterm)
    b'\x1b[14t',            # report text-area size in pixels
    b'\x1b[18t',            # report text-area size in chars
    b'\x1b]10;?\x07',       # OSC 10  query foreground colour
    b'\x1b]11;?\x07',       # OSC 11  query background colour
    b'\x1b]4;0;?\x07',      # OSC 4   query palette entry
    b'\x1b]52;c;?\x07',     # OSC 52  clipboard READ query
    b'\x1bZ',               # DECID  (obsolete identify)
)

# Escape-bearing byte-string literal inside a suite's source, e.g. "\x1b[3g" or
# b"\033[H". We harvest these so Part B exercises the actual sequences the suites
# assert on, not only our baseline.
_LIT_RE = re.compile(rb'''["']((?:\\x1b|\\033|\\e|\\u001b)[^"'\\]*(?:\\.[^"'\\]*)*)["']''',
                     re.IGNORECASE)
_ESC_ALIASES = ((rb'\\x1b', b'\x1b'), (rb'\\033', b'\x1b'), (rb'\\e', b'\x1b'),
                (rb'\\u001b', b'\x1b'))
_SIMPLE_ESCAPES = {b'\\n': b'\n', b'\\r': b'\r', b'\\t': b'\t', b'\\a': b'\x07',
                   b'\\b': b'\x08', b'\\f': b'\x0c', b'\\\\': b'\\',
                   b'\\"': b'"', b"\\'": b"'"}


def _unescape(lit):
    """Turn a harvested source literal (with \\x1b, \\033, \\n ...) into raw bytes.
    Best-effort: an unrecognised escape is dropped, never executed."""
    for alias, real in _ESC_ALIASES:
        lit = re.sub(alias, real.decode('latin-1').encode('latin-1'), lit,
                     flags=re.IGNORECASE)
    out = bytearray()
    i = 0
    while i < len(lit):
        if lit[i:i + 1] == b'\\':
            two = lit[i:i + 2]
            if two.lower() == b'\\x' and len(lit) >= i + 4:
                try:
                    out.append(int(lit[i + 2:i + 4], 16))
                    i += 4
                    continue
                except ValueError:
                    pass
            if two in _SIMPLE_ESCAPES:
                out += _SIMPLE_ESCAPES[two]
                i += 2
                continue
            i += 2                       # unknown backslash escape -> drop
            continue
        out += lit[i:i + 1]
        i += 1
    return bytes(out)


# esctest2 builds its sequences programmatically (through the single escio.Write
# choke point), so there is little to harvest as a literal. Instead, in an ISOLATED
# subprocess (escio opens the real stdout fd on import), import esccmd with Write
# intercepted and reads stubbed, invoke every command function that needs no
# argument, and emit the captured sequences as hex. Fully defensive: any failure
# yields nothing, so a future esctest2 layout change degrades to zero, never a crash.
_ESCTEST2_CAPTURE = r'''
import sys, os, inspect
sys.argv = ['x']
try:
    import escio
    recorded = []
    def _cap(s, sideChannelOk=True):
        recorded.append(s.encode('latin-1', 'replace') if isinstance(s, str) else s)
    escio.Write = _cap
    for _n in dir(escio):
        if _n.startswith(('Read', 'Expect')):
            setattr(escio, _n, lambda *a, **k: "")
    import esccmd
    for _nm, _fn in inspect.getmembers(esccmd, inspect.isfunction):
        try:
            _sig = inspect.signature(_fn)
            if all(p.default is not inspect.Parameter.empty
                   or p.kind in (p.VAR_POSITIONAL, p.VAR_KEYWORD)
                   for p in _sig.parameters.values()):
                _fn()
        except Exception:
            pass
    for _s in recorded:
        if b'\x1b' in _s and len(_s) <= 256:
            sys.stdout.write(_s.hex() + '\n')
except Exception:
    pass
'''


def _harvest_esctest2():
    src = _suite_dir('esctest2', 'ESCTEST2_SRC')
    if not src:
        return []
    esctest = os.path.join(src, 'esctest')
    if not os.path.isdir(esctest):
        return []
    try:
        proc = subprocess.run([sys.executable, '-c', _ESCTEST2_CAPTURE],
                              cwd=esctest, stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=60, check=False)
    except (OSError, subprocess.SubprocessError):
        return []
    seqs = set()
    for line in proc.stdout.splitlines():
        line = line.strip()
        try:
            seqs.add(bytes.fromhex(line))
        except ValueError:
            continue
    return sorted(seqs)


def _harvest(suite_id, env_var, patterns):
    """Pull escape-bearing literals out of a suite's source files. Bounded, and
    silent (returns []) when the suite is not present."""
    src = _suite_dir(suite_id, env_var)
    if not src:
        return []
    seqs = set()
    for pat in patterns:
        for path in glob.glob(os.path.join(src, pat), recursive=True):
            try:
                with open(path, 'rb') as handle:
                    data = handle.read(2_000_000)
            except OSError:
                continue
            for m in _LIT_RE.findall(data):
                raw = _unescape(m)
                if b'\x1b' in raw and len(raw) <= 256:
                    seqs.add(raw)
    return sorted(seqs)


def _check_invariants(seq):
    """Feed one sequence to secure-terminal; return a list of invariant violations
    (empty == clean). Reuses the adversarial harness observables."""
    problems = []
    try:
        sent = adv._obs_writeback(seq)               # pylint: disable=protected-access
    except Exception as exc:                         # noqa: BLE001
        return ['crash in write-back path: %r' % (exc,)]
    if sent:
        joined = b''.join(b if isinstance(b, bytes) else bytes(b) for b in sent)
        problems.append('wrote %d bytes back to pty: %r' % (len(joined), joined[:40]))
    try:
        text = adv._obs_render_strip(seq)            # pylint: disable=protected-access
    except Exception as exc:                         # noqa: BLE001
        problems.append('crash in line render: %r' % (exc,))
        return problems
    # secure-terminal's line mode deliberately passes through printable ASCII plus
    # tab, newline, and the two line-LOCAL cursor controls it documents: backspace
    # (0x08) and carriage return (0x0D). Those are safe (they cannot cross a line to
    # rewrite committed output). Anything else non-printable -- other C0/C1, or any
    # codepoint > 0x7e (the invisible / bidi / homoglyph classes) -- is a violation.
    smuggled = [c for c in text
                if not (0x20 <= ord(c) <= 0x7e or c in '\t\n\r\x08')]
    if smuggled:
        problems.append('smuggled non-ASCII/control in rendered text: %r'
                        % (''.join(smuggled[:8]),))
    return problems


def run_invariants():
    """Part B: assert the three invariants over the baseline queries plus every
    sequence harvested from the acquired suites."""
    corpus = {'baseline': list(_BASELINE_QUERIES)}
    corpus['esctest2'] = _harvest_esctest2()
    corpus['libvterm'] = _harvest('libvterm', 'LIBVTERM_SRC',
                                  ['t/*.test', 't/**/*.test'])
    corpus['pyte'] = _harvest('pyte', 'PYTE_SRC',
                              ['tests/**/*.py', 'tests/*.py'])

    total = failures = 0
    for source, seqs in corpus.items():
        if not seqs:
            acquired = source == 'baseline' or _suite_dir(
                source, source.upper() + '_SRC') is not None
            why = ('acquired, no literal escapes harvested (programmatic DSL)'
                   if acquired else 'suite not acquired')
            _log('  ....  %-9s no sequences (%s)' % (source, why))
            continue
        bad = 0
        for seq in seqs:
            total += 1
            problems = _check_invariants(seq)
            if problems:
                bad += 1
                failures += 1
                _log('  FAIL  %-9s %r -> %s' % (source, seq[:32], '; '.join(problems)))
        _log('  %s  %-9s %d sequences, %d violations'
             % ('PASS' if bad == 0 else 'FAIL', source, len(seqs), bad))
    _log('  invariant totals: %d sequences, %d violations' % (total, failures))
    return failures == 0


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(
        prog='conformance',
        description='Run reviewed conformance/reference suites against '
                    'secure-terminal: reference-parser self-tests + a security '
                    'invariant over the spec surface.')
    # Mutually exclusive: supplying both would disable BOTH parts and exit 0 -- a
    # false green. argparse rejects the combination for us.
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--self-tests-only', action='store_true',
                      help='Part A only (reference-parser self-tests).')
    mode.add_argument('--invariants-only', action='store_true',
                      help='Part B only (security invariant over sequences).')
    args = parser.parse_args(argv)

    run_part_a = not args.invariants_only
    run_part_b = not args.self_tests_only

    # Only Part B feeds live escape sequences to secure-terminal, so only it needs
    # the confinement gate and the secure-terminal positive control. Part A runs
    # only the external parsers' own tests (no terminal, no secure-terminal), so a
    # self-tests-only run must not be blocked by either.
    if run_part_b:
        adv.require_confined()
        adv.positive_control()          # fail loud if the machinery is broken

    ok = True
    if run_part_a:
        _log('== Part A: reference-parser self-tests ==')
        results = [selftest_pyte(), selftest_libvterm()]
        if any(r is False for r in results):
            ok = False
        if all(r is None for r in results):
            _log('  (no reference suites acquired; run conformance/acquire.sh first)')
    if run_part_b:
        _log('== Part B: security invariant over the spec surface ==')
        if not run_invariants():
            ok = False

    _log('conformance: %s' % ('OK' if ok else 'FAILURES'))
    return 0 if ok else 1


if __name__ == '__main__':
    sys.exit(main())
