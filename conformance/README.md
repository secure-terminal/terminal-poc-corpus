# conformance corpora (safe acquisition)

External terminal **conformance / test / fuzz-seed** corpora used alongside this
PoC corpus for differential and robustness testing. This directory does **not**
vendor them; it records **how to acquire them safely** and pins them.

## Policy

1. **apt-first**: if the suite is in Debian, install the signed-repo package.
   That is the safest path (no per-suite trust work).
2. **git, pin a reviewed commit SHA**: otherwise clone the git repo and check out
   a specific **commit SHA**. Never trust a mutable branch or tag. On GitHub, tag
   GPG signatures are typically **web-flow (browser), so reject** them as
   authenticity evidence.
3. **Verify a real maintainer fingerprint out-of-band** where one exists. Among
   these, only **vttest** offers a genuine maintainer GPG key (Thomas E. Dickey,
   fingerprint `19882D92 DDA4C400 C22C0D56 CC2AF447 2167BE03`).
4. **No unsigned tarballs.** The only tarball in play (vttest) is PGP-signed, and
   its apt package is preferable anyway.

## Files

- `manifest.json`: each suite: purpose, license, method (`apt` / `apt+git` /
  `git`), the apt package and/or git URL, and the **pinned SHA**. The pins are the
  HEAD at manifest time, so **review the pinned commit before trusting it.**
- `acquire.sh`: enforces the policy. It reports the apt package for `apt` suites;
  for `git` suites it clones and checks out the pinned SHA and **verifies HEAD
  equals the pin** (a served-different or moved commit is rejected). Vendored trees
  land in `vendor/<id>` (git-ignored).

```
./acquire.sh --list     # show the acquisition plan (no network)
./acquire.sh            # apt suites: print the package; git suites: clone @ pin
```

## Shortlist (why each)

vttest (conformance baseline), esctest2 (thorough automated conformance), pyte +
libvterm (small parser corpora that double as known-good reference parsers for
differential testing), Ghostty (aggressive real-world edge cases), alacritty/vte +
vt100-rust (parser fuzz targets + seed corpus), vtebench (throughput/DoS stress,
optional), terminalguide (behaviour reference data). See `manifest.json` notes.

**Deferred:** `termless` (2026, single-maintainer, npm transitive-dep supply
chain, so it fails apt-first; if ever used, git-SHA-pin + vendor and audit the
lockfile, never a live `npm install`).
