#!/bin/bash
# Copyright (C) 2026 - 2026 ENCRYPTED SUPPORT LLC <adrelanos@whonix.org>
# See the file COPYING for copying conditions.
# AI-Assisted.

# Safe acquisition of the external conformance / test / fuzz-seed corpora listed in
# manifest.json, per the supply-chain policy (see README.md):
#   - apt suites: report the signed-repo package to install (never auto-install).
#   - git suites: clone and check out the PINNED COMMIT SHA, then verify the
#     checked-out HEAD equals the pin -- a mutable branch/tag is never trusted.
#   - vttest: prefer apt; the tarball is PGP-signed, verify the fingerprint OOB.
# Vendored trees land in conformance/vendor/<id> (git-ignored).

set -o errexit
set -o nounset
set -o pipefail
set -o errtrace
shopt -s inherit_errexit

here="$(cd -- "$(dirname -- "$0")" && pwd)"
manifest="${here}/manifest.json"
vendor="${here}/vendor"
list_only="false"
for_tests="false"

case "${1:-}" in
   --list)      list_only="true" ;;
   ## Acquire ONLY the suites the conformance harness runs (pyte, libvterm,
   ## esctest2), cloning their source even for the apt+git ones so their test
   ## trees are present. Skips the heavy corpora (ghostty, vte, ...) not needed
   ## for conformance.py.
   --for-tests) for_tests="true" ;;
esac

## Suites conformance.py needs the source tree of (their own tests + sequences).
for_tests_ids=" pyte libvterm esctest2 "

# Emit "id|method|apt_package|git_url|pin" for each suite, parsed with python3
# (JSON, no jq dependency).
rows="$(python3 -c '
import json, sys
data = json.load(open(sys.argv[1]))
for s in data["suites"]:
    print("|".join((s["id"], s["method"], s.get("apt_package", ""),
                    s.get("git_url", ""), s.get("pin", ""))))
' "${manifest}")"

acquire_git() {
   local id="$1" url="$2" pin="$3" dest="${vendor}/$1"
   if [ -z "${pin}" ]; then
      printf 'SKIP %s: no pinned SHA in the manifest (policy: pin a reviewed commit)\n' "${id}" >&2
      return 0
   fi
   if [ ! -d "${dest}/.git" ]; then
      git clone --quiet -- "${url}" "${dest}"
   fi
   # The pin must exist and become HEAD exactly -- a served-different-commit or a
   # moved branch/tag is rejected, not silently accepted.
   if ! git -C "${dest}" cat-file -e "${pin}^{commit}" 2>/dev/null; then
      git -C "${dest}" fetch --quiet origin
   fi
   git -C "${dest}" checkout --quiet --detach "${pin}"
   local head
   head="$(git -C "${dest}" rev-parse HEAD)"
   if [ "${head}" != "${pin}" ]; then
      printf 'FAIL %s: HEAD %s != pinned %s\n' "${id}" "${head}" "${pin}" >&2
      return 1
   fi
   printf 'ok   %s: pinned %s\n' "${id}" "${pin}"
}

fail=0
while IFS='|' read -r id method apt_package git_url pin; do
   [ -n "${id}" ] || continue
   ## --for-tests: clone only the conformance-harness suites, by git, whatever
   ## their manifest method (pyte/libvterm are apt+git: we want their test tree).
   if [ "${for_tests}" = "true" ]; then
      case "${for_tests_ids}" in
         *" ${id} "*) acquire_git "${id}" "${git_url}" "${pin}" || fail=1 ;;
      esac
      continue
   fi
   case "${method}" in
      apt)
         printf 'apt  %s: install the signed-repo package: apt install %s\n' \
            "${id}" "${apt_package}" ;;
      apt+git)
         printf 'apt  %s: prefer: apt install %s (git pin %s only if tests absent)\n' \
            "${id}" "${apt_package}" "${pin}" ;;
      git)
         if [ "${list_only}" = "true" ]; then
            printf 'git  %s: clone %s @ %s\n' "${id}" "${git_url}" "${pin}"
         else
            acquire_git "${id}" "${git_url}" "${pin}" || fail=1
         fi ;;
      *)
         printf 'SKIP %s: unknown method %s\n' "${id}" "${method}" >&2 ;;
   esac
done <<< "${rows}"

[ "${fail}" -eq 0 ]
