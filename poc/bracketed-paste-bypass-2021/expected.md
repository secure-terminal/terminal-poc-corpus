# Expected behaviour: bracketed-paste-bypass-2021

## Class

bracketed-paste-bypass -- CVE-2021-31701 CVE-2021-37326 CVE-2021-40147

## What the payload does

Pasted content that embeds the end-bracketed-paste sequence (CSI 201 ~) tricks the terminal into ending paste mode early, so the rest of the paste is treated as typed input and runs. A secure terminal sanitizes paste to ASCII and strips the escape, so the guard cannot be broken.

## Verification (paste-bypass)

secure-terminal neutralizes this class; the harness detects a hit via the paste-bypass mode.

## Reference

https://www.cyberark.com/resources/threat-research-blog/dont-trust-this-title-abusing-terminal-emulators-with-ansi-escape-characters
