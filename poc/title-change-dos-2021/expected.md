# Expected behaviour: title-change-dos-2021

## Class

title-change-dos -- CVE-2021-28847 CVE-2021-28848 CVE-2021-32198 CVE-2021-33500 CVE-2021-42095

## What the payload does

A flood of rapid window-title changes (OSC 0) exhausts CPU/memory and freezes several terminals (CyberArk 2021). A secure terminal that interprets no OSC processes it as inert stripped text in bounded time.

## Verification (denial-of-service)

secure-terminal neutralizes this class; the harness detects a hit via the denial-of-service mode.

## Reference

https://www.cyberark.com/resources/threat-research-blog/dont-trust-this-title-abusing-terminal-emulators-with-ansi-escape-characters
