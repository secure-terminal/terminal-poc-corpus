# Expected behaviour: osc-code-injection-urxvt-2022

## Class

osc-code-injection -- CVE-2022-4170

## What the payload does

rxvt-unicode < 9.30 evaluates an OSC 705 (background) operating-system-command, executing injected code directly from program output -- no reflection needed.

## Verification (canary-command)

secure-terminal neutralizes this class; the harness detects a hit via the canary-command mode.

## Reference

https://nvd.nist.gov/vuln/detail/CVE-2022-4170
