# Expected behaviour: device-status-reflection-rxvt-2021

## Class

device-status-reflection -- CVE-2021-33477

## What the payload does

A colour query (OSC 10 ; ?) makes the terminal write its reply back into the shell input. In rxvt-unicode < 9.30 the reply was not newline-stripped, so the reflected bytes could inject a command. Any write-back to the pty from output is the reflection primitive this class is about.

## Verification (reflection)

secure-terminal neutralizes this class; the harness detects a hit via the reflection mode.

## Reference

https://nvd.nist.gov/vuln/detail/CVE-2021-33477
