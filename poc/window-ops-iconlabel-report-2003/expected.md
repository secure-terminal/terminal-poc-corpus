# Expected behaviour: window-ops-iconlabel-report-2003

## Class

window-ops -- CVE-2003-0065

## What the payload does

A window-operation variant of the echoback class: set the icon label via OSC 1, then request it back via CSI 20 t. A vulnerable terminal reflects the icon label into the shell input.

## Verification (canary-command)

secure-terminal neutralizes this class; the harness detects a hit via the canary-command mode.

## Reference

https://hdm.io/writing/termulation.txt
