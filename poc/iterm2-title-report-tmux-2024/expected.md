# Expected behaviour: iterm2-title-report-tmux-2024

## Class

title-report-echoback -- CVE-2024-38395 CVE-2024-38396

## What the payload does

The 2003 title-report echoback resurfaced in iTerm2 < 3.5.2: an unfiltered window-title report, combined with default tmux integration, reflects the attacker-set title into the shell and runs it (no Enter needed).

## Verification (canary-command)

secure-terminal neutralizes this class; the harness detects a hit via the canary-command mode.

## Reference

https://vin01.github.io/piptagole/escape-sequences/iterm2/rce/2024/06/16/iterm2-rce-window-title-tmux-integration.html
