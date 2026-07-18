# Expected behaviour: notification-spoof-kitty-2022

## Class

notification-spoof -- CVE-2022-41322

## What the payload does

A desktop-notification OSC (OSC 9 / 99) carries attacker-chosen text that pops up as a trusted-looking system notification. Here the notification text is the benign canary token.

## Verification (notification-spoof)

secure-terminal neutralizes this class; the harness detects a hit via the notification-spoof mode.

## Reference

https://nvd.nist.gov/vuln/detail/CVE-2022-41322
