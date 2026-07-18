# Expected behaviour: osc8-hyperlink-phishing

## Class

OSC 8 hyperlink text/target mismatch (phishing).
(publicly documented class, no dedicated CVE).

## What the payload does

An OSC 8 hyperlink whose VISIBLE text (https://bank.example) differs from its actual TARGET (https://attacker.example/...). A user clicking the trusted-looking text is sent elsewhere. Carries no executable content.

## Verification (hyperlink-mismatch)

Detect a hit via: link target contains POC-CANARY while visible text differs.

secure-terminal neutralizes this class, so the deception/exfil does not occur.

## Reference

https://gist.github.com/egmontkob/eb114294efbcd5adb1944c9f3cb5feda
