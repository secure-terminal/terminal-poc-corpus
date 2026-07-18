# Expected behaviour: osc8-url-scheme-injection-2023

## Class

osc8-url-scheme-arg-injection -- CVE-2023-46321 CVE-2023-46322

## What the payload does

An OSC 8 hyperlink whose target uses a dangerous URL scheme (e.g. ssh:// with an -oProxyCommand argument). Clicking it passes attacker arguments to the scheme handler, reaching code execution -- while the visible text looks benign.

## Verification (hyperlink-mismatch)

secure-terminal neutralizes this class; the harness detects a hit via the hyperlink-mismatch mode.

## Reference

https://vin01.github.io/piptagole/escape-sequences/iterm2/hyper/url-handlers/code-execution/2024/05/21/arbitrary-url-schemes-terminal-emulators.html
