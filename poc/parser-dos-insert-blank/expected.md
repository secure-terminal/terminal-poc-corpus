# Expected behaviour: parser-dos-insert-blank

## Class

parser-dos -- CVE-2012-2738 CVE-2000-0476

## What the payload does

A control sequence with an enormous repeat/count parameter (here insert-blank-characters CSI <huge> @) drives excessive memory/CPU in VTE/xterm. A secure terminal strips the sequence and never allocates.

## Verification (denial-of-service)

secure-terminal neutralizes this class; the harness detects a hit via the denial-of-service mode.

## Reference

https://nvd.nist.gov/vuln/detail/CVE-2012-2738
