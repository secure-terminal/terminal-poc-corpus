# Expected behaviour: regis-decoder-overflow-2023

## Class

regis-decoder -- CVE-2023-40359

## What the payload does

A ReGIS char-set-name reporting sequence overruns a buffer in xterm (triggerable even via a crafted process name in a listing). A secure terminal never runs a ReGIS decoder (it strips the DCS).

## Verification (decoder-crash)

secure-terminal neutralizes this class; the harness detects a hit via the decoder-crash mode.

## Reference

https://nvd.nist.gov/vuln/detail/CVE-2023-40359
