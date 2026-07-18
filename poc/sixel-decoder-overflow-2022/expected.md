# Expected behaviour: sixel-decoder-overflow-2022

## Class

sixel-decoder -- CVE-2022-24130

## What the payload does

A Sixel image with a repeat operator that overruns a bounds check in xterm <= 370 set_sixel, corrupting memory. A secure terminal never runs a Sixel decoder (it strips the DCS), so no decoder executes.

## Verification (decoder-crash)

secure-terminal neutralizes this class; the harness detects a hit via the decoder-crash mode.

## Reference

https://dgl.cx/2023/09/ansi-terminal-security
