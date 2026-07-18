# Expected behaviour: charset-shift-deception

## Class

charset-shift-deception -- documented class

## What the payload does

A charset shift (ESC ( 0, DEC special graphics) makes plain ASCII render as line-drawing glyphs, so the same bytes look like something else. Here the canary token is wrapped in a shift so it would render as line-drawing on a terminal that honours it.

## Verification (charset-deception)

secure-terminal neutralizes this class; the harness detects a hit via the charset-deception mode.

## Reference

https://secure-terminal.github.io
