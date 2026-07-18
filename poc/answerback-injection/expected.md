# Expected behaviour: answerback-injection

## Class

answerback-injection -- documented class

## What the payload does

The ENQ control (0x05) makes a terminal transmit its answerback string back into the shell input. Where the answerback is attacker-settable from output, this injects a chosen string. Any write-back from output is the reflection primitive.

## Verification (reflection)

secure-terminal neutralizes this class; the harness detects a hit via the reflection mode.

## Reference

https://hdm.io/writing/termulation.txt
