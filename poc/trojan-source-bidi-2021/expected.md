# Expected behaviour: trojan-source-bidi-2021

## Class

Trojan-Source bidirectional-override deception.
CVE CVE-2021-42574

## What the payload does

Bidirectional-override control characters (U+202E RLO, U+202C PDF, and the isolates U+2066-2069) make the RENDERED order of the text differ from its LOGICAL byte order, so a reviewer and a compiler/shell "see" different things. Carries no executable content; the harm is pure visual deception.

## Verification (display-deception)

Detect a hit via: rendered-order != logical-order (U+202E present).

secure-terminal neutralizes this class, so the deception/exfil does not occur.

## Reference

https://trojansource.codes/
