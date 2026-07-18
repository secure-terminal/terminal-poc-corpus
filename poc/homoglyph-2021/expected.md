# Expected behaviour: homoglyph-2021

## Class

Homoglyph identifier deception.
CVE CVE-2021-42694

## What the payload does

A visually identical code point (here Cyrillic U+0430 for Latin a) makes one identifier look like another ("admin" vs "<U+0430>dmin") while being a distinct string. Carries no executable content; the harm is pure visual deception.

## Verification (display-deception)

Detect a hit via: non-ASCII homoglyph present (U+0430).

secure-terminal neutralizes this class, so the deception/exfil does not occur.

## Reference

https://trojansource.codes/
