# Expected behaviour: homoglyph-domain-install-2021

## Class

Homoglyph domain deception (IDN homograph), applied to a copy-paste install command.
CVE CVE-2021-42694

## What the payload does

The URL an install one-liner would tell you to fetch -- `https://ex<U+0430>mple.com/get.sh` --
whose domain carries a Cyrillic homoglyph (the `a` is U+0430, not Latin U+0061). A terminal
that renders the glyph shows a clean-looking `example.com`; the bytes are a different,
attacker-registrable internationalized domain, so a `... | sudo bash` built around it would
fetch and execute from the attacker's host. The payload here is only the deceptive URL -- no
runnable command (the safety net for a display-deception PoC); the harm is the wrong domain.

## Verification (display-deception)

Detect a hit via: the non-ASCII homoglyph survives the render (U+0430 present).

secure-terminal neutralizes this class: strip mode replaces the look-alike with `_`
(`ex_mple.com`), detail mode names it (`ex<U+0430 CYRILLIC SMALL LETTER A>mple.com`), and
paste drops it with a "1 non-ASCII character" warning -- so the disguised domain cannot
survive to be run.

## Reference

https://trojansource.codes/ and https://en.wikipedia.org/wiki/IDN_homograph_attack
