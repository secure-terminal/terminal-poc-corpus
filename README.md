# terminal-poc-corpus

A **defensive, machine-readable corpus** of publicly-disclosed terminal-emulator
attack payloads: escape-sequence injection / reflection (answerback, title-report,
DECRQSS, DSR, font-query echoback), clipboard read/write (OSC 52), hyperlink and
URL-scheme abuse (OSC 8), window operations, screen-dump-to-file, decoder bugs
(Sixel, ReGIS), and display-deception classes (Trojan-Source bidi, homoglyphs,
bracketed-paste bypass).

It exists because the conformance suites (esctest, vttest, terminalguide) carry no
security or attribution metadata, and the security PoCs themselves are scattered
across CVEs, blog posts, and mailing-list archives. This collects them in one
CVE-tagged, attributed, machine-readable, **safe** format.

> **Read [SAFETY.md](SAFETY.md) first.** Payloads are stored hex-encoded (reading
> the repo is safe), canary-forked (a fired payload only writes a harmless marker),
> and meant to run in a **sandbox VM only** via the harness. This is a test suite,
> not a weapon.

## Layout

```
SAFETY.md                     the safety model (read this first)
schema/poc.schema.json        JSON Schema every meta.yaml is validated against
index.json                    generated flat manifest of all PoCs (Exploit-DB style)
poc/<id>/
    meta.yaml                 attribution + classification (validated by the schema)
    payload.hex               hex-encoded, canary-forked payload (never raw bytes)
    expected.md               safe behaviour + the canary to check
harness/run.py                sandbox-only runner: decode -> feed -> check canary
tools/validate.py             validate every meta.yaml against the schema
tools/build_index.py          regenerate index.json from poc/*/meta.yaml
```

## A PoC record (`meta.yaml`)

Fields: `id, title, class, cve[], affected[], author, source_url, archive_url,
date, severity, mechanism, references[], payload_encoding, expected_effect,
canary, modified, original_ref, notes`. See `schema/poc.schema.json` and the
worked example in `poc/title-report-echoback-2003/`.

## Using it

Regenerate/validate locally (these only read text, no payloads are decoded):

```
python3 tools/validate.py
python3 tools/build_index.py > index.json
```

Run the corpus against a terminal **inside the sandbox VM only**:

```
POC_CANARY_DIR=... harness/run.py --terminal <cmd> [poc/<id> ...]
```

The harness runs an always-firing positive control first and fails loud if the
canary machinery is not working, so a green "not vulnerable" result is trustworthy.

## Delivery vectors

These attacks arrive as **program output** -- so the terminal must neutralize them
whatever the source. The corpus therefore tests the terminal, not the source. Common
delivery channels (not separate PoCs, since the payload is one of the classes above):
a compromised or malicious program; a log/file you merely `cat` or `less`; a program
that passes attacker-controlled bytes through UNFILTERED (e.g. kubectl object output,
CVE-2021-25743); and LLM CLI tools that smuggle escape sequences from a prompt-injected
model into your terminal ("Terminal DiLLMa").

## Contributing

Public disclosures only. Every entry needs a source, a web-archive link, and an
author. A payload that would do anything harmful must be canary-forked
(`modified: true`) and pass the sanitization review before it is added.

## License

AGPL-3.0-or-later. See [LICENSE](LICENSE).
