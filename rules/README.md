# The rule corpus

51 rules, all written for this project. None of them are copied or adapted from Semgrep,
CodeQL, Bandit, or any other rule corpus. That matters because those corpora carry their
own licenses, some of which do not permit relicensing, and a rule set assembled by
copying wording would not be cleanly Apache 2.0.

Rules are derived from public standards. Every rule names its CWE (Common Weakness
Enumeration) identifier and its OWASP Top 10 category in `taxonomy`, and links the
upstream definitions under `references`. Standards text is descriptive of a weakness
class rather than copyrightable rule logic, and the detection criteria and both code
examples are original.

If you contribute a rule adapted from somewhere else, say so in the pull request and name
the source and its license. A rule that cannot be relicensed does not go in.

## Layout

```
owasp-top10-2021/     one directory per OWASP category
cwe/                  weaknesses better identified by CWE than by OWASP category
language-specific/    python/, javascript/
framework-specific/   flask/, django/, fastapi/, express/, fastify/, angular/, nextjs/, react/
```

`schema.py` is the contract and `categories.py` maps taxonomy identifiers to the risk
categories retrieval uses.

## Writing one

The audience is a language model reading the rule alongside a window of source, so write
`detection_criteria` as instructions to a reviewer rather than as a pattern. Say what to
flag, say what to exclude, and say when severity moves. Rules that only describe the
vulnerability produce findings on code that merely resembles it.

Both examples are required and both get read. `example_vulnerable` should be the smallest
thing that is genuinely wrong. `example_secure` should be the same code done right, not a
different scenario.

Exclusions belong in the text. A missing-authentication rule that does not tell the model
to skip health checks and login routes will report them, every run.

## Checking one

```sh
uv run sentinel rules validate      # schema, every file, exit 1 on error
uv run sentinel rules load          # embed and load into Postgres
uv run sentinel rules test <rule-id>   # confirm it retrieves for its own example
```

`rules test` is the one that catches the real problem. A rule that does not surface for
its own `example_vulnerable` will never surface for real code either, and a rule sitting
in the corpus unretrieved looks identical to a rule that works.

Retrieval currently returns nearly every JavaScript-eligible rule for any JavaScript file,
because 20 eligible rules against a top-20 retrieval is not a filter. More rules fix that.
It is the single highest-value contribution to this project right now.
