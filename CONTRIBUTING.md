# Contributing

Rules are the best place to start. The pipeline is finished enough that its behaviour is
mostly bounded by how good the corpus is, and adding a rule is a self-contained change
with a test that proves it works. Start at `rules/README.md`.

## Running the tests without the stack

Unit tests need no models, no Postgres, and no proxy. They run anywhere.

```sh
uv sync
make test      # unit tests only
make lint      # ruff, line length 100
```

Integration tests need the full stack up and skip themselves when it is missing, which
makes a green run meaningless if you were expecting them to execute. `make test-integration`
sets `SENTINEL_IT_REQUIRED=1` so skips become failures instead.

## Adding a rule

```sh
uv run sentinel rules validate
uv run sentinel rules load
uv run sentinel rules test <rule-id>
```

A rule that does not retrieve for its own example is not finished. Say in the pull request
whether the rule is original or adapted from another corpus, and name the license if it is
adapted.

## Changing the pipeline

`docs/architecture.md` has the layer map and a table of where to change what. Shared
tunables live in `src/sentinel/settings.py`. Change them there rather than in the nodes.

Two things to know before you touch the validator or the judge.

Validation is the trust boundary and it is deliberately plain Python. If you find yourself
wanting a model to decide whether a finding is grounded, that is the thing this design is
built to avoid.

The judge fails closed, so any failure suppresses a finding. Keep failures distinguishable
from verdicts. A timeout that reports itself as a judgement is worse than a crash, because
the report still looks complete.

## Measurement

If a change is meant to improve findings, measure it and say so with numbers. `evals/`
explains the method and the ways the scorer has flattered the tool in the past. Compare
runs of the same code when you quote stability, check `summary.complete` before quoting
precision, and check `cache_hit_rate` before believing a wall time.

Numbers that only move in the flattering direction are usually a scoring bug. That has
happened here more than once.
