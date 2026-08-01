# Evaluation

A security reviewer that nobody measured is a demo. This directory is how Sentinel gets
measured.

## What gets measured

**Precision.** Of the findings Sentinel emits, how many survive tracing the actual
source. This is only reported as `precision` when the ground truth is marked
`exhaustive: true`, because only then does "not on the list" prove "wrong". Under
non-exhaustive truth the same quotient is printed as `precision >= X (bound)`: it assumes
every unadjudicated finding is a false positive, which is the strictest reading available
and still not a measurement. A number named precision gets quoted as precision, so the
label carries the caveat rather than a footnote.

**Recall.** Of the defects that are actually in the repository, how many does Sentinel
find. The denominator includes defects Sentinel has never reported, which is the only
way a miss shows up as a miss.

When ground truth annotates `corpus_coverage` per entry, recall is also reported over
just the defects some rule actually covers. Raw recall conflates two different failures —
"had a rule and missed it" and "no rule exists" — and on a benchmark dense with planted
defects the second dominates. Quote both or neither.

**Stability.** How much of the output survives from one run to the next on unchanged
input. This is not a formality. llama.cpp continuous batching changes the order of
floating point reductions between runs, which moves logits enough to flip close calls
even under greedy decoding at temperature zero. A real finding can appear in one run and
be gone in the next. Any precision number from a single run is a sample, not a
measurement.

Compare runs of the same code, not runs across a code change. A stability number
computed across two different versions of the pipeline measures the change you made and
tells you nothing about reproducibility.

## Ground truth

`ground_truth/*.yaml`. Each entry gets adjudicated by reading the actual source, not by
accepting Sentinel's output, and then argued against by a second model told to refute the
verdict. Where that second pass reverses a call, the reversal is what gets recorded.
Several have reversed: findings first judged real turned out to be false, and one first
judged false turned out to be a real weakness graded under the wrong rule.

Each file carries the repository revision it was adjudicated against. When the target
repository changes, the ground truth is stale and needs re-adjudication.

Ground truth transcribed from an application's own documented vulnerability inventory,
written before Sentinel is ever run against it, is worth far more than ground truth
assembled from whatever the tool happened to emit. The first kind makes recall a
measurement. The second makes it a bound on what you already knew.

`exhaustive: false` means exactly that. Unmatched findings are unadjudicated rather than
proven false, and recall is an upper bound.

## Running it

```sh
make eval
make eval EVAL_TRUTH=evals/ground_truth/dvna.yaml EVAL_REPORTS=./sentinel-report

uv run python evals/score.py evals/ground_truth/dvna.yaml \
    ./sentinel-report/report.json \
    ./sentinel-report.baseline/report.json
```

Pass more than one report for the same target to get a stability rate alongside precision
and recall.

## Matching rules

A finding counts as detecting a known vulnerability when it names the same file, lands
within 40 lines of the adjudicated location, and cites a rule carrying the same CWE
(Common Weakness Enumeration) number. Matching is one-to-one: each finding and each
ground-truth entry can be used at most once. Assignment is greedy in ground-truth order,
not a global nearest-pair optimum: entries are considered in file order and each claims
the nearest unclaimed finding that also matches its CWE. Where two nearby entries accept
the same CWE, the earlier entry wins. The CWE is read from the cited rule's declared
taxonomy, and a documented parent/child pair (CWE-95 under CWE-94, CWE-321 under
CWE-798, CWE-201 under CWE-200) counts as the same weakness.

Some defects are one omission that surfaces in several places. A router registered
without an auth hook is a single mistake and every route it carries is unauthenticated
because of it, which can span hundreds of lines. Those entries carry `also_at` so a
correct detection at the far end still matches. It stays one entry, so recall is never
inflated by counting one mistake several times.

Three things this scorer got wrong before they were caught, all in the generous
direction:

1. **No CWE check at all.** An XSS finding roughly twenty lines from a CORS defect was
   credited with detecting it, purely on line proximity, turning 50% recall into a
   reported 100%.
2. **CWE matched as a substring.** `CWE-79` matched `cwe-798-hardcoded-secrets`, so a
   hardcoded-secret finding could be credited with detecting an XSS defect. Now the CWE
   number is parsed as a token.
3. **Many-to-one matching.** Every finding near a vulnerability counted as a true
   positive, so three duplicate findings for one defect inflated the numerator three
   times over.

Every one of those made the tool look better than it was. That is the direction scoring
bugs always seem to run, which is the argument for having someone try to break the
scorer rather than trusting it because it produced a plausible number. If you loosen the
matching, you are not measuring the tool, you are measuring your own generosity.

40 lines is a tolerance, not an identity relation. It can credit an unrelated same-CWE
operation nearby, and it will reject a correct finding after the file drifts. Exact CWE
equality also misses a legitimate finding expressed through a parent CWE or an OWASP-only
rule. Both are known limits of the method rather than defended choices.

The scorer refuses to run when a report's `run.target` does not match the ground truth
target, because scoring the wrong report produces numbers that look fine and mean
nothing.

## Reading a report before you trust its numbers

Check `summary.complete` first. False means the run could not account for the whole
target, either because the judge never answered for some candidates or because a file
never finished review. Findings are an undercount in both cases and precision computed
from that run is not worth quoting.

Check `cache_hit_rate` in `metrics.json` too. A run served from cache is a replay of
earlier model output. Fine for reproducing a report, useless for measuring latency or
stability, and a fast wall time is the tell.

## Status

One public benchmark is published: DVNA at 9ba473a, 16 documented in-scope defects across
12 JavaScript files. Sentinel reported 2 findings, both true positives, zero false
positives — 2 of the 6 defects the corpus has a rule for, 0 of the 10 it does not.
Precision is a lower bound (ground truth is `exhaustive: false`) and one run yields no
stability figure. See the root README for the full statement.

Development also happened against private code that cannot be shared, so those results are
not in this repository.

One known coverage hole remains: deep review can exceed its deadline on a small file and
skip it entirely, which quietly costs findings. The judge's counterpart to that — refutations
blowing their deadline under concurrent load — is fixed; the gateway now acquires a backend
slot before starting the deadline, so a per-node timeout measures model time rather than
time spent queued behind other files.
