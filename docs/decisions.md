# Architecture decisions

Every row is a decision that could reasonably have gone the other way, the option that
lost, and what it cost. Decisions without a cost are usually decisions nobody actually
made.

## The trust boundary

| | |
|---|---|
| **Decision** | Deterministic Python decides whether a finding is grounded. `graph/validation.py` rejects any candidate that cannot cite a rule retrieved for its own window and quote source text that actually appears there. |
| **Rejected** | Ask the model to check its own work, which is what most LLM review tools do. |
| **Why** | A model that hallucinated a snippet will happily confirm the snippet. Self-policing fails in exactly the cases you built it for. |
| **Consequence** | The reviewing model quotes source that is not in the file about 19% of the time and none of it reaches a report. The cost is that validation cannot judge meaning, only presence, so a correctly-quoted irrelevant finding still gets through to the judge. |

## The judge argues the other side

| | |
|---|---|
| **Decision** | The judge tries to refute the finding. It survives only when refutation fails. |
| **Rejected** | Score groundedness, emit above a threshold. That was the original design and it shipped. |
| **Why** | Entailment scoring asks "does this finding resemble the rule text", which is nearly always yes for a finding generated from that rule. It never asks whether the rule's preconditions hold. Almost everything came back grounded. |
| **Consequence** | Precision improved and latency got much worse, because refutation runs the 49B model with reasoning on. Groundedness scoring is retained as telemetry. In one run it scored a candidate 0.99999 grounded that refutation correctly killed, which is the clearest evidence the two are measuring different things. |

## An unanswered judge is not a verdict

| | |
|---|---|
| **Decision** | Judge failures go to `unadjudicated_candidates`, set `summary.complete` false, and exit 4. |
| **Rejected** | Fail closed quietly, which is the conservative-looking option. |
| **Why** | The judge fails closed, so a timeout suppresses a finding exactly the way a refutation does. When both wrote the same reason string, an outage and a judgement were indistinguishable in the report, and a real finding could vanish behind text that read like a decision. |
| **Consequence** | Some runs now exit non-zero and announce they are incomplete, which looks worse and is honest. A precision number computed from an incomplete run is not quotable, and the report says so. |

## Loopback is enforced, not documented

| | |
|---|---|
| **Decision** | Every client that transmits source code checks its endpoint at construction and refuses to start against a non-loopback host. `SENTINEL_ALLOW_REMOTE_MODELS=1` overrides it and prints what it costs. |
| **Rejected** | Default to loopback and describe the guarantee in the README. |
| **Why** | An audit found that one environment variable pointed the embedding client at an arbitrary host, and the air-gap test still passed, because a scan of committed configuration cannot see a runtime override. The headline claim was true of the defaults and false as an invariant. |
| **Consequence** | Pointing Sentinel at a remote model now takes a deliberate, badly-named environment variable. Anyone who genuinely wants a hosted backend has one more step, and the property the tool advertises is the property it enforces. |

## Exact-match caching only

| | |
|---|---|
| **Decision** | The response cache is exact-match on the request. |
| **Rejected** | Semantic caching at a similarity threshold, which LiteLLM supports and which would raise the hit rate. |
| **Why** | Two files can differ only in the line that makes one of them vulnerable. At 0.92 similarity those are the same request, and the cache would return a clean verdict for vulnerable code. |
| **Consequence** | A lower cache hit rate and slower re-reviews. `metrics.json` reports a real hit rate rather than a flattering one. |

## One file at a time

| | |
|---|---|
| **Decision** | The review unit is a single file, chunked into windows under a token budget. |
| **Rejected** | Whole-program analysis with cross-file context. |
| **Why** | It bounds context, makes every finding attributable to a location, and lets files run concurrently. It was also the only thing that fit in the budget of a local 49B model. |
| **Consequence** | This is the largest limit on recall and it is structural, not a tuning problem. A vulnerability that lives across a request handler in one file and a data access layer in another cannot be seen. Authorization bugs sit squarely in that blind spot. The fix is deterministic cross-file analysis establishing the precondition, with the model judging only what needs judgment. |

## A small model guards the large one

| | |
|---|---|
| **Decision** | A 2B model decides whether the 49B reviewer runs on a file at all. |
| **Rejected** | Review everything, or filter by file extension and path heuristics. |
| **Why** | Guardrail, classify, retrieve, and triage together cost about eight seconds per file. Deep review costs over a minute. |
| **Consequence** | Real throughput gain, and a new failure mode: anything triage waves off is never reviewed, and a bad triage call is invisible in the output. Triage sees a sample from every window rather than a prefix, specifically so a file cannot be dismissed on its imports. |

## Rules are structured data, not a DSL

| | |
|---|---|
| **Decision** | Rules are YAML validated against a Pydantic schema, with detection criteria written as prose instructions to a model. |
| **Rejected** | A pattern language, in the shape of Semgrep or CodeQL. |
| **Why** | A pattern language re-implements a static analyzer badly, and the model is the matcher here. Prose can express "exclude intentionally public routes" in a way no pattern can. |
| **Consequence** | Contributing a rule takes no new language, which makes the corpus the easiest place to help. The cost is that nothing enforces the prose. A rule can say to exclude health checks and the model can report a health check anyway, which it has. Machine-checkable exclusions are the fix and they are not built. |

## Reasoning off for generation, on for judgment

| | |
|---|---|
| **Decision** | Deep review runs with reasoning disabled. The refutation pass runs with it enabled. |
| **Rejected** | One setting for both. |
| **Why** | Generation produces a list and competes for the token budget. Reasoning traces consumed the window before the JSON answer arrived, so the cost landed as hard timeouts rather than slower-but-better output. Refutation produces one short answer and is where the judgment is genuinely hard. |
| **Consequence** | Two configurations to keep straight, and a judge slow enough that it blows its deadline under concurrent load. That is a live coverage hole, not a solved problem. |

## Provenance is checked at startup

| | |
|---|---|
| **Decision** | `models/registry.py` refuses to start on a model outside a declared-origin allowlist. |
| **Rejected** | Document the model list and trust the operator. |
| **Why** | The deployment environments this targets often have procurement rules about model origin, and a check that runs is worth more than a policy in a README. |
| **Consequence** | Swapping in a model takes a config edit rather than an environment variable. The check reads the origin declared in `config/models.yaml`, so it is a gate on your own configuration and not independent verification of who trained what. That limit is stated wherever the claim is made. |
