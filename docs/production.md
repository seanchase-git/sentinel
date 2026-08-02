# What would have to change for production

Sentinel is a working prototype with published limits. This is the honest gap between it
and something a team could depend on, written so nobody has to discover these by
deploying it.

Nothing here is a known-unknown. Every item is a decision I made to skip, and the reason.

## Findings quality comes first

Everything below is engineering. None of it matters while recall is the binding
constraint, and recall is limited by reviewing one file at a time with no cross-file
view. A tool that misses authorization bugs because it cannot see two files at once does
not become useful by getting better packaging. See the per-file row in
[decisions.md](decisions.md).

Two coverage holes are open and both quietly cost findings: the judge blows its deadline
(generation latency, not concurrency — a single-file review with no queueing trips it),
and deep review can time out on a small file and skip it. Both
surface in the report and in the exit code, so they are visible rather than silent, but
visible is not fixed.

## Secrets

The LiteLLM master key lives in `config/litellm.yaml` as a development placeholder. It is
loopback-only and authenticates nothing external, which is why it is acceptable here and
would not be acceptable anywhere else. Production wants it out of the file and into the
platform's secret store, rotated, and never logged.

Reports are the bigger exposure. `report.json` contains verbatim source, and so do
suppressed candidates, unadjudicated candidates, and error strings. There is no
redaction pass. A finding about a hardcoded credential quotes the credential. Today the
mitigation is `umask 077` and keeping output outside the repository, which is a
documentation-shaped control rather than an engineering one.

## Network enforcement

Loopback is enforced at construction for every client that transmits source code, which
covers the realistic regression of somebody adding a hosted fallback. It is not a
sandbox. A dependency that opens its own socket is not stopped by application-level
checks, and `litellm[proxy]` pulls a wide cloud and observability surface including Azure
packages, boto3, and LangSmith. None of it is configured or called, and none of it is
prevented from calling out either.

Real enforcement is a network namespace, a firewall rule, or a seccomp profile that
denies non-loopback egress for the whole process tree. That is the control an air-gapped
deployment would actually be audited against, and it belongs to the platform rather than
to this code.

## Observability

`metrics.json` records per-node latency, per-model tokens, and a real cache hit rate,
written once at the end of a run. That is enough to answer "why was that slow" after the
fact and nothing else.

Missing: structured logs with correlation across a run, metrics exported anywhere a
dashboard can read them, and any alerting on the conditions that already have exit codes.
A run that exits 4 because the judge never answered is exactly the event an operator
needs pushed to them, and today it is a line of terminal output.

## Scale

Concurrency is a semaphore over files, sized against the backend's slot count. The whole
design assumes one machine and one operator.

A team-sized deployment needs a work queue, incremental review of a diff rather than a
tree, and results that persist somewhere queryable. Reviewing a large repository
end to end takes long enough that it is a batch job, not a pre-commit hook, and pretending
otherwise would waste somebody's afternoon.

## Model provenance

The registry refuses to start on a model outside a declared-origin allowlist. That check
reads the origin declared in `config/models.yaml`, so it enforces your own configuration
and does not verify who trained what.

Production wants checksums pinned per GGUF and verified at load, a signed manifest, and a
recorded provenance chain from upstream repository to the file on disk. Model licenses
also differ and three of the six carry redistribution conditions, which matters the
moment weights move inside an organization. See [models.md](models.md).

## Packaging

Setup is a Makefile, a Postgres install, six llama-server processes, a Redis, and 74.5 GB
of weights you download yourself. It works and it is not a deployment.

The real version is a container image or an installer that stages weights with checksums,
health-checks the stack as a unit, and fails loudly when a backend is missing rather than
part way through the first review. The current health check learned that lesson once
already: it reported Redis healthy in the same second Redis died, because it checked that
a port answered rather than that its own process was alive.
