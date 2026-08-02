"""Central review tunables.

One home for the knobs that policy and reporting both care about, so no layer
has to reach into another module for a constant. Node-local prompt/content
truncation limits stay next to the nodes that use them.
"""

# Retrieval
TOP_K_RULES = 20

# Guardrail categories that describe what the reviewed code DOES rather than an
# attack on the reviewer. These downgrade from "refuse the file" to a recorded
# warning, and the file is reviewed normally.
#
# Sentinel exists to read code that abuses interpreters — eval, raw SQL,
# deserialization, shell execution — so treating "this is code interpreter
# abuse" as grounds to refuse makes the tool refuse its own subject matter.
# Observed: a Blazor page is rejected S14 for containing
# JS.InvokeVoidAsync("eval", ...), the exact construct
# cwe-79-blazor-unsafe-js-interop exists to find, so that rule could never fire
# on the code it targets.
#
# Widen this set only with care. Everything not listed here still halts the
# file, including an unsafe verdict with no parseable category and unparseable
# guard output — both must keep failing closed. The guardrail's real job,
# refusing content that tries to manipulate the reviewing model, is untouched:
# prompt-injection lives in categories that are not listed here, plus the
# deterministic filename screen in nodes.py.
GUARDRAIL_ADVISORY_CATEGORIES: frozenset[str] = frozenset({"S14"})

# Groundedness judge: emit a finding only if grounded AND score >= threshold
JUDGE_THRESHOLD = 0.7

# Per-node timeouts, treated as overall deadlines by the gateway (seconds)
GUARDRAIL_TIMEOUT = 30.0
CLASSIFY_TIMEOUT = 15.0
RETRIEVE_TIMEOUT = 30.0
TRIAGE_TIMEOUT = 90.0
DEEP_REVIEW_TIMEOUT_PER_WINDOW = 600.0
# The judge is the 49B reviewer running an adversarial refutation with reasoning
# ON, not a small model answering a groundedness template. 120s was sized for the
# old model and refutations routinely blew through it. Because the judge fails
# closed, a timeout suppresses the finding rather than judging it.
#
# Infrastructure slowness quietly suppressing real vulnerabilities is the worst
# failure shape this system has, so the budget is generous on purpose. Measured
# refutation latency is 43-130s per finding when the backend is not contended,
# and longer under concurrent load.
#
# Raised 300 -> 600 on 2026-08-01. 300s was half of DEEP_REVIEW_TIMEOUT_PER_WINDOW
# on the reasoning that one verdict is smaller than a whole window. That reasoning
# ignored decode rate: a /think refutation on the 49B at the measured ~9 tok/s
# spends its whole budget on roughly 2700 tokens, which a reasoning trace reaches
# routinely. A one-file flask_sqli review tripped it and quarantined a real
# hardcoded-secret finding, marking the run complete=false — on a fixture small
# enough that queueing was not a factor, so this is generation time, not
# contention. The same shape cost DVNA run 1 its quotability. Deadlines are
# infrastructure, not detection: a judge that never answered must not read as a
# judge that refuted. Now equal to the window deadline, which is the natural
# ceiling — SLOT_ACQUIRE_TIMEOUT (900s) still sits above it, so genuine slot
# starvation keeps its own distinct error.
JUDGE_TIMEOUT_PER_FINDING = 600.0

# Per-file concurrency for the runner. Higher than deep-review's 2 slots on
# purpose: guardrail, classify, triage and embedding live on other backends and
# genuinely parallelise. Contention on the 49B is bounded by the slot gate in
# gateway.py, not by this number.
FILE_CONCURRENCY = 4

# How long a call may wait for a free backend slot before giving up.
#
# The per-node timeouts above are deadlines on MODEL time. They only mean that
# if the clock starts when the request reaches a slot, so the gateway acquires a
# slot first and starts the deadline after. That leaves a second, different
# failure — waiting forever for a slot that never frees — which needs its own
# bound and its own error, because the remedies are opposite: a slow model wants
# a bigger deadline, a starved queue wants less concurrency or more slots.
#
# Sized above DEEP_REVIEW_TIMEOUT_PER_WINDOW: the longest a slot can legitimately
# be held is one full deep-review window, so anything beyond that is starvation
# rather than a queue doing its job.
SLOT_ACQUIRE_TIMEOUT = 900.0

# Embedding input bounds (bytes, not tokens — see gateway._truncate_utf8).
#
# The nomic GGUF declares n_ctx_train=2048 and llama.cpp clamps per-slot context
# to it, so an input above 2048 real tokens is rejected outright; raising ctx or
# ubatch past that is a verified no-op. The chunker's `len(text)//4` figure is a
# character estimate and cannot bound tokenizer output — measured real/estimate
# ratios on live repos run 1.0-2.0, so a 1200-"token" chunk has reached 2033 real
# tokens (15 short of the ceiling).
#
# A tokenizer never emits more tokens than the input has UTF-8 bytes (every token
# maps to at least one byte), so a byte cap bounds tokens without a per-chunk
# round-trip to /tokenize. EMBED_SOFT_INPUT_BYTES is tuned for retrieval quality:
# at the ~0.43 tokens/byte observed on real JS/TS it lands near 1760 tokens.
# EMBED_HARD_INPUT_BYTES is the provable ceiling used on retry — below 2048 bytes,
# so it cannot exceed 2048 tokens for any input in any language.
EMBED_SOFT_INPUT_BYTES = 4096
EMBED_HARD_INPUT_BYTES = 1900
