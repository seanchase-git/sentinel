# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What Sentinel is

Sentinel is a **fully-local, air-gap-capable security reviewer** for AI-generated ("vibe-coded") Python/JavaScript/TypeScript codebases. It reviews source against a curated YAML rules corpus, **grounds every finding in a retrieved rule** (Postgres + pgvector), and gates findings through an **LLM-as-judge** to suppress hallucinations. All models are US-origin open-weight GGUFs served locally by llama.cpp behind a LiteLLM proxy — **no cloud APIs, ever; no code leaves the machine.**

Current status: core pipeline complete. 51-rule starter corpus; verified end-to-end on the fixture apps. One public benchmark: DVNA at 9ba473a — 2 findings, both true positives, zero false positives; 2 of the 6 documented defects the corpus covers, 0 of the 10 it does not. Precision is a lower bound (`exhaustive: false`) and one run gives no stability figure.

**For the as-built layers, patterns, pipeline/finding-lifecycle diagrams, and a "where to change X" table, read `docs/architecture.md` first.** Shared tunables (thresholds, retrieval K, per-node timeouts, concurrency) live in `src/sentinel/settings.py` — change them there, not in the nodes.

## Commands

```sh
# One-time environment (uv, Python 3.12, Postgres+pgvector, DB schema)
make bootstrap                 # uv sync + scripts/setup-postgres.sh
brew services start postgresql@17

# Bring the stack up (order matters)
make backends-up               # 6 llama-server backends on :8090-:8095 (loads ~74.5GB)
make proxy-up                  # dedicated Redis (:6390) + LiteLLM gateway (:8100)
uv run sentinel rules load     # embed + load rules/ into Postgres
uv run sentinel status         # health of all backends + gateway

# Review
uv run sentinel review <path-or-git-url> [-o DIR] [--format json|md|both] \
    [--language python,javascript] [--severity high]   # threshold: high-and-above
# writes report.json, report.md, metrics.json to ./sentinel-report/ (default)

# Rules corpus
uv run sentinel rules validate      # schema-check every YAML (exit 1 on error)
uv run sentinel rules list          # DB-backed (add --yaml for the file view)
uv run sentinel rules test <id>     # verify a rule self-retrieves for its own example

# Tear down
make backends-down && make proxy-down
```

### Tests & lint

```sh
make test                 # unit tests only (no models/DB): uv run pytest -m "not integration"
make test-integration     # SENTINEL_IT_REQUIRED=1 — skips become FAILURES (needs full stack up)
uv run pytest tests/unit/test_validation.py -q          # a single file
uv run pytest -k test_snippet_located_within_window -q  # a single test
make lint                 # ruff check src tests
```

**Integration gating:** `tests/integration/conftest.py` skips when backends/DB/gateway are down — *unless* `SENTINEL_IT_REQUIRED=1` (set by `make test-integration`), which turns skips into failures so the gate can't pass vacuously. Fixtures: `embedder_backend`, `rules_db`, `gateway`, `full_stack`.

## Architecture (the big picture)

The review of a **single file** is a LangGraph pipeline (`src/sentinel/graph/graph.py`), invoked per-file by the runner under an `asyncio.Semaphore(4)`:

```
guardrail → classify → retrieve → triage → deep_review → validate → judge → emit
```

Conditional exits jump straight to `emit`: guardrail-unsafe (`blocked_unsafe`), triage-clean (`triaged_clean`), no candidates.

- **guardrail** (`input-guard`, Llama Guard 3) — scans the *whole file in bounded segments* + a filename regex screen; any unsafe verdict halts the file. `nodes.guardrail_check`.
- **classify** (`classify`, Llama 3.2 1B, JSON grammar) — language/framework/risk_categories. Framework is detected deterministically from imports (`nodes.detect_framework`); the walker's extension-based language is authoritative.
- **retrieve** (`nodes.retrieve_rules`) — chunks the file (tree-sitter, `ingest/chunker.py`), groups chunks into ≤8k-token **review windows**, batch-embeds via `nomic-embed`, and pulls top-K=20 rules **per window** from pgvector (`retrieval/rules_store.py`): language hard-filter + risk-category priority with language-only backfill + `+0.05` framework rerank.
- **triage** (`triage`, Granite 3.3 2B) — sees a sample from *every* window; false → skip file.
- **deep_review** (`deep-review`, Nemotron Super 49B, reasoning-off `/no_think` + JSON grammar) — emits candidate findings **per window**; each candidate is tagged with its window index.
- **validate** (`graph/validation.py`, **pure code — the grounding guarantee**) — every candidate is checked against *its own window's* retrieved rules: rule_id must be cited (with unambiguous fuzzy-snap for transcription typos), snippet must be verbatim source located *within the window nearest the claimed line* (whitespace-normalized fallback replaces the snippet with exact source text), CVEs not in the rule are rejected, severity mismatch is recorded (never silently clamped), duplicates deduped by exact span.
- **applicability** (`graph/evidence.py`, pure code) — deep review must name its evidence (untrusted source, sink, line numbers); code verifies those locations exist in the candidate's window. Access-control CWEs (306/862/639) take a sink-and-enforcement-reason shape because a missing check has no untrusted source. Sink-only CWEs are listed explicitly; unknown CWEs default to flow-required so corpus growth fails closed.
- **judge** (`deep-review`, Nemotron 49B with `/think`) — argues the finding is WRONG and it survives only if refutation fails. Granite Guardian's groundedness runs concurrently as telemetry, not as the decision. A `GatewayError` here means the judge never answered: those go to `unadjudicated_candidates` with `summary.complete=false` and exit code 4, never mixed in with real rejections.
- **emit** → `report/builder.py` assembles findings + suppressed candidates + rejected inputs; `report/{json_writer,markdown_writer}.py` write the artifacts; `metrics.py` records per-node latency, per-model tokens, and real cache-hit rate.

**The gateway (`models/gateway.py`) is the choke point** for LLM and embedding calls made through it. `retrieval/embedder.py` is a second, separate httpx client. Both route their base URL through `netguard.require_loopback`, so the air-gap guarantee holds across both, but 'single choke point' overstates it. The gateway provides: per-node timeouts as overall deadlines (`asyncio.timeout`, `max_retries=0`), JSON-schema structured output with one repair retry, `chat_template_kwargs` passthrough for the judge, cache-hit detection via the `x-litellm-cache-key` response header, and metrics recording. Everything resolves to `http://127.0.0.1:8100`.

## Non-obvious things to know

- **Backend/port map** lives in `config/models.yaml` (single source of truth). `models/registry.py` enforces a **Section 1532 provenance allowlist** (US-origin only) at load time — a non-allowlisted model is a hard startup error. `scripts/start-backends.sh` reads launch plans from the registry; GGUFs come from `~/.lmstudio/models/`.
- Ports: 8090 deep-review · 8091 input-guard · 8092 triage · 8093 judge · 8094 classify · 8095 nomic-embed · 8100 LiteLLM · 6390 Sentinel's dedicated Redis (kept off the default 6379 to avoid other projects' Redis).
- **Cache is exact-match, not semantic** (deviation D2): semantic caching at 0.92 similarity could return stale findings for a file differing only in its vulnerable line. `metrics.json` reports a real `cache_hit_rate` from deterministic hits on re-reviews.
- **SQL column `refs`, not `references`** (deviation D4): `REFERENCES` is a reserved word in Postgres (`pg_get_keywords()` catcode R). The YAML field stays `references`; the loader maps it.
- **Rule risk-categories** are derived from taxonomy (`rules/categories.py`): specific CWE mappings win over the broad OWASP-category fallback, so an XSS classification doesn't pull SQL-injection rules. Adding a rule under a new CWE/OWASP id may need a mapping entry there.
- The rules loader (`rules/loader.py`) uses a **strict YAML loader that rejects duplicate keys** (parsed columns must not disagree with the verbatim `yaml_body` stored for grounding).
- Reasoning models: Nemotron uses `/no_think` (verified v1.5 mechanism); `extract_json` (in `gateway.py`) tries whole-string parse first, then strips only an anchored leading `<think>` block, then falls back to the *last* balanced JSON block.

## Repo layout

- `src/sentinel/` — `cli.py` (Typer), `graph/` (nodes, graph, state, validation, runner, schemas), `retrieval/` (embedder, rules_store), `models/` (gateway, registry, prompts/*.md), `ingest/` (walker, chunker), `report/` (builder + writers), `metrics.py`
- `rules/` — corpus, organized `owasp-top10-2021/`, `cwe/`, `language-specific/`, `framework-specific/`; schema in `rules/schema.py`
- `config/` — `models.yaml`, `litellm.yaml`, `redis-cache.conf`
- `scripts/` — `setup-postgres.sh`, `schema.sql`, `start-backends.sh`, `start-proxy.sh`
- `tests/` — `unit/` (no models/DB), `integration/` (gated), `fixtures/vulnerable_apps/` (each with a frozen `expected_findings.yaml`)
- `evals/` — `score.py` + `ground_truth/*.yaml`; `examples/` — a committed report from the fixture app

## Conventions

- Python 3.12, managed by **uv** (`uv run …`, `uv sync`). Not pip/poetry.
- Pydantic v2 for all schemas; `ruff` (line length 100) for lint.
- Rules are **structured YAML validated against `rules/schema.py`** — no rule DSL. Every rule needs `detection_criteria` written for an LLM reviewer and both `example_vulnerable`/`example_secure`.
- When adding a rule, run `uv run sentinel rules validate` then `rules test <id>` to confirm it self-retrieves.
