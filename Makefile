.PHONY: status bootstrap db-init backends-up backends-down backends-status proxy-up proxy-down \
        rules-load test test-integration lint eval review-fixture benchmark-dotnet

UV ?= uv

bootstrap:
	$(UV) sync --group dev
	./scripts/setup-postgres.sh

db-init:
	./scripts/setup-postgres.sh

backends-up:
	./scripts/start-backends.sh up $(MODELS)

backends-down:
	./scripts/start-backends.sh down

backends-status:
	$(UV) run sentinel status --backends-only

status:
	$(UV) run sentinel status

proxy-up:
	./scripts/start-proxy.sh up

proxy-down:
	./scripts/start-proxy.sh down

rules-load:
	$(UV) run sentinel rules load

test:
	$(UV) run pytest -m "not integration" -q

test-integration:
	SENTINEL_IT_REQUIRED=1 $(UV) run pytest -m integration -q

lint:
	$(UV) run ruff check src tests

# Score the most recent reports against adjudicated ground truth. Pass several
# report dirs for the same target to also get a stability rate, which matters
# because output is not reproducible run to run (see README).
#   make eval
#   make eval EVAL_REPORTS="./sentinel-report ./sentinel-report.baseline"
EVAL_TRUTH ?= evals/ground_truth/dvna.yaml
EVAL_REPORTS ?= ./sentinel-report
eval:
	@for d in $(EVAL_REPORTS); do \
	    if [ ! -f "$$d/report.json" ]; then \
	        echo "no report at $$d/report.json"; \
	        echo "Scoring needs a review to score. Run one first, against the target"; \
	        echo "named in $(EVAL_TRUTH):"; \
	        echo "    uv run sentinel review <target> -o $$d"; \
	        echo "Override with: make eval EVAL_TRUTH=... EVAL_REPORTS=..."; \
	        exit 2; \
	    fi; \
	done
	$(UV) run python evals/score.py $(EVAL_TRUTH) \
	    $(foreach d,$(EVAL_REPORTS),$(d)/report.json)

review-fixture:
	$(UV) run sentinel review tests/fixtures/vulnerable_apps/flask_sqli --output out/

benchmark-dotnet:
	bash scripts/fetch-dotnet-benchmark.sh
