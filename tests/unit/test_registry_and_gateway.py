import asyncio
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import yaml

from sentinel.metrics import MetricsCollector
from sentinel.models.gateway import _EMBED_OVERFLOW_RE, _truncate_utf8, extract_json
from sentinel.models.registry import (
    DEFAULT_MODELS_CONFIG,
    ProvenanceError,
    load_registry,
)
from sentinel.settings import EMBED_HARD_INPUT_BYTES, EMBED_SOFT_INPUT_BYTES


class TestProvenanceAllowlist:
    def test_shipped_config_loads(self):
        registry = load_registry()
        assert set(registry.models) == {
            "deep-review", "input-guard", "triage", "judge", "classify", "nomic-embed",
        }
        assert all(m.origin == "USA" for m in registry.models.values())

    def test_disallowed_origin_rejected(self, tmp_path: Path):
        raw = yaml.safe_load(DEFAULT_MODELS_CONFIG.read_text())
        raw["models"]["classify"]["origin"] = "PRC"
        raw["models"]["classify"]["developer"] = "Covered Nation Lab"
        bad = tmp_path / "models.yaml"
        bad.write_text(yaml.safe_dump(raw))
        with pytest.raises(ProvenanceError, match="Section 1532"):
            load_registry(bad)

    def test_ports_unique(self):
        registry = load_registry()
        ports = [m.port for m in registry.models.values()]
        assert len(ports) == len(set(ports))

    def test_embedding_mode_gets_flag(self):
        registry = load_registry()
        assert "--embedding" in registry.get("nomic-embed").launch_command()
        assert "--embedding" not in registry.get("deep-review").launch_command()


class TestExtractJson:
    def test_plain_json(self):
        assert extract_json('{"a": 1}') == {"a": 1}

    def test_json_after_think_block(self):
        text = "<think>hmm the code looks fine</think>\n{\"findings\": []}"
        assert extract_json(text) == {"findings": []}

    def test_json_embedded_in_prose(self):
        text = 'Here is my analysis: {"grounded": true, "score": 0.9} — done.'
        assert extract_json(text) == {"grounded": True, "score": 0.9}

    def test_last_json_block_wins_over_earlier_invalid(self):
        text = 'first {broken then {"ok": 1}'
        assert extract_json(text) == {"ok": 1}

    def test_last_valid_top_level_block_wins(self):
        # draft-then-final pattern from reasoning models (Codex M4 finding)
        text = 'draft {"findings": []}\nfinal {"findings": [{"rule_id": "x"}]}'
        assert extract_json(text) == {"findings": [{"rule_id": "x"}]}

    def test_nested_object_returns_outer_not_inner(self):
        assert extract_json('{"a": {"b": 1}}') == {"a": {"b": 1}}

    def test_array_containing_objects_returns_array(self):
        assert extract_json('out: [{"a": 1}, {"b": 2}]') == [{"a": 1}, {"b": 2}]

    def test_array_output(self):
        assert extract_json("result:\n[1, 2, 3]") == [1, 2, 3]

    def test_braces_inside_strings_ignored(self):
        text = '{"snippet": "if (x) { return; }", "n": 2}'
        assert extract_json(text) == {"snippet": "if (x) { return; }", "n": 2}

    def test_literal_think_tag_inside_json_string_preserved(self):
        # a code_snippet legitimately containing </think> must not corrupt parsing
        text = '{"findings": [{"code_snippet": "x = \'</think>\'"}]}'
        assert extract_json(text) == {"findings": [{"code_snippet": "x = '</think>'"}]}

    def test_leading_think_block_stripped(self):
        text = "<think>let me reason</think>\n{\"findings\": []}"
        assert extract_json(text) == {"findings": []}

    def test_no_json_raises(self):
        with pytest.raises(ValueError):
            extract_json("no json here at all")


class TestEmbedInputBounding:
    """The embedder's context is a hard token ceiling (nomic GGUF n_ctx_train
    =2048, which llama.cpp clamps slots to). Bytes bound tokens, so these
    guarantees are what keep an oversized chunk from failing a whole file."""

    def test_short_text_untouched(self):
        assert _truncate_utf8("abc", 10) == ("abc", False)

    def test_exactly_at_budget_untouched(self):
        assert _truncate_utf8("abcde", 5) == ("abcde", False)

    def test_truncates_to_budget(self):
        text, was_cut = _truncate_utf8("a" * 100, 10)
        assert was_cut is True
        assert len(text.encode("utf-8")) == 10

    def test_never_splits_a_multibyte_character(self):
        # 4-byte emoji against a budget that lands mid-character
        text, was_cut = _truncate_utf8("😀" * 10, 10)
        assert was_cut is True
        assert text == "😀" * 2  # 8 bytes; the 3rd would overflow
        assert len(text.encode("utf-8")) <= 10

    def test_result_always_within_budget_for_mixed_scripts(self):
        sample = "def f():\n  # 日本語のコメント 😀\n  return 'x'\n" * 20
        for budget in (1, 7, 13, 64, 257, 1900):
            text, _ = _truncate_utf8(sample, budget)
            assert len(text.encode("utf-8")) <= budget

    def test_hard_budget_leaves_room_for_wordpiece_special_tokens(self):
        # The invariant the fix rests on, stated precisely: for this WordPiece
        # tokenizer, non-special token count never exceeds UTF-8 byte count
        # (verified exhaustively over all Unicode code points), and the model
        # then adds [CLS] and [SEP] OUTSIDE the input. So the true bound is
        # bytes + 2, and the hard budget must leave room for those two.
        # Regression guard: raising EMBED_HARD_INPUT_BYTES to >= 2046 silently
        # reintroduces the overflow this fix exists to prevent.
        nomic_context_tokens = 2048
        wordpiece_special_tokens = 2  # [CLS], [SEP]
        assert EMBED_HARD_INPUT_BYTES + wordpiece_special_tokens < nomic_context_tokens

    def test_soft_budget_is_above_hard_budget(self):
        # soft is a quality knob, hard is the provable floor it falls back to;
        # inverting them would make the retry a no-op
        assert EMBED_SOFT_INPUT_BYTES > EMBED_HARD_INPUT_BYTES

    def test_text_already_under_hard_budget_is_not_degraded_by_retry(self):
        # the retry re-truncates every input in the batch, so inputs that
        # already fit must pass through byte-identical
        small = "const x = 1;\n" * 10
        assert len(small.encode("utf-8")) < EMBED_HARD_INPUT_BYTES
        assert _truncate_utf8(small, EMBED_HARD_INPUT_BYTES) == (small, False)

    @pytest.mark.parametrize(
        "detail",
        [
            "input (4587 tokens) is larger than the max context size (2048 tokens)",
            "input (9444 tokens) is too large to process. increase the physical batch size",
            "Error code: 500 - {'message': 'input (850 tokens) is too large to process'}",
        ],
    )
    def test_overflow_errors_are_recognised_as_retryable(self, detail):
        assert _EMBED_OVERFLOW_RE.search(detail) is not None

    @pytest.mark.parametrize(
        "detail",
        [
            "Connection refused",
            "model not found: nomic-embed",
            "context deadline exceeded",
        ],
    )
    def test_unrelated_errors_are_not_treated_as_overflow(self, detail):
        assert _EMBED_OVERFLOW_RE.search(detail) is None


class _FakeEmbedResponse:
    """Minimal stand-in for the OpenAI raw-response wrapper _embed consumes."""

    def __init__(self, n: int, indices: list[int] | None = None):
        self._n = n
        self._indices = list(range(n)) if indices is None else indices
        self.headers: dict[str, str] = {}

    def parse(self):
        return self

    @property
    def data(self):
        return [
            SimpleNamespace(index=i, embedding=[float(i)] * 768) for i in self._indices
        ]

    usage = SimpleNamespace(prompt_tokens=0, completion_tokens=0)


class TestEmbedRetryPath:
    """_truncate_utf8 in isolation proves little; these drive it through _embed,
    which is where a reordering or prefix bug would corrupt retrieval."""

    def _gateway(self):
        from sentinel.metrics import MetricsCollector
        from sentinel.models.gateway import Gateway

        return Gateway(metrics=MetricsCollector())

    def test_overflow_retries_at_hard_budget_preserving_prefix_order_and_count(self):
        from sentinel.models.gateway import _EmbedInputTooLarge

        g = self._gateway()
        seen: list[list[str]] = []

        async def fake_call(model, texts, timeout):
            seen.append(list(texts))
            if len(seen) == 1:
                raise _EmbedInputTooLarge("input (9999 tokens) is too large to process")
            return _FakeEmbedResponse(len(texts))

        g._embed_call = fake_call
        chunks = ["AAAA" * 3000, "B" * 10, "CCCC" * 2000]
        vectors = asyncio.run(g.embed_queries(chunks))

        assert len(seen) == 2, "should attempt once, then retry once"
        first, retry = seen
        assert len(retry) == len(chunks) == len(vectors)
        # every retried input keeps the mandatory nomic prefix ...
        assert all(t.startswith("search_query: ") for t in retry)
        # ... is within the hard budget ...
        assert all(len(t.encode("utf-8")) <= EMBED_HARD_INPUT_BYTES for t in retry)
        # ... and stays in its original position
        assert [t[14:15] for t in retry] == ["A", "B", "C"]
        assert [v[0] for v in vectors] == [0.0, 1.0, 2.0]

    def test_second_overflow_fails_loudly_rather_than_returning_wrong_vectors(self):
        from sentinel.models.gateway import GatewayError, _EmbedInputTooLarge

        g = self._gateway()

        async def always_overflow(model, texts, timeout):
            raise _EmbedInputTooLarge("input (9999 tokens) is too large to process")

        g._embed_call = always_overflow
        with pytest.raises(GatewayError, match="even at"):
            asyncio.run(g.embed_queries(["x" * 100]))

    def test_duplicate_response_indices_are_rejected(self):
        # the LiteLLM partial-cache-hit bug shape: right count, wrong indices.
        # This must raise, never silently pair the wrong vector with a chunk.
        from sentinel.models.gateway import GatewayError

        g = self._gateway()

        async def duplicated(model, texts, timeout):
            return _FakeEmbedResponse(len(texts), indices=[0, 0, 1, 1, 2])

        g._embed_call = duplicated
        with pytest.raises(GatewayError, match="shape mismatch"):
            asyncio.run(g.embed_queries(["a", "b", "c", "d", "e"]))


class TestSlotGate:
    """The slot gate exists so a per-node timeout measures MODEL time.

    Before it, more concurrent requests than a backend had slots queued inside
    llama-server with the deadline already running, so a refutation could burn
    its whole 300s budget waiting behind two deep-review windows and be reported
    as a slow model when the model never ran. That is how the DVNA benchmark
    lost a real finding.
    """

    def _gateway(self, limits):
        from sentinel.models.gateway import Gateway

        g = Gateway.__new__(Gateway)
        g.metrics = MetricsCollector()
        g._slot_limits = limits
        g._slots = {}
        return g

    def test_concurrency_never_exceeds_the_backends_declared_slots(self):
        g = self._gateway({"deep-review": 2})
        live = 0
        peak = 0

        async def call():
            nonlocal live, peak
            async with g._slot("deep-review"):
                live += 1
                peak = max(peak, live)
                await asyncio.sleep(0.01)
                live -= 1

        async def main():
            await asyncio.gather(*(call() for _ in range(8)))

        asyncio.run(main())
        assert peak == 2, f"{peak} concurrent calls against a 2-slot backend"

    def test_waiting_for_a_slot_is_not_billed_to_the_callers_deadline(self):
        """The whole point: a caller that waits then runs must not time out."""
        g = self._gateway({"deep-review": 1})
        results = []

        async def call(hold, deadline):
            async with g._slot("deep-review"):
                try:
                    async with asyncio.timeout(deadline):
                        await asyncio.sleep(hold)
                    results.append("ok")
                except TimeoutError:
                    results.append("timeout")

        async def main():
            # Both hold 0.05s of "model time" against a 0.10s deadline, on a
            # single-slot backend. The second waits for the first to finish.
            # Billed the wait, it would exceed its deadline; gated, it does not.
            await asyncio.gather(call(0.05, 0.10), call(0.05, 0.10))

        asyncio.run(main())
        assert results == ["ok", "ok"], results

    def test_slot_starvation_is_a_distinct_error_from_a_slow_model(self):
        from sentinel.models.gateway import GatewayError

        g = self._gateway({"deep-review": 1})

        async def main():
            async with g._slot("deep-review"):
                with pytest.raises(GatewayError, match="contention, not latency"):
                    async with g._slot("deep-review"):
                        pass

        with patch("sentinel.models.gateway.SLOT_ACQUIRE_TIMEOUT", 0.01):
            asyncio.run(main())
        assert g.metrics.counters.get("slot_starved") == 1

    def test_a_released_slot_is_reusable_after_the_body_raises(self):
        g = self._gateway({"deep-review": 1})

        async def main():
            for _ in range(3):
                with pytest.raises(ValueError):
                    async with g._slot("deep-review"):
                        raise ValueError("boom")
            # Not deadlocked: the semaphore was released on every failure.
            async with asyncio.timeout(0.5), g._slot("deep-review"):
                pass

        asyncio.run(main())

    def test_unknown_model_is_ungated_rather_than_blocked(self):
        g = self._gateway({})

        async def main():
            async with asyncio.timeout(0.5), g._slot("not-in-registry"):
                return True

        assert asyncio.run(main()) is True

    def test_limits_come_from_the_registry_not_a_hardcoded_number(self):
        from sentinel.models.gateway import _load_slot_limits

        limits = _load_slot_limits()
        registry = load_registry()
        assert limits == {a: m.parallel for a, m in registry.models.items()}
        assert limits["deep-review"] == registry.get("deep-review").parallel
