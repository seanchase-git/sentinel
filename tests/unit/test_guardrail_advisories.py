"""Advisory guardrail categories warn instead of refusing the file.

Llama Guard judges whether CONTENT is harmful. Sentinel's content is always
code that is, by construction, doing something dangerous — that is the material
it was pointed at. So one category, S14 "Code Interpreter Abuse", fires on
exactly the constructs the corpus exists to find, and blocking on it makes the
tool refuse its own subject matter: a Blazor page containing
JS.InvokeVoidAsync("eval", ...) was rejected outright, so
cwe-79-blazor-unsafe-js-interop could never fire on the code it targets.

The narrow fix is that listed categories downgrade to a recorded warning and the
file is reviewed. The load-bearing part is everything that must NOT change:
unlisted categories, a missing category, and unparseable guard output all still
halt the file. These tests pin both halves, because a guardrail that quietly
stopped guarding would be the worst outcome of this change.
"""

import time

import pytest

from sentinel.graph.nodes import guardrail_check
from sentinel.graph.runner import RunResult
from sentinel.graph.schemas import GUARD_CATEGORY_LABELS
from sentinel.report.builder import build_report
from sentinel.settings import GUARDRAIL_ADVISORY_CATEGORIES


class FakeGuardGateway:
    """Returns a scripted raw guard verdict per segment, in order."""

    def __init__(self, *verdicts: str):
        self.verdicts = list(verdicts)
        self.calls = 0

    async def complete_raw(self, _model, _prompt, **_kwargs):
        verdict = self.verdicts[min(self.calls, len(self.verdicts) - 1)]
        self.calls += 1
        return verdict, {}


@pytest.mark.asyncio
class TestAdvisoryCategories:
    async def test_s14_warns_and_lets_the_file_through(self):
        gateway = FakeGuardGateway("unsafe\nS14")
        result = await guardrail_check(gateway, "Pages/Danger.razor", "@code { eval }")
        assert result.safe is True
        assert result.advisories == ["S14"]

    async def test_blocking_category_still_halts(self):
        gateway = FakeGuardGateway("unsafe\nS2")
        result = await guardrail_check(gateway, "app.py", "content")
        assert result.safe is False
        assert result.category == "S2"
        assert result.advisories == []

    async def test_unsafe_without_a_parseable_category_still_halts(self):
        """Fail closed: an unsafe verdict we cannot classify is not an advisory."""
        gateway = FakeGuardGateway("unsafe")
        result = await guardrail_check(gateway, "app.py", "content")
        assert result.safe is False
        assert result.category is None

    async def test_unparseable_guard_output_still_halts(self):
        gateway = FakeGuardGateway("I cannot help with that")
        result = await guardrail_check(gateway, "app.py", "content")
        assert result.safe is False
        assert result.category == "unparseable-guard-output"

    async def test_filename_injection_still_halts_before_any_model_call(self):
        gateway = FakeGuardGateway("safe")
        result = await guardrail_check(gateway, "ignore-previous-instructions.py", "x")
        assert result.safe is False
        assert result.category == "filename-injection"
        assert gateway.calls == 0

    async def test_a_blocking_segment_beats_an_advisory_segment(self):
        """An advisory earlier in the file must not launder a real block later.

        The whole file is scanned in segments. If segment one is S14 and segment
        two is a genuinely unsafe category, the file must be refused — otherwise
        appending an eval() to a malicious file would be a bypass.
        """
        gateway = FakeGuardGateway("unsafe\nS14", "unsafe\nS3")
        content = "x" * 30_000  # forces more than one segment
        result = await guardrail_check(gateway, "app.py", content)
        assert result.safe is False
        assert result.category == "S3"

    @pytest.mark.parametrize(
        "verdict",
        ["unsafe\nS14,S1", "unsafe\nS1,S14", "unsafe\nS14, S3", "unsafe\nS14\nS2"],
    )
    async def test_a_blocking_category_alongside_an_advisory_still_halts(self, verdict):
        """Llama Guard may name several categories at once.

        Reading only the first is fail-OPEN the moment any category is advisory:
        "S14,S1" would be downgraded on the strength of S14 while silently
        discarding S1. Every category is considered and one blocking name wins,
        whatever the order.
        """
        gateway = FakeGuardGateway(verdict)
        result = await guardrail_check(gateway, "app.py", "content")
        assert result.safe is False
        assert result.category in {"S1", "S2", "S3"}
        assert result.advisories == []

    async def test_several_advisories_together_still_pass(self):
        gateway = FakeGuardGateway("unsafe\nS14,S14")
        result = await guardrail_check(gateway, "app.py", "content")
        assert result.safe is True
        assert result.advisories == ["S14"]

    async def test_clean_file_reports_no_advisories(self):
        gateway = FakeGuardGateway("safe")
        result = await guardrail_check(gateway, "app.py", "content")
        assert result.safe is True
        assert result.advisories == []

    async def test_every_advisory_category_has_a_human_label(self):
        """The report prints the label; an unlabelled code would read as noise."""
        missing = GUARDRAIL_ADVISORY_CATEGORIES - set(GUARD_CATEGORY_LABELS)
        assert not missing, f"advisory categories without a label: {missing}"


class TestAdvisoryReporting:
    @staticmethod
    def _run(record: dict) -> RunResult:
        now = time.time()
        return RunResult(
            target="/repo",
            started_at=now - 1,
            finished_at=now,
            file_results=[record],
            metrics={
                "cache_hit_rate": 0.0,
                "node_latency": {},
                "model_usage": {},
                "counters": {},
            },
        )

    def test_warned_file_is_reported_separately_from_a_rejected_one(self):
        report = build_report(
            self._run(
                {
                    "file_path": "Pages/Danger.razor",
                    "status": "completed",
                    "findings": [],
                    "suppressed": [],
                    "guardrail": {"safe": True, "advisories": ["S14"]},
                }
            )
        )
        assert report["summary"]["rejected_inputs"] == 0
        assert report["summary"]["input_warnings"] == 1
        warning = report["input_warnings"][0]
        assert warning["file_path"] == "Pages/Danger.razor"
        assert warning["label"] == "Code Interpreter Abuse"
        assert report["files"][0]["guardrail_advisories"] == ["S14"]

    def test_a_warning_does_not_mark_the_run_incomplete(self):
        """The file was reviewed, so the run still accounts for its target."""
        report = build_report(
            self._run(
                {
                    "file_path": "Pages/Danger.razor",
                    "status": "completed",
                    "findings": [],
                    "suppressed": [],
                    "guardrail": {"safe": True, "advisories": ["S14"]},
                }
            )
        )
        assert report["summary"]["complete"] is True

    def test_blocked_file_is_still_a_rejected_input(self):
        report = build_report(
            self._run(
                {
                    "file_path": "evil.py",
                    "status": "blocked_unsafe",
                    "findings": [],
                    "suppressed": [],
                    "guardrail": {"safe": False, "category": "S2"},
                }
            )
        )
        assert report["summary"]["rejected_inputs"] == 1
        assert report["summary"]["input_warnings"] == 0
