"""The dashboard is read-only, loopback-only, and must not become a file server.

It exists to show a review in flight, which means it reads backend logs from a
machine that reviews source code that cannot leave the building. Two properties
are therefore load-bearing rather than incidental: it will not serve a log for
an alias that is not a real backend, and it will not bind to a non-loopback
address. Both are pinned here.

The rest is parsing: live token rates are scraped from llama-server's own log
lines, and the review funnel is derived from a report. Both are formats owned by
someone else, so they get tests that fail loudly when the shape changes rather
than quietly reporting zero.
"""

import json
import time
from pathlib import Path

import pytest

from sentinel import dashboard
from sentinel.netguard import AirGapViolation

# Verbatim llama-server output, wrapped only to satisfy the line-length rule.
_T = "I slot print_timing: id"
TIMING_LINES = "\n".join(
    [
        f"140.37.067.157 {_T}  1 | task 51282 | n_decoded = 3222, tg = 8.64 t/s, tg_3s = 7.37 t/s",
        f"140.38.010.887 {_T}  0 | task 53905 | n_decoded =  146, tg = 7.49 t/s, tg_3s = 7.39 t/s",
        f"140.40.105.499 {_T}  1 | task 51282 | n_decoded = 3247, tg = 8.60 t/s, tg_3s = 8.23 t/s",
    ]
)


class TestLogAccess:
    def test_unknown_alias_is_refused(self):
        """The alias must be a real backend, not a sanitized string.

        Filtering a path still means trusting it. Requiring a name that already
        exists in the model registry means a traversal attempt has nothing to
        address in the first place.
        """
        result = dashboard.tail_log("../../../../etc/passwd")
        assert result["error"] == "unknown alias"
        assert result["lines"] == []

    @pytest.mark.parametrize(
        "alias",
        ["..", "../config/models.yaml", "deep-review/../../secrets", "", "nope"],
    )
    def test_traversal_shapes_are_all_refused(self, alias):
        assert dashboard.tail_log(alias)["error"] == "unknown alias"

    def test_known_alias_is_allowed_even_when_the_file_is_absent(self, monkeypatch, tmp_path):
        """A missing log is a missing log, not an access decision."""
        monkeypatch.setattr(dashboard, "LOG_DIR", tmp_path)
        result = dashboard.tail_log("litellm")
        assert result["error"] == "no log file"

    def test_tail_returns_the_last_lines(self, monkeypatch, tmp_path):
        monkeypatch.setattr(dashboard, "LOG_DIR", tmp_path)
        (tmp_path / "litellm.log").write_text("\n".join(f"line {i}" for i in range(500)))
        result = dashboard.tail_log("litellm", lines=10)
        assert len(result["lines"]) == 10
        assert result["lines"][-1] == "line 499"


class TestBackendActivity:
    def test_recent_timing_lines_report_live_generation(self, monkeypatch, tmp_path):
        monkeypatch.setattr(dashboard, "LOG_DIR", tmp_path)
        (tmp_path / "deep-review.log").write_text(TIMING_LINES)
        activity = dashboard._backend_activity("deep-review")
        assert activity["active"] is True
        # two distinct slots, each counted once at its most recent rate. Slot 1
        # appears twice; the later line (8.60) wins, so a slot cannot be counted
        # once per log line and inflate the aggregate.
        assert activity["slots"] == 2
        assert activity["tokens_per_second"] == round(8.60 + 7.49, 1)

    def test_a_stale_log_is_not_live(self, monkeypatch, tmp_path):
        """Freshness is the file's mtime; the log's own clock is process-relative."""
        monkeypatch.setattr(dashboard, "LOG_DIR", tmp_path)
        path = tmp_path / "deep-review.log"
        path.write_text(TIMING_LINES)
        stale = time.time() - (dashboard._ACTIVE_WINDOW_SECONDS + 60)
        import os

        os.utime(path, (stale, stale))
        assert dashboard._backend_activity("deep-review")["active"] is False

    def test_missing_log_is_not_live(self, monkeypatch, tmp_path):
        monkeypatch.setattr(dashboard, "LOG_DIR", tmp_path)
        assert dashboard._backend_activity("deep-review")["active"] is False


class TestRunSummaries:
    @staticmethod
    def _report(tmp_path: Path) -> Path:
        out = tmp_path / "run"
        out.mkdir()
        (out / "report.json").write_text(
            json.dumps(
                {
                    "run": {"target": "/repo/app", "timestamp": "now"},
                    "summary": {"findings": 2, "suppressed_candidates": 3},
                    "findings": [{"id": 1}, {"id": 2}],
                    "suppressed_candidates": [
                        {"stage": "validator"},
                        {"stage": "validator"},
                        {"stage": "judge"},
                    ],
                    "unadjudicated_candidates": [{"id": 9}],
                }
            )
        )
        return out

    def test_gate_drops_are_split_by_stage(self, tmp_path):
        """'The gate rejected it' and 'the judge refuted it' are different claims."""
        self._report(tmp_path)
        runs = dashboard.collect_runs(tmp_path)
        assert len(runs) == 1
        run = runs[0]
        assert run["gate_drops"] == {"validator": 2, "judge": 1}
        assert run["emitted"] == 2
        assert run["unadjudicated"] == 1
        # every candidate is accounted for by exactly one outcome
        assert run["candidates"] == run["emitted"] + run["unadjudicated"] + sum(
            run["gate_drops"].values()
        )

    def test_missing_directory_is_not_an_error(self, tmp_path):
        assert dashboard.collect_runs(tmp_path / "nope") == []

    def test_unreadable_report_is_skipped_rather_than_raising(self, tmp_path):
        out = tmp_path / "broken"
        out.mkdir()
        (out / "report.json").write_text("{not json")
        assert dashboard.collect_runs(tmp_path) == []


class TestServeIsLoopbackOnly:
    """Two different failures, two different behaviours, on purpose.

    An off-loopback bind is a security misconfiguration and must be loud. A port
    already in use or a thread that will not start is operational, and a
    dashboard is a convenience that must never be the reason a review fails.
    """

    def test_binding_off_box_is_refused(self, monkeypatch):
        monkeypatch.delenv("SENTINEL_ALLOW_REMOTE_MODELS", raising=False)
        with pytest.raises(AirGapViolation):
            dashboard.serve(port=8299, host="0.0.0.0")

    def test_air_gap_violation_is_not_swallowed_by_ensure_running(self, monkeypatch):
        monkeypatch.delenv("SENTINEL_ALLOW_REMOTE_MODELS", raising=False)
        with pytest.raises(AirGapViolation):
            dashboard.ensure_running(port=8299, host="203.0.113.9")

    def test_the_remote_model_escape_hatch_does_not_publish_the_dashboard(self, monkeypatch):
        """SENTINEL_ALLOW_REMOTE_MODELS is about where the MODELS live.

        Letting it also govern this listener would mean one variable, set for an
        unrelated reason, quietly exposes backend logs on every interface.
        """
        monkeypatch.setenv("SENTINEL_ALLOW_REMOTE_MODELS", "1")
        with pytest.raises(AirGapViolation):
            dashboard.ensure_running(port=8299, host="0.0.0.0")

    def test_operational_failure_returns_none(self, monkeypatch):
        """A dashboard that cannot start is not a reason to abort a review."""

        def boom(*_args, **_kwargs):
            raise OSError("address already in use")

        monkeypatch.setattr(dashboard, "ThreadingHTTPServer", boom)
        monkeypatch.setattr(dashboard, "_already_serving", lambda *a, **k: False)
        assert dashboard.ensure_running(port=8299) is None


class TestPage:
    def test_html_is_served_from_a_file_and_is_self_contained(self):
        html = dashboard.INDEX_HTML
        assert "<title>Sentinel</title>" in html
        # No external fetches: a webfont or CDN script would quietly falsify the
        # claim this page prints in its own footer.
        for offender in ("https://", "http://fonts", "cdn.", "<script src"):
            assert offender not in html, f"page reaches off-box via {offender!r}"

    def test_every_pipeline_stage_declares_what_it_trusts(self):
        for stage in dashboard.PIPELINE_STAGES:
            assert stage["kind"] in {"model", "pure", "hybrid"}
            assert stage["note"]
            if stage["kind"] == "pure":
                assert stage["backend"] is None, "a pure stage must call no model"


class TestSymlinkContainment:
    """A log path that leaves the log directory is refused.

    `is_file()` and `open()` both follow symlinks, so an allowlisted alias whose
    log file is a link elsewhere would otherwise serve that file to anyone who
    can reach the page.
    """

    def test_symlinked_log_is_refused(self, monkeypatch, tmp_path):
        logs = tmp_path / "logs"
        logs.mkdir()
        secret = tmp_path / "secret.txt"
        secret.write_text("PRIVATE KEY MATERIAL")
        (logs / "litellm.log").symlink_to(secret)
        monkeypatch.setattr(dashboard, "LOG_DIR", logs)

        result = dashboard.tail_log("litellm")
        assert result["lines"] == []
        assert "escapes" in result["error"]

    def test_ordinary_log_still_reads(self, monkeypatch, tmp_path):
        logs = tmp_path / "logs"
        logs.mkdir()
        (logs / "litellm.log").write_text("hello\nworld")
        monkeypatch.setattr(dashboard, "LOG_DIR", logs)
        assert dashboard.tail_log("litellm")["lines"] == ["hello", "world"]


class TestMalformedTimingLines:
    def test_a_bad_number_does_not_take_the_page_down(self, monkeypatch, tmp_path):
        """The regex accepts digit-and-dot runs that float() rejects."""
        monkeypatch.setattr(dashboard, "LOG_DIR", tmp_path)
        good = f"140.37.067.157 {_T}  0 | task 1 | n_decoded = 10, tg = 9.10 t/s, tg_3s = 9 t/s"
        bad = f"140.38.067.157 {_T}  1 | task 2 | n_decoded = 20, tg = 1.2.3 t/s, tg_3s = 9 t/s"
        (tmp_path / "deep-review.log").write_text(good + "\n" + bad)
        activity = dashboard._backend_activity("deep-review")
        assert activity["active"] is True
        assert activity["slots"] == 1
        assert activity["tokens_per_second"] == 9.1
