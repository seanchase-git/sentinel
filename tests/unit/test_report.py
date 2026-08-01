import json
import time
from pathlib import Path

from sentinel.graph.runner import RunResult
from sentinel.report.builder import build_report, filter_by_severity
from sentinel.report.json_writer import write_json_report, write_metrics
from sentinel.report.markdown_writer import render_markdown, write_markdown_report

RULE_YAML = "id: r1\ntaxonomy:\n  - owasp: A03:2021\ntitle: T\nseverity: high\n"


def _finding(severity="high", file_path="a.py", line=4):
    return {
        "finding_id": "f-1",
        "rule_id": "r1",
        "file_path": file_path,
        "line_start": line,
        "line_end": line,
        "code_snippet": 'cursor.execute(f"SELECT {x}")',
        "severity": severity,
        "claimed_severity": "critical",
        "explanation": "bad",
        "grounded_in_rule_chunk": RULE_YAML,
        "judge": {"grounded": True, "groundedness_score": 0.93, "reasoning": "ok"},
    }


def _run(file_results):
    now = time.time()
    return RunResult(
        target="/repo",
        started_at=now - 10,
        finished_at=now,
        file_results=file_results,
        metrics={"cache_hit_rate": 0.5, "node_latency": {}, "model_usage": {}, "counters": {}},
    )


def test_build_report_structure_and_counts():
    run = _run(
        [
            {"file_path": "a.py", "status": "completed", "findings": [_finding()],
             "suppressed": [{"stage": "judge", "reason": "not grounded",
                             "candidate": {"rule_id": "r1"}, "judge": None}]},
            {"file_path": "b.py", "status": "triaged_clean", "findings": [], "suppressed": []},
            {"file_path": "evil.py", "status": "blocked_unsafe", "findings": [], "suppressed": [],
             "guardrail": {"safe": False, "category": "S14"}},
        ]
    )
    report = build_report(run)
    assert report["summary"]["findings"] == 1
    assert report["summary"]["suppressed_candidates"] == 1
    assert report["summary"]["rejected_inputs"] == 1
    assert report["rejected_inputs"][0]["category"] == "S14"
    assert report["summary"]["file_status_counts"] == {
        "completed": 1, "triaged_clean": 1, "blocked_unsafe": 1,
    }
    # finding carries the full rule YAML (PRD grounded_in_rule_chunk)
    assert report["findings"][0]["grounded_in_rule_chunk"] == RULE_YAML
    # suppressed entries are tagged with their file
    assert report["suppressed_candidates"][0]["file_path"] == "a.py"


def test_findings_sorted_by_severity_then_location():
    run = _run(
        [
            {"file_path": "a.py", "status": "completed", "suppressed": [],
             "findings": [_finding("medium", "a.py", 9), _finding("critical", "a.py", 2)]},
        ]
    )
    report = build_report(run)
    assert [f["severity"] for f in report["findings"]] == ["critical", "medium"]


def test_severity_filter():
    findings = [_finding("low"), _finding("high"), _finding("critical")]
    assert len(filter_by_severity(findings, {"high", "critical"})) == 2
    assert len(filter_by_severity(findings, None)) == 3


def test_markdown_renders_all_sections():
    run = _run(
        [
            {"file_path": "a.py", "status": "completed", "findings": [_finding()],
             "suppressed": [{"stage": "validator", "reason": "uncited_rule: bogus",
                             "candidate": {"rule_id": "bogus"}, "judge": None}]},
            {"file_path": "evil.py", "status": "blocked_unsafe", "findings": [], "suppressed": [],
             "guardrail": {"safe": False, "category": "S14"}},
        ]
    )
    md = render_markdown(build_report(run))
    assert "# Sentinel Security Review" in md
    assert "### HIGH (1)" in md
    assert "A03:2021 Injection" in md
    assert 'cursor.execute(f"SELECT {x}")' in md
    assert "Suppressed candidates (audit trail)" in md
    assert "uncited_rule: bogus" in md
    assert "Rejected inputs" in md
    assert "*(model claimed critical)*" in md


def test_writers_produce_files(tmp_path: Path):
    run = _run([{"file_path": "a.py", "status": "completed",
                 "findings": [_finding()], "suppressed": []}])
    report = build_report(run)
    p1 = write_json_report(report, tmp_path)
    p2 = write_markdown_report(report, tmp_path)
    p3 = write_metrics(run.metrics, run.wall_seconds, tmp_path)
    assert p1.name == "report.json" and p2.name == "report.md" and p3.name == "metrics.json"
    parsed = json.loads(p1.read_text())
    assert parsed["summary"]["findings"] == 1
    assert json.loads(p3.read_text())["cache_hit_rate"] == 0.5


def test_judge_outage_is_distinguishable_from_a_verdict():
    """An unanswered judge must never look like a rejection.

    The judge fails closed, so a timeout suppresses a finding exactly as a
    refutation does. When both wrote reason "not grounded", an outage was
    unreadable from the report and a real finding could disappear behind a
    string that read like a decision.
    """
    run = _run(
        [
            {
                "file_path": "a.py",
                "status": "completed",
                "findings": [],
                "suppressed": [
                    {
                        "stage": "judge",
                        "reason": "judge unavailable: deep-review chat_json "
                        "exceeded 300.0s deadline",
                        "candidate": {"rule_id": "r1"},
                        "judge": {
                            "grounded": False,
                            "groundedness_score": 0.0,
                            "judge_unavailable": True,
                            "error": "deep-review chat_json exceeded 300.0s deadline",
                        },
                    },
                    {
                        "stage": "judge",
                        "reason": "not grounded",
                        "candidate": {"rule_id": "r1"},
                        "judge": {"grounded": False, "groundedness_score": 0.0},
                    },
                ],
            }
        ]
    )
    report = build_report(run)

    # The outage is quarantined, NOT filed alongside a real verdict.
    assert report["summary"]["suppressed_candidates"] == 1
    assert report["summary"]["judge_unavailable"] == 1
    assert report["summary"]["complete"] is False

    assert [s["reason"] for s in report["suppressed_candidates"]] == ["not grounded"]
    assert len(report["unadjudicated_candidates"]) == 1
    assert report["unadjudicated_candidates"][0]["reason"].startswith("judge unavailable:")

    # The warning must be loud in the rendered report, not buried in a field.
    markdown = render_markdown(report)
    assert "WARNING" in markdown
    assert "judge did not answer" in markdown
    assert "Unadjudicated candidates" in markdown


def test_no_judge_warning_when_every_finding_was_actually_judged():
    run = _run(
        [
            {
                "file_path": "a.py",
                "status": "completed",
                "findings": [_finding()],
                "suppressed": [
                    {
                        "stage": "judge",
                        "reason": "not grounded",
                        "candidate": {"rule_id": "r1"},
                        "judge": {"grounded": False, "groundedness_score": 0.0},
                    }
                ],
            }
        ]
    )
    report = build_report(run)
    assert report["summary"]["judge_unavailable"] == 0
    assert report["summary"]["complete"] is True
    assert report["unadjudicated_candidates"] == []
    assert "judge did not answer" not in render_markdown(report)


def test_run_is_incomplete_when_a_file_never_finished_review():
    """An errored file is an undercount too, not just an unjudged candidate.

    `complete` must not require the reader to also cross-check
    file_status_counts to learn that part of the target was never reviewed.
    """
    run = _run(
        [
            {"file_path": "a.py", "status": "completed", "findings": [_finding()],
             "suppressed": []},
            {"file_path": "b.py", "status": "error", "findings": [], "suppressed": [],
             "error": "deep review failed: deep-review chat_json exceeded 600.0s deadline"},
        ]
    )
    report = build_report(run)
    assert report["summary"]["judge_unavailable"] == 0
    assert report["summary"]["complete"] is False


def test_markdown_warns_when_a_file_never_finished_review():
    """A file error must surface in the rendered report, not just the exit code.

    Warning only on judge outages let a run with an unreviewed file render
    "No grounded findings were emitted" with no caveat, which reads as a clean
    bill of health for a target that was never fully assessed.
    """
    run = _run(
        [
            {"file_path": "a.py", "status": "completed", "findings": [], "suppressed": []},
            {"file_path": "b.py", "status": "error", "findings": [], "suppressed": [],
             "error": "deep review failed: deep-review chat_json exceeded 600.0s deadline"},
        ]
    )
    md = render_markdown(build_report(run))
    assert "INCOMPLETE" in md
    assert "never finished review" in md
    # The judge answered for everything it was given, so no judge claim.
    assert "the judge did not answer" not in md
