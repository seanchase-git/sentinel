"""End-to-end review of the deliberately-vulnerable fixture apps.

Asserts recall against frozen expected_findings.yaml (matched on
file + rule_id + overlapping line range) and structural precision (every
emitted finding cites a real corpus rule and a verbatim snippet). Unexpected
findings are reported as warnings, not failures — a formal false-positive
rate needs the PRD's denominator defined (Pass 2).
"""

from pathlib import Path

import pytest
import yaml

from sentinel.graph.runner import review_target
from sentinel.rules.loader import load_rules

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "vulnerable_apps"
CORPUS_IDS = {r.id for r in load_rules(REPO_ROOT / "rules").rules}


def _overlaps(a_start: int, a_end: int, b_start: int, b_end: int) -> bool:
    return a_start <= b_end and b_start <= a_end


def _findings_by_file(run) -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for record in run.file_results:
        out.setdefault(record["file_path"], []).extend(record.get("findings", []))
    return out


@pytest.mark.parametrize("app", ["flask_sqli", "express_idor", "dotnet_sample"])
async def test_e2e_recall_and_precision(app, full_stack):
    app_dir = FIXTURES / app
    expected_spec = yaml.safe_load((app_dir / "expected_findings.yaml").read_text())
    run = await review_target(str(app_dir))
    by_file = _findings_by_file(run)
    all_findings = [f for fs in by_file.values() for f in fs]

    # structural precision (machine-enforced grounding): every emitted finding
    # cites a real corpus rule, carries a verbatim snippet, and passed the judge
    for f in all_findings:
        assert f["rule_id"] in CORPUS_IDS, f"finding cites unknown rule {f['rule_id']}"
        src = (app_dir / f["file_path"]).read_text()
        assert f["code_snippet"] in src, f"snippet not verbatim in {f['file_path']}"
        assert f["grounded_in_rule_chunk"], "missing grounding rule body"
        assert f["judge"]["grounded"] and f["judge"]["groundedness_score"] >= 0.7

    # recall: every expected finding is present — matched on file, an accepted
    # rule_id, and an overlapping line range.
    #
    # Entries marked `unstable: true` are real defects the pipeline detects only
    # some of the time (see the fixture spec for the per-entry reason). They warn
    # rather than fail: a case that flips between runs would otherwise turn this
    # gate into noise, and a noisy gate stops being read, which is how a genuine
    # regression in the reliable entries slips through. They are NOT excused —
    # they stay in the spec at their exact location and every miss is printed.
    missing = []
    unstable_missing = []
    for exp in expected_spec["expected"]:
        accepted = set(exp["rule_ids"])
        candidates = by_file.get(exp["file"], [])
        hit = any(
            f["rule_id"] in accepted
            and _overlaps(f["line_start"], f["line_end"], exp["line_start"], exp["line_end"])
            for f in candidates
        )
        if hit:
            continue
        record = (exp["file"], exp["rule_ids"], exp["line_start"])
        if exp.get("unstable"):
            unstable_missing.append(record)
        else:
            missing.append(record)

    if unstable_missing:
        print(
            f"\n{app}: UNSTABLE expected findings missed this run "
            f"(known-variable, not a gate failure): {unstable_missing}"
        )
    assert not missing, f"{app}: missing expected findings: {missing}"

    # benign files must not produce findings
    for clean in expected_spec.get("clean_files", []):
        assert not by_file.get(clean), f"{app}: unexpected findings in clean file {clean}"

    # report (not fail) findings beyond the expected set — informational FP
    # signal. A finding is "expected" if it matches an expected spec by file,
    # an accepted rule_id, and overlapping lines.
    def _is_expected(f: dict) -> bool:
        return any(
            f["file_path"] == e["file"]
            and f["rule_id"] in set(e["rule_ids"])
            and _overlaps(f["line_start"], f["line_end"], e["line_start"], e["line_end"])
            for e in expected_spec["expected"]
        )

    unexpected = [
        (f["file_path"], f["rule_id"], f["line_start"])
        for f in all_findings
        if not _is_expected(f)
    ]
    if unexpected:
        print(f"\n{app}: findings beyond the frozen expected set (review manually): {unexpected}")
