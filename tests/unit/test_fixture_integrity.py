"""Fixture specs must stay honest about the source they describe.

`expected_findings.yaml` is the recall denominator for the end-to-end gate, so
drift between a spec and its fixture source silently corrupts the measurement in
whichever direction the drift happens to run: a stale line range makes a real
detection look like a miss, and an unknown rule_id makes an expected finding
unmatchable no matter what the pipeline does.

These checks need no models and no database, so they run in the fast unit suite
and fail the moment a fixture is edited without its spec.

Motivating defect: the first revision of dotnet_sample/Danger.razor initialised
`untrustedHtml` and `script` to `""` — untainted literals with no request-bound
source anywhere in the file — while its spec claimed two XSS findings. The
applicability gate correctly refused to certify findings whose untrusted source
it could not locate, so the app scored 0/3 against a spec describing
vulnerabilities the source did not actually contain.
"""

from pathlib import Path

import pytest
import yaml

from sentinel.rules.loader import load_rules

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "vulnerable_apps"

FIXTURE_APPS = sorted(
    path.name for path in FIXTURES.iterdir() if (path / "expected_findings.yaml").is_file()
)

CORPUS_IDS = {rule.id for rule in load_rules(REPO_ROOT / "rules").rules}


def _spec(app: str) -> dict:
    return yaml.safe_load((FIXTURES / app / "expected_findings.yaml").read_text())


def test_every_fixture_app_has_a_spec():
    """A fixture app without a spec is invisible to the end-to-end gate."""
    apps = {path.name for path in FIXTURES.iterdir() if path.is_dir()}
    missing = apps - set(FIXTURE_APPS)
    assert not missing, f"fixture apps missing expected_findings.yaml: {missing}"


@pytest.mark.parametrize("app", FIXTURE_APPS)
class TestFixtureSpec:
    def test_expected_files_exist(self, app):
        for entry in _spec(app)["expected"]:
            assert (FIXTURES / app / entry["file"]).is_file(), (
                f"{app}: spec names {entry['file']}, which does not exist"
            )

    def test_expected_line_ranges_are_inside_the_file(self, app):
        """A range past EOF can never overlap a finding, so it is an automatic miss."""
        for entry in _spec(app)["expected"]:
            line_count = len((FIXTURES / app / entry["file"]).read_text().split("\n"))
            assert 1 <= entry["line_start"] <= entry["line_end"] <= line_count, (
                f"{app}: {entry['file']} lines {entry['line_start']}-{entry['line_end']} "
                f"fall outside a {line_count}-line file"
            )

    def test_expected_rule_ids_exist_in_the_corpus(self, app):
        """An unmatchable rule_id turns a real detection into a phantom miss."""
        for entry in _spec(app)["expected"]:
            unknown = set(entry["rule_ids"]) - CORPUS_IDS
            assert not unknown, f"{app}: spec cites rule ids absent from the corpus: {unknown}"

    def test_unstable_entries_must_justify_themselves(self, app):
        """`unstable: true` downgrades a miss to a warning, so it needs a reason.

        Without this, the flag is an unaudited mute button: anything that starts
        failing can be marked unstable and the gate goes quiet. Requiring a
        written reason keeps the cost of silencing an entry visible in review.
        """
        for entry in _spec(app)["expected"]:
            if not entry.get("unstable"):
                continue
            reason = (entry.get("unstable_reason") or "").strip()
            assert len(reason) > 40, (
                f"{app}: {entry['file']}:{entry['line_start']} is marked unstable "
                "without a substantive unstable_reason"
            )

    def test_clean_files_exist_and_are_not_also_expected_to_fail(self, app):
        spec = _spec(app)
        expected_files = {entry["file"] for entry in spec["expected"]}
        for clean in spec.get("clean_files", []):
            assert (FIXTURES / app / clean).is_file(), f"{app}: clean file {clean} does not exist"
            assert clean not in expected_files, (
                f"{app}: {clean} is listed as clean and as carrying an expected finding"
            )
