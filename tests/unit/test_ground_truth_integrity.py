"""Ground truth must point at executable defects, not at documentation.

Recall and precision are only meaningful if the denominator is honest. Two ways
it silently stops being honest:

1. A line drifts (the benchmark is re-pinned, or a transcription is simply
   wrong) and the entry can no longer be matched by evals/score.py, which
   depresses recall for a reason that has nothing to do with the reviewer.

2. An entry points at a line that is not executable code. This one is worse than
   a miss: teaching repositories print their own vulnerable source as sample
   text, so an entry anchored on a sample would score a reviewer's *false
   positive* as a true positive, inflating precision and recall together.

Both are caught here rather than discovered while reading a number. The
executable check is the same one the applicability gate uses in production, so
ground truth is held to the standard the pipeline is held to.

These tests skip when the benchmark checkout is absent (it is fetched on demand
by scripts/fetch-dotnet-benchmark.sh), so they never fail a clean clone.
"""

import re
from pathlib import Path

import pytest
import yaml
from tree_sitter_language_pack import get_parser

from sentinel.graph.evidence import _RAZOR_CODE_BLOCK_RE, _node_is_non_executed

REPO_ROOT = Path(__file__).resolve().parents[2]
GROUND_TRUTH_DIR = REPO_ROOT / "evals" / "ground_truth"

SPECS = sorted(GROUND_TRUTH_DIR.glob("*.yaml"))


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text())


def _target_root(spec: dict, spec_path: Path) -> Path:
    return (REPO_ROOT / spec["target"]).resolve() if spec.get("target") else spec_path.parent


def _entries(spec: dict) -> list[dict]:
    return spec.get("vulnerabilities", [])


def _lines_claimed(entry: dict) -> list[int]:
    return [entry["line"], *entry.get("also_at", [])]


def _is_executable(path: Path, line_no: int) -> bool | None:
    """Mirror graph/evidence.py: a Razor @code body is C# and parses as C#."""
    source = path.read_text(errors="replace")
    lines = source.split("\n")
    text = lines[line_no - 1].strip()
    if not text:
        return None
    grammar = "razor" if path.suffix in (".razor", ".cshtml") else "csharp"
    column = lines[line_no - 1].find(text.split()[0])
    base = len("\n".join(lines[: line_no - 1]).encode()) + (1 if line_no > 1 else 0)
    byte_offset = base + len(lines[line_no - 1][:column].encode())

    code_block = _RAZOR_CODE_BLOCK_RE.search(source)
    if grammar == "razor" and code_block is not None:
        body_start = len(source[: code_block.end()].encode())
        if byte_offset >= body_start:
            tree = get_parser("csharp").parse(source.encode()[body_start:])
            node = tree.root_node.descendant_for_byte_range(
                byte_offset - body_start, byte_offset - body_start
            )
            return node is not None and not _node_is_non_executed(node, "csharp")
    tree = get_parser(grammar).parse(source.encode())
    node = tree.root_node.descendant_for_byte_range(byte_offset, byte_offset)
    return node is not None and not _node_is_non_executed(node, grammar)


@pytest.mark.parametrize("spec_path", SPECS, ids=lambda p: p.stem)
class TestGroundTruthSpec:
    def test_entry_ids_are_unique(self, spec_path):
        ids = [entry["id"] for entry in _entries(_load(spec_path))]
        duplicates = {name for name in ids if ids.count(name) > 1}
        assert not duplicates, f"{spec_path.name}: duplicate entry ids {duplicates}"

    def test_every_entry_declares_corpus_coverage(self, spec_path):
        """Without it, raw recall conflates 'missed it' with 'no rule exists'."""
        for entry in _entries(_load(spec_path)):
            assert entry.get("corpus_coverage"), (
                f"{spec_path.name}: {entry['id']} does not record corpus_coverage"
            )

    def test_claimed_lines_exist_and_are_executable(self, spec_path):
        spec = _load(spec_path)
        root = _target_root(spec, spec_path)
        if not root.exists():
            pytest.skip(f"benchmark checkout absent: {root}")

        problems: list[str] = []
        for entry in _entries(spec):
            path = root / entry["file"]
            if not path.is_file():
                problems.append(f"{entry['id']}: missing file {entry['file']}")
                continue
            line_count = len(path.read_text(errors="replace").split("\n"))
            for line_no in _lines_claimed(entry):
                if not 1 <= line_no <= line_count:
                    problems.append(f"{entry['id']}: line {line_no} outside {entry['file']}")
                    continue
                if _is_executable(path, line_no) is False:
                    problems.append(
                        f"{entry['id']}: {entry['file']}:{line_no} is not executable code — "
                        "a finding there would be a false positive scored as a true positive"
                    )
        assert not problems, f"{spec_path.name}:\n  " + "\n  ".join(problems)


def test_at_least_one_ground_truth_spec_exists():
    assert SPECS, "no ground truth specs found under evals/ground_truth/"


def test_razor_code_block_regex_matches_both_directives():
    assert _RAZOR_CODE_BLOCK_RE.search("@code {\n}")
    assert _RAZOR_CODE_BLOCK_RE.search("@functions {\n}")
    assert not _RAZOR_CODE_BLOCK_RE.search("@codeword {\n}")
    assert not re.search(r"^@code", "<p>@code</p>", re.MULTILINE)
