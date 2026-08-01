"""Performance smoke: time a ~5,000-line repo review against the 15-min budget.

Informational this pass (PRD AC7 becomes a hard gate at v1 close, once the
corpus is at full size). Assembles the two vulnerable fixture apps plus benign
filler files into a temp repo and records wall-clock.
"""

import time
from pathlib import Path

import pytest

from sentinel.graph.runner import review_target

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures" / "vulnerable_apps"
TARGET_LINES = 5000
BUDGET_SECONDS = 15 * 60

_BENIGN_MODULE = '''\
"""Benign module {n}: data helpers with no security-relevant surface."""


def transform_{n}(items):
    return [x * 2 for x in items if x is not None]


def summarize_{n}(records):
    total = sum(r.get("value", 0) for r in records)
    return {{"count": len(records), "total": total, "mean": total / max(1, len(records))}}


class Accumulator{n}:
    def __init__(self):
        self._values = []

    def add(self, value):
        self._values.append(value)
        return self

    def result(self):
        return sum(self._values)
'''


def _assemble_repo(dest: Path) -> int:
    total = 0
    for app in ("flask_sqli", "express_idor"):
        for src in (FIXTURES / app).rglob("*"):
            if src.is_file() and src.suffix in {".py", ".js"}:
                text = src.read_text()
                (dest / f"{app}_{src.name}").write_text(text)
                total += text.count("\n") + 1
    n = 0
    while total < TARGET_LINES:
        module = _BENIGN_MODULE.format(n=n)
        (dest / f"benign_{n}.py").write_text(module)
        total += module.count("\n") + 1
        n += 1
    return total


async def test_perf_smoke_5000_lines(full_stack, tmp_path):
    repo = tmp_path / "big_repo"
    repo.mkdir()
    line_count = _assemble_repo(repo)
    assert line_count >= TARGET_LINES

    start = time.perf_counter()
    run = await review_target(str(repo))
    elapsed = time.perf_counter() - start

    files = len(run.file_results)
    findings = sum(len(r.get("findings", [])) for r in run.file_results)
    print(
        f"\nperf smoke: {line_count} lines / {files} files reviewed in {elapsed:.1f}s "
        f"({findings} findings); budget {BUDGET_SECONDS}s"
    )
    # informational: warn but do not fail if over budget this pass
    if elapsed > BUDGET_SECONDS:
        print(f"WARNING: review exceeded the {BUDGET_SECONDS}s budget")
    assert files > 0
