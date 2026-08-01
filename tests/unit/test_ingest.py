from pathlib import Path

import pytest

from sentinel.ingest.chunker import (
    WINDOW_TOKEN_BUDGET,
    chunk_file,
    group_windows,
)
from sentinel.ingest.walker import IngestError, acquire, cleanup, is_git_url, walk

REPO_ROOT = Path(__file__).resolve().parents[2]
FLASK_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "vulnerable_apps" / "flask_sqli"

PY_SAMPLE = '''\
import os
import sqlite3

BASE = "/data"


def first(a):
    return a + 1


def second(b):
    if b:
        return b * 2
    return 0


class Widget:
    def __init__(self, name):
        self.name = name

    def render(self):
        return f"<div>{self.name}</div>"
'''

TS_SAMPLE = """\
import express from 'express';

const app = express();

export function handler(req: express.Request, res: express.Response): void {
  res.json({ ok: true });
}

app.get('/x', handler);
"""


class TestWalker:
    def test_walk_finds_expected_fixture_files(self):
        files = list(walk(FLASK_FIXTURE))
        rel_paths = {f.rel_path for f in files}
        assert "app.py" in rel_paths
        assert "utils.py" in rel_paths
        # html template is not a reviewable language in v1
        assert not any(p.endswith(".html") for p in rel_paths)

    def test_walk_language_filter(self):
        files = list(walk(FLASK_FIXTURE, languages={"javascript"}))
        assert files == []

    def test_ignored_dirs_skipped(self, tmp_path: Path):
        (tmp_path / "node_modules" / "lib").mkdir(parents=True)
        (tmp_path / "node_modules" / "lib" / "index.js").write_text("x = 1")
        (tmp_path / "src").mkdir()
        (tmp_path / "src" / "main.js").write_text("const a = 1;")
        rel_paths = [f.rel_path for f in walk(tmp_path)]
        assert rel_paths == ["src/main.js"]

    def test_minified_files_skipped(self, tmp_path: Path):
        (tmp_path / "bundle.min.js").write_text("var a=1;")
        (tmp_path / "long_line.js").write_text("var a = " + "1 + " * 3000 + "1;")
        (tmp_path / "ok.js").write_text("const fine = true;")
        rel_paths = [f.rel_path for f in walk(tmp_path)]
        assert rel_paths == ["ok.js"]

    def test_is_git_url(self):
        assert is_git_url("https://github.com/org/repo.git")
        assert is_git_url("git@github.com:org/repo.git")
        assert is_git_url("file:///tmp/mirror.git")
        assert not is_git_url("tests/fixtures/vulnerable_apps/flask_sqli")

    def test_acquire_local_dir(self):
        root, tmp = acquire(str(FLASK_FIXTURE))
        assert tmp is None and root == FLASK_FIXTURE.resolve()

    def test_acquire_missing_target_raises(self):
        with pytest.raises(IngestError):
            acquire("/nonexistent/place")

    def test_acquire_local_git_clone_roundtrip(self, tmp_path: Path):
        import subprocess

        src = tmp_path / "srcrepo"
        src.mkdir()
        (src / "a.py").write_text("x = 1\n")
        subprocess.run(["git", "init", "-q"], cwd=src, check=True)
        subprocess.run(["git", "add", "."], cwd=src, check=True)
        subprocess.run(
            ["git", "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"],
            cwd=src,
            check=True,
        )
        root, tmp = acquire(f"file://{src}")
        try:
            assert tmp is not None
            assert [f.rel_path for f in walk(root)] == ["a.py"]
        finally:
            cleanup(tmp)
            assert not tmp.exists()


class TestChunker:
    def test_python_top_level_boundaries(self):
        chunks = chunk_file(PY_SAMPLE, "python")
        text = "\n".join(c.text for c in chunks)
        assert "def first" in text and "class Widget" in text
        for chunk in chunks:
            assert 1 <= chunk.start_line <= chunk.end_line

    def test_chunk_text_is_exact_source_slice(self):
        lines = PY_SAMPLE.split("\n")
        for chunk in chunk_file(PY_SAMPLE, "python"):
            assert chunk.text == "\n".join(lines[chunk.start_line - 1 : chunk.end_line])

    def test_chunks_are_ordered_and_non_overlapping(self):
        chunks = chunk_file(PY_SAMPLE, "python")
        for prev, cur in zip(chunks, chunks[1:], strict=False):
            assert cur.start_line > prev.end_line

    def test_typescript_parses(self):
        chunks = chunk_file(TS_SAMPLE, "typescript")
        assert chunks
        assert any("export function handler" in c.text for c in chunks)

    def test_empty_source(self):
        assert chunk_file("", "python") == []
        assert chunk_file("   \n\n", "python") == []

    def test_garbage_falls_back_to_line_windows(self):
        garbage = "\n".join(f"?!{{{i}]] ###" for i in range(200))
        chunks = chunk_file(garbage, "python")
        assert chunks, "fallback must still produce chunks"

    def test_oversized_function_split(self):
        big = "def huge():\n" + "\n".join(f"    x_{i} = {i} * 2  # padding" for i in range(2000))
        chunks = chunk_file(big, "python")
        assert len(chunks) > 1

    def test_pathological_long_lines_stay_within_budget(self):
        # one short line then several 4001-char lines (each below the minified
        # threshold) must still yield windows within the token budget
        src = "x = 1\n" + "\n".join("y = " + "a" * 3997 for _ in range(10))
        chunks = chunk_file(src, "python")
        windows = group_windows(chunks)
        assert windows
        for w in windows:
            assert w.token_estimate <= WINDOW_TOKEN_BUDGET

    def test_window_grouping_respects_budget(self):
        body = "\n".join(f"    v_{j} = {j}  # some padding text" for j in range(120))
        big = "\n\n".join(f"def f_{i}():\n{body}" for i in range(40))
        chunks = chunk_file(big, "python")
        windows = group_windows(chunks)
        assert len(windows) >= 2
        for window in windows:
            assert window.token_estimate <= WINDOW_TOKEN_BUDGET or len(window.chunks) == 1
        # windows preserve order and cover all chunks
        flattened = [c for w in windows for c in w.chunks]
        assert flattened == chunks


class TestBuildCacheExclusion:
    """Build caches hold prebundled dependency source. Reviewing them spends the
    run on third-party code, which for an Angular project can rival or exceed
    the project's own file count."""

    def test_angular_cache_excluded(self, tmp_path):
        (tmp_path / ".angular/cache/21.2.2/app/vite/deps").mkdir(parents=True)
        (tmp_path / ".angular/cache/21.2.2/app/vite/deps/rxjs.js").write_text("export const x=1;\n")
        (tmp_path / "src").mkdir()
        (tmp_path / "src/main.ts").write_text("export const y = 2;\n")
        found = {f.rel_path for f in walk(tmp_path)}
        assert found == {"src/main.ts"}

    @pytest.mark.parametrize(
        "cache_dir", [".angular", ".cache", ".turbo", ".svelte-kit", ".parcel-cache"]
    )
    def test_each_build_cache_excluded(self, tmp_path, cache_dir):
        (tmp_path / cache_dir).mkdir()
        (tmp_path / cache_dir / "vendor.js").write_text("export const v=1;\n")
        (tmp_path / "app.js").write_text("export const a=1;\n")
        assert {f.rel_path for f in walk(tmp_path)} == {"app.js"}

    def test_nested_build_cache_excluded(self, tmp_path):
        # component-level path matching, not just top level
        (tmp_path / "packages/web/.angular").mkdir(parents=True)
        (tmp_path / "packages/web/.angular/dep.js").write_text("export const d=1;\n")
        (tmp_path / "packages/web/index.js").write_text("export const i=1;\n")
        assert {f.rel_path for f in walk(tmp_path)} == {"packages/web/index.js"}


class TestSymlinkContainment:
    """A symlink with a reviewable extension is an arbitrary-file-read if
    followed: the target gets chunked, embedded, sent to the models, and quoted
    verbatim into report.json. Reviewing untrusted repos is the use case."""

    def test_symlink_escaping_the_root_is_skipped(self, tmp_path):
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secrets.js").write_text("const API_KEY = 'real-secret';\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.js").write_text("export const a = 1;\n")
        (repo / "config.js").symlink_to(outside / "secrets.js")
        found = {f.rel_path for f in walk(repo)}
        assert found == {"app.js"}, f"symlink escaped the root: {found}"

    def test_symlink_inside_the_root_is_still_reviewed(self, tmp_path):
        repo = tmp_path / "repo"
        (repo / "lib").mkdir(parents=True)
        (repo / "lib" / "real.js").write_text("export const r = 1;\n")
        (repo / "alias.js").symlink_to(repo / "lib" / "real.js")
        found = {f.rel_path for f in walk(repo)}
        assert found == {"lib/real.js", "alias.js"}

    def test_broken_symlink_is_skipped(self, tmp_path):
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.js").write_text("export const a = 1;\n")
        (repo / "dangling.js").symlink_to(repo / "nope.js")
        assert {f.rel_path for f in walk(repo)} == {"app.js"}

    def test_symlinked_directory_escaping_the_root_is_skipped(self, tmp_path):
        # NOTE: on CPython 3.12 rglob does not descend into symlinked dirs, so
        # this would pass even without the containment check. Kept because the
        # check must not regress if that traversal behaviour changes, and
        # _escapes_root is now applied to every file rather than only ones
        # where is_symlink() is true (a file reached THROUGH a linked dir
        # reports is_symlink() False).
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "vendor.js").write_text("const v = 1;\n")
        repo = tmp_path / "repo"
        repo.mkdir()
        (repo / "app.js").write_text("export const a = 1;\n")
        (repo / "linked").symlink_to(outside, target_is_directory=True)
        found = {f.rel_path for f in walk(repo)}
        assert found == {"app.js"}, f"escaped via directory symlink: {found}"
