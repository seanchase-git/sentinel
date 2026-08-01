"""Repo acquisition and file walking.

Accepts a local directory or a git URL (cloned --depth 1 into a temp dir;
works against local/LAN mirrors when air-gapped — remote URLs are a
pre-review acquisition step outside the no-network guarantee, which covers
the review pipeline itself).
"""

import shutil
import subprocess
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

EXTENSION_LANGUAGES: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}

IGNORED_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", ".mypy_cache",
    ".pytest_cache", ".ruff_cache", "dist", "build", ".next", ".nuxt",
    "coverage", ".tox", "site-packages", "vendor",
    # Build caches that hold prebundled third-party source. Reviewing these
    # burns the run on dependency code: an Angular build cache can yield more
    # files from .angular/cache/*/vite/deps than the project has source files.
    # They are large but not long-lined, so the minified-file heuristic does
    # not catch them.
    ".angular", ".cache", ".turbo", ".svelte-kit", ".parcel-cache", ".gradle",
}

# Heuristics for generated/minified files we should not review
_MAX_FILE_BYTES = 1_000_000
_MINIFIED_LINE_LENGTH = 5000

_GIT_URL_PREFIXES = ("http://", "https://", "git://", "ssh://", "git@", "file://")


class IngestError(RuntimeError):
    pass


@dataclass
class SourceFile:
    path: Path            # absolute path on disk
    rel_path: str         # path relative to the repo root (used in reports)
    language: str


def is_git_url(target: str) -> bool:
    return target.startswith(_GIT_URL_PREFIXES) or (
        target.endswith(".git") and not Path(target).exists()
    )


def acquire(target: str) -> tuple[Path, Path | None]:
    """Resolve a review target to a local directory.

    Returns (repo_root, tmp_dir); tmp_dir is non-None when we cloned and the
    caller must clean it up (see cleanup())."""
    if is_git_url(target):
        tmp_dir = Path(tempfile.mkdtemp(prefix="sentinel-clone-"))
        result = subprocess.run(
            ["git", "clone", "--depth", "1", target, str(tmp_dir / "repo")],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode != 0:
            shutil.rmtree(tmp_dir, ignore_errors=True)
            raise IngestError(f"git clone failed for {target}: {result.stderr.strip()}")
        return tmp_dir / "repo", tmp_dir

    root = Path(target).expanduser().resolve()
    if not root.is_dir():
        raise IngestError(f"review target is not a directory or git URL: {target}")
    return root, None


def cleanup(tmp_dir: Path | None) -> None:
    if tmp_dir is not None:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _looks_minified(path: Path) -> bool:
    if path.name.endswith((".min.js", ".min.css", ".bundle.js")):
        return True
    try:
        with path.open(encoding="utf-8", errors="replace") as fh:
            # inspect a bounded number of lines; any very long line marks the
            # file minified/generated (not just the first line)
            for i, line in enumerate(fh):
                if len(line) > _MINIFIED_LINE_LENGTH:
                    return True
                if i >= 50:
                    break
    except OSError:
        return True
    return False


def _escapes_root(path: Path, resolved_root: Path) -> bool:
    """True if path resolves outside the review root.

    A symlink with a reviewable extension is otherwise an arbitrary-file-read:
    point `config.js` at something outside the repo and its contents are chunked,
    embedded, sent to the models, and quoted verbatim into the report. Reviewing
    untrusted repositories is the whole use case, so the link target has to be
    proven inside the root rather than assumed.

    Checked for every file, not only ones where is_symlink() is true. A file
    reached THROUGH a symlinked directory reports is_symlink() False, so the
    per-file check would miss it. Today rglob does not descend into symlinked
    directories, but that is CPython traversal behaviour rather than a promise
    (3.13 added recurse_symlinks and moved the semantics), and containment is
    not something to leave resting on it."""
    try:
        resolved = path.resolve(strict=True)
    except OSError:  # broken link, or a symlink loop
        return True
    return not resolved.is_relative_to(resolved_root)


def walk(repo_root: Path, languages: set[str] | None = None) -> Iterator[SourceFile]:
    """Yield reviewable source files under repo_root, sorted for determinism."""
    resolved_root = repo_root.resolve()
    for path in sorted(repo_root.rglob("*")):
        if not path.is_file():
            continue
        if any(part in IGNORED_DIRS for part in path.relative_to(repo_root).parts):
            continue
        # check before stat/read: an escaping path must never be opened
        if _escapes_root(path, resolved_root):
            continue
        language = EXTENSION_LANGUAGES.get(path.suffix.lower())
        if language is None or (languages and language not in languages):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        if _looks_minified(path):
            continue
        yield SourceFile(
            path=path,
            rel_path=str(path.relative_to(repo_root)),
            language=language,
        )
