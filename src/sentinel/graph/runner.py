"""Run the review graph across a repository's files."""

import asyncio
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.graph.graph import build_graph
from sentinel.ingest.walker import SourceFile, acquire, cleanup, walk
from sentinel.models.gateway import Gateway
from sentinel.settings import FILE_CONCURRENCY

logger = logging.getLogger("sentinel.runner")


@dataclass
class RunResult:
    target: str
    started_at: float
    finished_at: float = 0.0
    file_results: list[dict[str, Any]] = field(default_factory=list)
    metrics: dict[str, Any] = field(default_factory=dict)

    @property
    def wall_seconds(self) -> float:
        return round(self.finished_at - self.started_at, 2)


def _serialize_state(state: dict[str, Any]) -> dict[str, Any]:
    """Reduce final graph state to a JSON-safe per-file record."""
    classification = state.get("classification")
    guardrail = state.get("guardrail")
    return {
        "file_path": state["file_path"],
        "status": state.get("status", "error"),
        "error": state.get("error"),
        "guardrail": guardrail.model_dump() if guardrail else None,
        "classification": classification.model_dump() if classification else None,
        "windows": state.get("windows", []),
        "triage": state.get("triage"),
        "findings": state.get("findings", []),
        "suppressed": state.get("suppressed", []),
    }


async def review_file(graph, source_file: SourceFile) -> dict[str, Any]:
    try:
        source = source_file.path.read_text(encoding="utf-8", errors="replace")
        final_state = await graph.ainvoke(
            {
                "file_path": source_file.rel_path,
                "abs_path": str(source_file.path),
                "source": source,
                "language_hint": source_file.language,
                "grammar_hint": source_file.grammar,
            }
        )
        return _serialize_state(final_state)
    except Exception as exc:  # keep the run going; the file reports as error
        logger.exception("review failed for %s", source_file.rel_path)
        return {
            "file_path": source_file.rel_path,
            "status": "error",
            "error": str(exc),
            "findings": [],
            "suppressed": [],
        }


async def review_target(
    target: str,
    languages: set[str] | None = None,
    gateway: Gateway | None = None,
) -> RunResult:
    """Review a local path or git URL end-to-end."""
    gateway = gateway or Gateway()
    graph = build_graph(gateway)
    result = RunResult(target=target, started_at=time.time())

    repo_root, tmp_dir = acquire(target)
    try:
        files = list(walk(Path(repo_root), languages))
        semaphore = asyncio.Semaphore(FILE_CONCURRENCY)

        async def bounded(source_file: SourceFile) -> dict[str, Any]:
            async with semaphore:
                logger.info("reviewing %s", source_file.rel_path)
                return await review_file(graph, source_file)

        result.file_results = list(
            await asyncio.gather(*(bounded(f) for f in files))
        )
    finally:
        cleanup(tmp_dir)

    result.finished_at = time.time()
    result.metrics = gateway.metrics.summary()
    return result
