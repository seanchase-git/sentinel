"""Assemble the final report structure from a RunResult."""

import time
from typing import Any

from sentinel import __version__
from sentinel.graph.runner import RunResult
from sentinel.graph.schemas import GUARD_CATEGORY_LABELS
from sentinel.models.registry import load_registry
from sentinel.settings import JUDGE_THRESHOLD, TOP_K_RULES

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def severity_rank(severity: str) -> int:
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return len(SEVERITY_ORDER)


def filter_by_severity(findings: list[dict], severities: set[str] | None) -> list[dict]:
    if not severities:
        return findings
    return [f for f in findings if f["severity"] in severities]


def build_report(
    run: RunResult,
    severities: set[str] | None = None,
) -> dict[str, Any]:
    registry = load_registry()
    findings: list[dict] = []
    suppressed: list[dict] = []
    rejected_inputs: list[dict] = []
    input_warnings: list[dict] = []
    per_file: list[dict] = []

    for record in run.file_results:
        file_findings = filter_by_severity(record.get("findings", []), severities)
        findings.extend(file_findings)
        suppressed.extend(
            {**s, "file_path": record["file_path"]} for s in record.get("suppressed", [])
        )
        guard = record.get("guardrail") or {}
        if record.get("status") == "blocked_unsafe":
            rejected_inputs.append(
                {
                    "file_path": record["file_path"],
                    "category": guard.get("category"),
                    "note": "input rejected by guardrail; file was not reviewed",
                }
            )
        # An advisory is the opposite of a rejection: the guardrail objected, the
        # objection was judged not to be grounds for refusing source code, and
        # the file was reviewed normally. Reported so that decision is visible
        # rather than silently applied.
        for category in guard.get("advisories") or []:
            label = GUARD_CATEGORY_LABELS.get(category, category)
            input_warnings.append(
                {
                    "file_path": record["file_path"],
                    "category": category,
                    "label": label,
                    "note": (
                        f"guardrail flagged {category} ({label}); reviewing code that "
                        "abuses interpreters is this tool's purpose, so the file was "
                        "reviewed. Confirm the construct is intended."
                    ),
                }
            )
        per_file.append(
            {
                "file_path": record["file_path"],
                "status": record.get("status"),
                "error": record.get("error"),
                "classification": record.get("classification"),
                "triage": record.get("triage"),
                "windows": record.get("windows", []),
                "guardrail_advisories": guard.get("advisories") or [],
                "finding_count": len(file_findings),
            }
        )

    findings.sort(key=lambda f: (severity_rank(f["severity"]), f["file_path"], f["line_start"]))

    # A candidate the judge never answered for was NOT suppressed by a decision,
    # so it does not belong in the same list as candidates that were judged and
    # rejected. It is quarantined instead: it passed deterministic validation and
    # is simply unadjudicated. Keeping it inside suppressed_candidates would let a
    # precision number silently rest on candidates nobody ever ruled on.
    unadjudicated = [s for s in suppressed if (s.get("judge") or {}).get("judge_unavailable")]
    suppressed = [s for s in suppressed if not (s.get("judge") or {}).get("judge_unavailable")]

    status_counts: dict[str, int] = {}
    for record in run.file_results:
        status = record.get("status", "error")
        status_counts[status] = status_counts.get(status, 0) + 1

    return {
        "run": {
            "target": run.target,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z", time.localtime(run.started_at)),
            "sentinel_version": __version__,
            "wall_seconds": run.wall_seconds,
            "models": {
                alias: {
                    "role": m.role,
                    "developer": m.developer,
                    "origin": m.origin,
                    "hf_repo": m.hf_repo,
                    # Basename only. The absolute path is machine-specific and
                    # embeds the operator's home directory, which then ships in
                    # every report and every example report committed to a repo.
                    # hf_repo already identifies the model unambiguously.
                    "gguf": m.gguf_path.name,
                }
                for alias, m in registry.models.items()
            },
            "thresholds": {
                "judge_groundedness": JUDGE_THRESHOLD,
                "retrieval_top_k": TOP_K_RULES,
            },
            "severity_filter": sorted(severities) if severities else None,
        },
        "summary": {
            "files_reviewed": len(run.file_results),
            "file_status_counts": status_counts,
            "findings": len(findings),
            "findings_by_severity": {
                sev: sum(1 for f in findings if f["severity"] == sev)
                for sev in SEVERITY_ORDER
                if any(f["severity"] == sev for f in findings)
            },
            "suppressed_candidates": len(suppressed),
            "judge_unavailable": len(unadjudicated),
            "rejected_inputs": len(rejected_inputs),
            "input_warnings": len(input_warnings),
            # False whenever this run cannot account for the whole target: a
            # candidate never got a verdict, OR a file never finished review.
            # Both mean `findings` is an undercount, and a consumer reading
            # `complete` must not have to also cross-check file_status_counts.
            "complete": not unadjudicated and not status_counts.get("error"),
        },
        "findings": findings,
        "suppressed_candidates": suppressed,
        "unadjudicated_candidates": unadjudicated,
        "rejected_inputs": rejected_inputs,
        "input_warnings": input_warnings,
        "files": per_file,
    }
