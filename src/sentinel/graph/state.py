"""Graph state for a single file's review."""

from typing import Any, Literal, TypedDict

from sentinel.graph.schemas import (
    CandidateFinding,
    Classification,
    GuardrailResult,
    JudgeVerdict,
)
from sentinel.retrieval.rules_store import RetrievedRule

FileStatus = Literal["completed", "blocked_unsafe", "triaged_clean", "error"]


class ValidatedFinding(TypedDict):
    finding_id: str
    rule_id: str
    file_path: str
    line_start: int
    line_end: int
    code_snippet: str
    severity: str                 # rule's declared severity (emitted)
    claimed_severity: str         # model's original claim (audit)
    explanation: str
    grounded_in_rule_chunk: str   # full rule YAML body
    judge: JudgeVerdict | None


class Suppressed(TypedDict):
    stage: Literal["validator", "judge"]
    reason: str
    candidate: dict[str, Any]
    judge: dict[str, Any] | None


class WindowReview(TypedDict):
    start_line: int
    end_line: int
    rule_ids: list[str]


class FileReviewState(TypedDict, total=False):
    # inputs
    file_path: str                # relative path, used in reports and prompts
    abs_path: str
    source: str
    language_hint: str            # from the walker (extension-based)

    # node outputs
    guardrail: GuardrailResult
    classification: Classification
    windows: list[WindowReview]                     # provenance of window split
    _window_objects: Any                            # live ReviewWindow objs (cleared at emit)
    window_rules: list[list[RetrievedRule]]         # rules per window
    triage: dict[str, Any]                          # {worth_deep_review, reasoning}
    candidate_findings: list[CandidateFinding]
    _candidate_windows: list[int]                   # window index per candidate
    validated_findings: list[ValidatedFinding]      # post-validator, pre/post judge
    suppressed: list[Suppressed]
    findings: list[ValidatedFinding]                # final, judge-approved

    status: FileStatus
    error: str | None
