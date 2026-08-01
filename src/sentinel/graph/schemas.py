"""Pydantic models shared across graph nodes, validation, and reports."""

from typing import Literal

from pydantic import BaseModel, Field, PrivateAttr

RiskCategory = Literal[
    "auth", "data_access", "deserialization", "injection", "secrets", "crypto",
    "xss", "csrf", "ssrf", "path_traversal", "dependency", "config",
]


class GuardrailResult(BaseModel):
    safe: bool
    category: str | None = None


class Classification(BaseModel):
    language: Literal["python", "javascript", "typescript"]
    framework: str | None = None
    risk_categories: list[RiskCategory] = Field(default_factory=list)


class TriageResult(BaseModel):
    worth_deep_review: bool
    reasoning: str


class EvidenceLocation(BaseModel):
    """One model-claimed source location, verified later against the window."""

    line: int = Field(ge=1)
    text: str = Field(min_length=1)


class CandidateFinding(BaseModel):
    """Deep-review output, before code-level validation and the judge."""

    rule_id: str
    line_start: int = Field(ge=1)
    line_end: int = Field(ge=1)
    code_snippet: str = Field(min_length=1)
    severity: Literal["low", "medium", "high", "critical"]
    explanation: str = Field(min_length=1)
    # Optional at schema-parse time so one malformed candidate can enter the
    # deterministic rejection/audit path instead of invalidating the model's
    # entire response. The applicability gate requires a sink for every rule
    # and a source only for vulnerability models that actually have data flow.
    untrusted_source: EvidenceLocation | None = None
    sink: EvidenceLocation | None = None
    auth_missing_enforcement_reason: str | None = None
    # Deterministic gate metadata is private so the model cannot manufacture a
    # suppression reason through the JSON schema. validation.py reads it to
    # create a first-class audit rejection while preserving the cited rule_id.
    _applicability_rejection_reason: str | None = PrivateAttr(default=None)

    @property
    def applicability_rejection_reason(self) -> str | None:
        return self._applicability_rejection_reason

    def rejected_for_applicability(self, reason: str) -> "CandidateFinding":
        rejected = self.model_copy(deep=True)
        rejected._applicability_rejection_reason = reason
        return rejected


class DeepReviewOutput(BaseModel):
    findings: list[CandidateFinding] = Field(default_factory=list)


class JudgeVerdict(BaseModel):
    grounded: bool
    groundedness_score: float = Field(ge=0.0, le=1.0)
    reasoning: str


class RefutationVerdict(BaseModel):
    """Adversarial judge output: a finding is rejected when it is refuted."""

    refuted: bool
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str = Field(min_length=1)
