"""Pydantic schema for security rules stored as YAML under rules/."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sentinel.rules.categories import RISK_CATEGORIES, derive_risk_categories

SUPPORTED_LANGUAGES = frozenset({"python", "javascript", "typescript", "csharp", "any"})


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"low": 0, "medium": 1, "high": 2, "critical": 3}[self.value]


class RuleReference(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str
    title: str


class RuleValidationError(ValueError):
    """Raised when a rule YAML file fails schema validation."""

    def __init__(self, path: str, message: str):
        self.path = path
        super().__init__(f"{path}: {message}")


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9]+(-[a-z0-9]+)*$", min_length=3)
    taxonomy: list[dict[str, str]] = Field(min_length=1)
    title: str = Field(min_length=3)
    severity: Severity
    languages: list[str] = Field(min_length=1)
    frameworks: list[str] = Field(default_factory=list)
    description: str = Field(min_length=20)
    detection_criteria: str = Field(min_length=20)
    example_vulnerable: str = Field(min_length=10)
    example_secure: str = Field(min_length=10)
    references: list[RuleReference] = Field(default_factory=list)
    risk_categories: list[str] = Field(default_factory=list)

    @field_validator("languages")
    @classmethod
    def _known_languages(cls, v: list[str]) -> list[str]:
        unknown = set(v) - SUPPORTED_LANGUAGES
        if unknown:
            raise ValueError(
                f"unsupported languages {sorted(unknown)}; allowed: {sorted(SUPPORTED_LANGUAGES)}"
            )
        return v

    @field_validator("taxonomy")
    @classmethod
    def _known_taxonomy_kinds(cls, v: list[dict[str, str]]) -> list[dict[str, str]]:
        import re

        for entry in v:
            for kind, value in entry.items():
                if kind == "owasp":
                    if not re.fullmatch(r"A(0[1-9]|10):2021", value):
                        raise ValueError(
                            f"malformed owasp id {value!r} (expected e.g. 'A03:2021')"
                        )
                elif kind == "cwe":
                    if not re.fullmatch(r"CWE-\d+", value):
                        raise ValueError(f"malformed cwe id {value!r} (expected 'CWE-<n>')")
                else:
                    raise ValueError(f"unknown taxonomy kind {kind!r}; allowed: owasp, cwe")
        return v

    @model_validator(mode="after")
    def _resolve_risk_categories(self) -> "Rule":
        explicit = set(self.risk_categories)
        unknown = explicit - RISK_CATEGORIES
        if unknown:
            raise ValueError(
                f"unknown risk_categories {sorted(unknown)}; allowed: {sorted(RISK_CATEGORIES)}"
            )
        resolved = explicit | derive_risk_categories(self.taxonomy)
        if not resolved:
            raise ValueError(
                "no risk categories: taxonomy derives none and none declared explicitly"
            )
        self.risk_categories = sorted(resolved)
        return self

    @property
    def embedding_text(self) -> str:
        """Text embedded for retrieval: title + description + detection_criteria (PRD §6.1)."""
        return f"{self.title}\n\n{self.description}\n\n{self.detection_criteria}"

    @property
    def owasp_categories(self) -> list[str]:
        return [v for e in self.taxonomy for k, v in e.items() if k == "owasp"]

    @property
    def cwe_ids(self) -> list[str]:
        return [v for e in self.taxonomy for k, v in e.items() if k == "cwe"]

    @classmethod
    def from_yaml_dict(cls, data: dict[str, Any], path: str = "<memory>") -> "Rule":
        try:
            return cls.model_validate(data)
        except Exception as exc:
            raise RuleValidationError(path, str(exc)) from exc
