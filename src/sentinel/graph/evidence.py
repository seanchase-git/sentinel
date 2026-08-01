"""Deterministic applicability checks for deep-review evidence claims.

The generic gate proves that claimed evidence exists in the candidate's review
window. Rule-family predicates then prove only preconditions that are safe to
decide mechanically. This is deliberately a small registry keyed by CWE,
rather than one universal regex:
TLS disablement, literal secrets, and query-text flow have different semantics,
and making those semantics explicit prevents a future rule from accidentally
inheriting an unrelated heuristic.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from difflib import get_close_matches

from sentinel.graph.schemas import CandidateFinding, EvidenceLocation
from sentinel.ingest.chunker import ReviewWindow
from sentinel.retrieval.rules_store import RetrievedRule

_CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
_TLS_DISABLED_RE = re.compile(
    r"\bverify\s*=\s*False\b|\bCERT_NONE\b|\b_create_unverified_context\s*\(",
    re.IGNORECASE,
)
_ENV_READ_RE = re.compile(
    r"\bos\.environ\b|\bos\.getenv\s*\(|\bprocess\.env\b|\bgetenv\s*\(",
    re.IGNORECASE,
)
_SECRET_NAME_RE = re.compile(
    r"secret|pass(?:word|wd)?|api[_-]?key|access[_-]?token|credential|private[_-]?key",
    re.IGNORECASE,
)
_STRING_LITERAL_RE = re.compile(r"(?P<quote>['\"])(?P<value>(?:\\.|(?!\1).)*)(?P=quote)")
_ASSIGNMENT_RE = re.compile(
    r"(?:\b(?:const|let|var)\s+)?\b(?P<name>[A-Za-z_$][\w$]*)\s*=\s*(?P<rhs>.+)"
)
_INJECTION_SINK_RE = re.compile(
    r"\b(?:execute|executemany|query|raw|extra|system|exec|execSync|spawn|popen|"
    r"run|call|check_output)\s*\(",
    re.IGNORECASE,
)
_NOSQL_SINK_RE = re.compile(
    r"\b(?:find|findOne|findMany|aggregate|countDocuments|updateOne|updateMany|"
    r"deleteOne|deleteMany)\s*\(",
    re.IGNORECASE,
)
_COERCION_RE = re.compile(
    r"\b(?:String|Number|Boolean|parseInt|parseFloat|sanitize|validate)\s*\(",
    re.IGNORECASE,
)
_INTERPOLATION_RE = re.compile(r"(?:\$\{[^}]+\}|\{[^}]+\})")

# How far from its claimed line the evidence text may actually sit. Sized from
# observed off-by-two drift, where the model pointed at a comment header
# immediately above the code it meant, plus margin for a decorator or a wrapped
# signature. Small on purpose: a large window would let "the text appears
# somewhere nearby" stand in for "the model knows where the code is".
_EVIDENCE_LINE_TOLERANCE = 5


@dataclass(frozen=True)
class ApplicabilityDecision:
    accepted: bool
    reason: str | None = None


Predicate = Callable[
    [CandidateFinding, list[str], ReviewWindow, RetrievedRule], str | None
]


def _reject(reason: str) -> ApplicabilityDecision:
    return ApplicabilityDecision(accepted=False, reason=reason)


def _line_at(
    location: EvidenceLocation,
    lines: list[str],
    window: ReviewWindow,
    label: str,
) -> tuple[EvidenceLocation | None, str | None]:
    if location.line < window.start_line or location.line > window.end_line:
        return None, f"applicability_{label}_line_outside_window"
    if location.line > len(lines):
        return None, f"applicability_{label}_line_missing"
    if not location.text.strip():
        return None, f"applicability_{label}_text_empty"
    if "\n" in location.text or "\r" in location.text:
        return None, f"applicability_{label}_text_not_single_line"
    actual = lines[location.line - 1]
    if location.text in actual:
        return location, None
    # The model's line arithmetic drifts. Observed: a route handler claimed two
    # lines above its actual position, because the model pointed at the comment
    # header introducing it. Requiring exact agreement rejected a real finding
    # over those two lines.
    #
    # validation.py already assumes this drift: _locate_exact and
    # _locate_normalized search for the text and RECOMPUTE the line from where
    # it was actually found. Requiring exact agreement here made the two layers
    # contradict each other about how far the same model can be trusted.
    #
    # Search a bounded neighbourhood instead, clamped to the window, and take
    # the nearest hit. The anti-fabrication property is unchanged: the text must
    # genuinely exist near where the model said it was.
    lo = max(window.start_line, location.line - _EVIDENCE_LINE_TOLERANCE)
    hi = min(min(window.end_line, len(lines)), location.line + _EVIDENCE_LINE_TOLERANCE)
    hits = [n for n in range(lo, hi + 1) if location.text in lines[n - 1]]
    if not hits:
        return None, f"applicability_{label}_text_mismatch"
    nearest = min(hits, key=lambda n: abs(n - location.line))
    return location.model_copy(update={"line": nearest}), None


def _rule_cwes(rule: RetrievedRule) -> set[str]:
    text = f"{rule.rule_id}\n{rule.yaml_body}"
    return {match.upper() for match in _CWE_RE.findall(text)}


def _tls_disabled(
    candidate: CandidateFinding,
    lines: list[str],
    window: ReviewWindow,
    _rule: RetrievedRule,
) -> str | None:
    assert candidate.sink is not None
    if not _TLS_DISABLED_RE.search(lines[candidate.sink.line - 1]):
        return "applicability_tls_not_explicitly_disabled"
    return None


def _hardcoded_secret(
    candidate: CandidateFinding,
    lines: list[str],
    window: ReviewWindow,
    _rule: RetrievedRule,
) -> str | None:
    assert candidate.sink is not None
    sink_line = lines[candidate.sink.line - 1]
    if _ENV_READ_RE.search(sink_line):
        return "applicability_hardcoded_secret_is_environment_read"
    if not _SECRET_NAME_RE.search(sink_line):
        return "applicability_hardcoded_secret_literal_missing"
    literals = [match.group("value") for match in _STRING_LITERAL_RE.finditer(sink_line)]
    if not any(len(value.strip()) >= 6 and any(ch.isalpha() for ch in value) for value in literals):
        return "applicability_hardcoded_secret_literal_missing"
    return None


def _contains_taint(text: str, taints: set[str]) -> bool:
    for taint in taints:
        if not taint:
            continue
        if re.search(rf"(?<![\w$]){re.escape(taint)}(?![\w$])", text):
            return True
    return False


def _first_call_argument(line: str) -> str:
    """Return a conservative first call argument, respecting quotes/nesting."""
    match = _INJECTION_SINK_RE.search(line)
    if match is None:
        return ""
    start = match.end()
    depth = 0
    quote: str | None = None
    escaped = False
    for index in range(start, len(line)):
        char = line[index]
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote is not None:
            escaped = True
            continue
        if quote is not None:
            if char == quote:
                quote = None
            continue
        if char in "'\"`":
            quote = char
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            if depth == 0:
                return line[start:index]
            depth -= 1
        elif char == "," and depth == 0:
            return line[start:index]
    return line[start:]


def _is_text_construction(text: str, taints: set[str]) -> bool:
    if not _contains_taint(text, taints):
        return False
    return bool(
        _INTERPOLATION_RE.search(text)
        or ("+" in text and ("'" in text or '"' in text or "`" in text))
        or re.search(r"\.(?:format|replace)\s*\(", text)
        or re.search(r"%\s*\(?[A-Za-z_$]", text)
    )


def _injection_text_flow(
    candidate: CandidateFinding,
    lines: list[str],
    window: ReviewWindow,
    _rule: RetrievedRule,
) -> str | None:
    assert candidate.untrusted_source is not None and candidate.sink is not None
    source = candidate.untrusted_source
    sink = candidate.sink
    if source.line > sink.line:
        return "applicability_injection_source_after_sink"

    source_line = lines[source.line - 1]
    taints = {source.text.strip()}
    assignment = _ASSIGNMENT_RE.search(source_line)
    if assignment is not None and source.text in assignment.group("rhs"):
        taints.add(assignment.group("name"))

    text_tainted: set[str] = set()
    for line in lines[source.line - 1 : sink.line]:
        assignment = _ASSIGNMENT_RE.search(line)
        if assignment is not None and _contains_taint(assignment.group("rhs"), taints):
            name = assignment.group("name")
            taints.add(name)
            if _is_text_construction(assignment.group("rhs"), taints):
                text_tainted.add(name)

    sink_line = lines[sink.line - 1]
    first_arg = _first_call_argument(sink_line)
    if not first_arg:
        return "applicability_injection_sink_not_query_operation"
    if _is_text_construction(first_arg, taints):
        return None
    if _contains_taint(first_arg, text_tainted):
        return None

    # Passing the untrusted value itself as the first argument makes it query or
    # command text. Its appearance only after the first comma is a parameter
    # collection and is intentionally rejected.
    stripped_arg = first_arg.lstrip()
    if _contains_taint(first_arg, taints) and not stripped_arg.startswith(
        ("'", '"', "[", "(", "{")
    ):
        return None
    return "applicability_injection_no_query_text_flow"


def _nosql_query_flow(
    candidate: CandidateFinding,
    lines: list[str],
    window: ReviewWindow,
    _rule: RetrievedRule,
) -> str | None:
    """Require direct untrusted data in a NoSQL query object.

    NoSQL queries are structured objects, not SQL text. Treating CWE-943 as a
    text-construction predicate made every legitimate Mongo finding
    structurally impossible, especially multiline ``findOne({ ... })`` calls
    where the source expression appears after the call's opening line.
    """
    assert candidate.untrusted_source is not None and candidate.sink is not None
    start = min(candidate.untrusted_source.line, candidate.sink.line)
    end = max(candidate.untrusted_source.line, candidate.sink.line)
    region = "\n".join(lines[start - 1 : end])
    if _NOSQL_SINK_RE.search(region) is None:
        return "applicability_injection_sink_not_query_operation"
    if candidate.untrusted_source.text not in region:
        return "applicability_injection_no_query_object_flow"
    if _COERCION_RE.search(region):
        return "applicability_injection_source_is_coerced"
    return None


# Access-control weaknesses are the absence of a check, not a flow of tainted
# data, so the source/sink evidence model does not apply to them. CWE-862 is
# missing authorization and CWE-639 is authorization bypass via a user-supplied
# key; both are "no check happened here" rather than "this value reached that
# operation".
_ACCESS_CONTROL_CWES: frozenset[str] = frozenset({"CWE-306", "CWE-862", "CWE-639"})

# These weaknesses are properties of one operation/configuration rather than a
# source-to-sink flow. This list is derived from every current corpus rule, not
# just the two families found by the live regression:
# - crypto/random/comparison: CWE-208, 295, 327, 330, 338, 347
# - explicitly disabled controls/config: CWE-352, 489, 614
# - broad exposure or literal/config values: CWE-798, 915, 942
# Their sink is still mandatory and source evidence is verified when supplied.
# Unknown/new CWEs default to flow-required so expanding the corpus fails closed
# until its evidence shape is consciously classified.
_SINK_ONLY_CWES: frozenset[str] = frozenset(
    {
        "CWE-208",
        "CWE-295",
        "CWE-327",
        "CWE-330",
        "CWE-338",
        "CWE-347",
        "CWE-352",
        "CWE-489",
        "CWE-614",
        "CWE-798",
        "CWE-915",
        "CWE-942",
    }
)

_CWE_PREDICATES: dict[str, Predicate] = {
    "CWE-295": _tls_disabled,
    "CWE-798": _hardcoded_secret,
    "CWE-78": _injection_text_flow,
    "CWE-89": _injection_text_flow,
    "CWE-943": _nosql_query_flow,
}


def find_applicability_rule(
    cited_rule_id: str, rules: list[RetrievedRule]
) -> RetrievedRule | None:
    """Resolve the rule exactly as the downstream validator will.

    Applicability must not be bypassable by a near-miss ID that validation will
    later snap to a retrieved rule.
    """
    by_id = {rule.rule_id: rule for rule in rules}
    if cited_rule_id in by_id:
        return by_id[cited_rule_id]
    close = get_close_matches(cited_rule_id, list(by_id), n=2, cutoff=0.85)
    return by_id[close[0]] if len(close) == 1 else None


def requires_untrusted_source(rule: RetrievedRule) -> bool:
    """Whether this rule's vulnerability model is genuinely source-to-sink."""
    cwes = _rule_cwes(rule)
    return not bool(cwes & (_ACCESS_CONTROL_CWES | _SINK_ONLY_CWES))


def validate_applicability(
    candidate: CandidateFinding,
    source: str,
    window: ReviewWindow,
    rule: RetrievedRule,
) -> ApplicabilityDecision:
    """Verify evidence locations and mechanically decidable rule preconditions.

    Access-control rules take a different evidence shape from taint rules. A
    missing-authentication defect has no untrusted source: nothing flows
    anywhere, the defect is the ABSENCE of an enforcement step on the route.
    Demanding a source for CWE-306 made the gate structurally incapable of
    passing that whole class, and it rejected real unauthenticated-route
    findings with applicability_missing_untrusted_source. For those rules the
    enforcement reason is the evidence and the sink is the route declaration.
    """
    cwes = _rule_cwes(rule)
    access_control = bool(cwes & _ACCESS_CONTROL_CWES)

    if candidate.sink is None:
        return _reject("applicability_missing_sink")
    if requires_untrusted_source(rule) and candidate.untrusted_source is None:
        return _reject("applicability_missing_untrusted_source")

    lines = source.split("\n")
    resolved_source: EvidenceLocation | None = None
    if candidate.untrusted_source is not None:
        resolved_source, reason = _line_at(
            candidate.untrusted_source, lines, window, "source"
        )
        if reason is not None:
            return _reject(reason)
    resolved_sink, reason = _line_at(candidate.sink, lines, window, "sink")
    if reason is not None:
        return _reject(reason)
    assert resolved_sink is not None

    if access_control and not (
        candidate.auth_missing_enforcement_reason
        and candidate.auth_missing_enforcement_reason.strip()
    ):
        return _reject("applicability_auth_enforcement_reason_missing")

    predicates = {_CWE_PREDICATES[cwe] for cwe in cwes if cwe in _CWE_PREDICATES}
    resolved_candidate = candidate.model_copy(
        update={"untrusted_source": resolved_source, "sink": resolved_sink}
    )
    for predicate in predicates:
        reason = predicate(resolved_candidate, lines, window, rule)
        if reason is not None:
            return _reject(reason)
    return ApplicabilityDecision(accepted=True)


def mark_applicability_rejection(
    candidate: CandidateFinding, reason: str
) -> CandidateFinding:
    """Attach code-owned rejection metadata without corrupting the rule ID."""
    return candidate.rejected_for_applicability(reason)
