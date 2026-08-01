"""Pure-code validation between deep review and the judge.

This module is the product's grounding guarantee: model output is never
trusted for rule citations, snippet text, or line numbers. Everything here
is deterministic; rejects become audit-trail entries, not silent drops.
"""

import difflib
import re
import uuid
from dataclasses import dataclass

from sentinel.graph.schemas import CandidateFinding
from sentinel.retrieval.rules_store import RetrievedRule

_CVE_RE = re.compile(r"CVE-\d{4}-\d{2,}", re.IGNORECASE)


def _resolve_rule_id(
    cited: str, rules_by_id: dict[str, RetrievedRule]
) -> tuple[RetrievedRule | None, str | None]:
    """Resolve a cited rule_id to a retrieved rule.

    Exact match preferred. Otherwise, if the citation is a close, UNAMBIGUOUS
    match to exactly one retrieved id (models transcribe long kebab ids
    imperfectly, e.g. a01→a14), snap to it and return a correction note. The
    judge still independently verifies groundedness against the snapped rule,
    so a wrong snap is caught downstream. Ambiguous or distant citations are
    left unresolved (→ uncited_rule)."""
    exact = rules_by_id.get(cited)
    if exact is not None:
        return exact, None
    close = difflib.get_close_matches(cited, list(rules_by_id), n=2, cutoff=0.85)
    if len(close) == 1:
        snapped = rules_by_id[close[0]]
        return snapped, f"rule_id_corrected: cited {cited!r} → {close[0]!r}"
    return None, None


@dataclass
class ValidationOutcome:
    accepted: list[dict]     # ValidatedFinding dicts (judge not yet run)
    rejected: list[dict]     # Suppressed dicts with stage="validator"


Bounds = tuple[int, int] | None  # (win_start_line, win_end_line), 1-indexed inclusive


def _in_bounds(start_line: int, end_line: int, bounds: Bounds) -> bool:
    if bounds is None:
        return True
    return start_line >= bounds[0] and end_line <= bounds[1]


def _pick_nearest(
    spans: list[tuple[int, int]], claimed: int, bounds: Bounds
) -> tuple[int, int] | None:
    in_range = [s for s in spans if _in_bounds(s[0], s[1], bounds)]
    if not in_range:
        return None
    return min(in_range, key=lambda s: abs(s[0] - claimed))


def _locate_exact(
    source: str, snippet: str, claimed: int, bounds: Bounds
) -> tuple[int, int] | None:
    """Locate snippet as an exact substring, within bounds, nearest the claimed
    line. Returns a 1-indexed line range."""
    spans: list[tuple[int, int]] = []
    idx = source.find(snippet)
    while idx != -1:
        start_line = source.count("\n", 0, idx) + 1
        spans.append((start_line, start_line + snippet.count("\n")))
        idx = source.find(snippet, idx + 1)
    return _pick_nearest(spans, claimed, bounds)


def _locate_normalized(
    source: str, snippet: str, claimed: int, bounds: Bounds
) -> tuple[int, int, str] | None:
    """Whitespace-normalized line-sequence match, tolerant of blank lines
    between snippet lines. Returns (start, end, exact_source_text) so the
    emitted snippet is always verbatim source; picks the occurrence nearest the
    claimed line within bounds."""
    snippet_lines = [ln.strip() for ln in snippet.split("\n") if ln.strip()]
    if not snippet_lines:
        return None
    source_lines = source.split("\n")
    stripped = [ln.strip() for ln in source_lines]
    matches: list[tuple[int, int]] = []  # (start_idx, end_idx) 0-indexed inclusive
    for start in range(len(source_lines)):
        if stripped[start] != snippet_lines[0]:
            continue
        # walk forward, skipping blank source lines, matching each snippet line
        si = 0
        j = start
        while j < len(source_lines) and si < len(snippet_lines):
            if not stripped[j]:
                j += 1
                continue
            if stripped[j] != snippet_lines[si]:
                break
            si += 1
            j += 1
        if si == len(snippet_lines):
            matches.append((start, j - 1))
    spans = [(s + 1, e + 1) for s, e in matches]
    picked = _pick_nearest(spans, claimed, bounds)
    if picked is None:
        return None
    exact = "\n".join(source_lines[picked[0] - 1 : picked[1]])
    return picked[0], picked[1], exact


# Lines the model writes to mean "some source omitted here". Deep review does
# this even when told to quote verbatim, and it used to kill the finding
# outright: valid findings were rejected over formatting rather than substance.
_ELISION_RE = re.compile(
    r"^\s*(?:\.\.\.|…|(?://|#)\s*(?:\.\.\.|…).*|/\*\s*(?:\.\.\.|…)\s*\*/)\s*$"
)

# The form that actually shows up: a collapsed brace body on ONE line, as in
#   app.post('/items', async (req) => { ... });
#   export function handleRequest(id, payload) { ... }
# A whole-line ellipsis check misses these entirely, and this shape is what
# killed those findings. Split into the text up to and including the brace, and
# the text from the closing brace on, then treat the two halves as fragments
# either side of a gap.
_INLINE_ELISION_RE = re.compile(r"^(?P<pre>.*\{)\s*(?:\.\.\.|…)\s*(?P<post>\}.*)$")

# An elided snippet that resolves to a span this long stopped being a citation
# and became a region. Reject rather than emit a finding pointing at 80 lines.
_MAX_ELIDED_SPAN_LINES = 60


def _locate_elided(
    source: str, snippet: str, claimed: int, bounds: Bounds
) -> tuple[int, int, str] | None:
    """Locate a snippet the model wrote with '...' standing in for omitted code.

    Every non-elision line must still appear in the real source, in order,
    inside the window. Only the *gaps* are tolerated. The emitted snippet is
    the contiguous source span the fragments bracket, so what lands in the
    report remains verbatim source and the grounding guarantee is unchanged.
    """
    fragments: list[list[str]] = []
    current: list[str] = []
    for line in snippet.split("\n"):
        if _ELISION_RE.match(line):
            if current:
                fragments.append(current)
                current = []
            continue
        inline = _INLINE_ELISION_RE.match(line)
        if inline:
            # "foo() { ... }" becomes fragment ["foo() {"] then fragment ["}"]
            current.append(inline.group("pre").strip())
            fragments.append(current)
            current = [inline.group("post").strip()]
        elif line.strip():
            current.append(line.strip())
    if current:
        fragments.append(current)
    # Fewer than two fragments means there was no real elision to bridge, and
    # the earlier locators already had their chance.
    if len(fragments) < 2:
        return None

    source_lines = source.split("\n")
    stripped = [ln.strip() for ln in source_lines]

    def match_at(frag: list[str], start: int) -> int | None:
        """End index (0-indexed, inclusive) if frag matches from start."""
        si, j = 0, start
        while j < len(stripped) and si < len(frag):
            if not stripped[j]:
                j += 1
                continue
            if stripped[j] != frag[si]:
                return None
            si += 1
            j += 1
        return j - 1 if si == len(frag) else None

    spans: list[tuple[int, int]] = []
    for start in range(len(stripped)):
        first_end = match_at(fragments[0], start)
        if first_end is None:
            continue
        cursor = first_end + 1
        for frag in fragments[1:]:
            nxt = None
            for probe in range(cursor, len(stripped)):
                nxt = match_at(frag, probe)
                if nxt is not None:
                    cursor = nxt + 1
                    break
            if nxt is None:
                cursor = None
                break
        if cursor is None:
            continue
        # A collapsed function body can bracket a span far too long to quote:
        # `app.put('/items/:id', async (req) => { ... });` can span most of a
        # file. Citing ninety lines is not a citation, but dropping the finding
        # loses a real defect. Fall back to the opening fragment, which is the
        # line the finding is actually about.
        if cursor - start > _MAX_ELIDED_SPAN_LINES:
            spans.append((start + 1, first_end + 1))
        else:
            spans.append((start + 1, cursor))
    picked = _pick_nearest(spans, claimed, bounds)
    if picked is None:
        return None
    exact = "\n".join(source_lines[picked[0] - 1 : picked[1]])
    return picked[0], picked[1], exact


def _cited_cves(text: str) -> set[str]:
    return {m.upper() for m in _CVE_RE.findall(text)}


def _framework_mismatch(rule: RetrievedRule, detected: str | None) -> str | None:
    """Reject a framework-specific rule cited against a different framework.

    Retrieval offers rules by language and risk category, so a Django rule
    reaches a file that imports sqlite3 and no Django, and a Next.js rule
    reaches every Fastify server. The model cites them, the judge finds them
    textually grounded, and a wrong-framework rule lands in the report.

    Only fires when detection is confident. `detected is None` stays permissive,
    because guessing costs recall and the detector deliberately reports nothing
    rather than guess."""
    if detected is None or not rule.frameworks:
        return None
    if detected in rule.frameworks:
        return None
    return (
        f"framework_mismatch: rule declares {sorted(rule.frameworks)} but the file "
        f"was detected as {detected!r}"
    )


def validate_findings(
    candidates: list[CandidateFinding],
    source: str,
    file_path: str,
    retrieved_rules: list[RetrievedRule],
    candidate_windows: list[int] | None = None,
    window_rules: list[list[RetrievedRule]] | None = None,
    window_bounds: list[tuple[int, int]] | None = None,
    detected_framework: str | None = None,
) -> ValidationOutcome:
    """Validate deep-review candidates.

    When candidate_windows/window_rules/window_bounds are supplied, each
    candidate is validated against ONLY its originating window's retrieved
    rules and its snippet is located within that window's line span (plan D6
    grounding boundary). Without them, all candidates validate against the
    flat retrieved_rules set (used by unit tests)."""
    flat_rules_by_id = {r.rule_id: r for r in retrieved_rules}
    accepted: list[dict] = []
    rejected: list[dict] = []
    seen: set[tuple[str, int, int]] = set()

    for i, candidate in enumerate(candidates):
        raw = candidate.model_dump()

        def reject(reason: str, raw: dict = raw) -> None:
            rejected.append(
                {"stage": "validator", "reason": reason, "candidate": raw, "judge": None}
            )

        # Applicability is decided in code while the originating ReviewWindow
        # object is still available. Carry that decision as private candidate
        # metadata so the audit reason is first-class and the cited rule_id
        # remains truthful. The private attribute is absent from the model JSON
        # schema, so deep review cannot manufacture a suppression reason.
        applicability_reason = candidate.applicability_rejection_reason
        if applicability_reason is not None:
            reject(applicability_reason)
            continue

        if candidate_windows is not None and window_rules is not None:
            widx = candidate_windows[i]
            rules_by_id = {r.rule_id: r for r in window_rules[widx]}
            bounds: Bounds = window_bounds[widx] if window_bounds else None
        else:
            rules_by_id = flat_rules_by_id
            bounds = None

        # 1. rule citation must come from THIS window's retrieved set (with
        #    unambiguous near-miss correction for imperfectly transcribed ids)
        rule, correction_note = _resolve_rule_id(candidate.rule_id, rules_by_id)
        if rule is None:
            reject(f"uncited_rule: {candidate.rule_id!r} is not in the window's retrieved rules")
            continue
        # 1b. a framework-specific rule must match the file's framework
        mismatch = _framework_mismatch(rule, detected_framework)
        if mismatch is not None:
            reject(mismatch)
            continue

        notes: list[str] = []
        if correction_note:
            notes.append(correction_note)

        # 2. snippet must exist in the source within the window, nearest the
        #    model's claimed line; recompute line numbers from where it's found
        snippet = candidate.code_snippet
        located = _locate_exact(source, snippet, candidate.line_start, bounds)
        if located is not None:
            line_start, line_end = located
        else:
            normalized = _locate_normalized(source, snippet, candidate.line_start, bounds)
            if normalized is not None:
                line_start, line_end, snippet = normalized
            else:
                # last resort: the model elided the middle with "...". Every
                # quoted line must still be real source in order; only the gap
                # is forgiven, and the snippet is replaced with the real span.
                elided = _locate_elided(source, snippet, candidate.line_start, bounds)
                if elided is None:
                    reject("snippet_not_found: code_snippet not present in the source window")
                    continue
                line_start, line_end, snippet = elided
                notes.append(
                    "elided_snippet: model omitted lines with an ellipsis; "
                    "snippet replaced with the verbatim source span it brackets"
                )

        # 4. invented CVEs: any CVE not present in the cited rule's YAML
        rule_cves = _cited_cves(rule.yaml_body)
        invented = _cited_cves(candidate.explanation) - rule_cves
        if invented:
            reject(f"invented_cve: {sorted(invented)} not present in cited rule")
            continue

        # 5. severity: emit the rule's declared severity; keep the model's
        #    claim for the judge and the audit trail (no silent clamping)
        if candidate.severity != rule.severity:
            notes.append(
                f"severity_mismatch: model claimed {candidate.severity!r}, "
                f"rule declares {rule.severity!r}"
            )

        # dedupe identical (rule, exact span) findings across windows
        key = (rule.rule_id, line_start, line_end)
        if key in seen:
            reject("duplicate_finding: same rule and exact location already reported")
            continue
        seen.add(key)

        finding = {
            "finding_id": str(uuid.uuid4()),
            "rule_id": rule.rule_id,
            "file_path": file_path,
            "line_start": line_start,
            "line_end": line_end,
            "code_snippet": snippet,
            "severity": rule.severity,
            "claimed_severity": candidate.severity,
            "explanation": candidate.explanation,
            "grounded_in_rule_chunk": rule.yaml_body,
            "judge": None,
        }
        if notes:
            finding["validator_notes"] = notes
        accepted.append(finding)

    return ValidationOutcome(accepted=accepted, rejected=rejected)
