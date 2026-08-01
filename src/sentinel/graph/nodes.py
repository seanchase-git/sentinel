"""Graph node implementations."""

import asyncio
import re
from contextlib import suppress
from pathlib import Path
from string import Template

from sentinel.graph.evidence import (
    find_applicability_rule,
    mark_applicability_rejection,
    validate_applicability,
)
from sentinel.graph.schemas import (
    Classification,
    DeepReviewOutput,
    GuardrailResult,
    RefutationVerdict,
    TriageResult,
)
from sentinel.ingest.chunker import ReviewWindow, chunk_file, group_windows
from sentinel.models.gateway import Gateway, GatewayError
from sentinel.retrieval.rules_store import RetrievedRule, RulesStore
from sentinel.settings import (
    CLASSIFY_TIMEOUT,
    DEEP_REVIEW_TIMEOUT_PER_WINDOW,
    GUARDRAIL_TIMEOUT,
    JUDGE_THRESHOLD,
    JUDGE_TIMEOUT_PER_FINDING,
    RETRIEVE_TIMEOUT,
    TOP_K_RULES,
    TRIAGE_TIMEOUT,
)

__all__ = [
    "DEEP_REVIEW_REASONING_ENABLED",
    "JUDGE_THRESHOLD",
    "TOP_K_RULES",
]  # re-exported for back-compat

_PROMPTS_DIR = Path(__file__).resolve().parent.parent / "models" / "prompts"

# Guardrail input truncation: :8091 runs 16384 ctx across 2 slots → ~8k
# tokens/slot; leave room for the template and verdict.
_GUARD_MAX_CONTENT_CHARS = 24_000
_CLASSIFY_MAX_CONTENT_CHARS = 2_000


def _load_template(name: str) -> Template:
    return Template((_PROMPTS_DIR / name).read_text(encoding="utf-8"))


_GUARD_TEMPLATE = _load_template("llama_guard.md")
_CLASSIFIER_TEMPLATE = _load_template("classifier.md")
_TRIAGE_TEMPLATE = _load_template("triage.md")
_DEEP_REVIEW_TEMPLATE = _load_template("deep_review.md")
_JUDGE_REFUTE_TEMPLATE = _load_template("judge_refute.md")

# Reasoning is ON for the adversarial refutation pass and OFF for generation.
#
# Measured: turning it on for generation made most files in a run fail with
# "deep-review chat_json exceeded 600.0s deadline" and the run emitted nothing.
# Reasoning traces consume the window before the JSON answer is produced, so the
# cost lands as hard timeouts rather than as slower-but-better output.
#
# The refutation pass keeps /think (see judge_finding). That is where the
# judgment is genuinely hard and where there is one short answer to produce, so
# the token budget is not competing with a list of findings.
DEEP_REVIEW_REASONING_ENABLED = False

_GUARD_VERDICT_RE = re.compile(r"^\s*(safe|unsafe)\s*$", re.IGNORECASE | re.MULTILINE)
_GUARD_CATEGORY_RE = re.compile(r"\b(S\d{1,2})\b")

# Deterministic framework detection from imports/requires — more reliable
# than asking a 1B model; the LLM value is only a fallback.
_FRAMEWORK_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("flask", re.compile(r"^\s*(from flask[.\s]|import flask\b)", re.MULTILINE)),
    ("django", re.compile(r"^\s*(from django[.\s]|import django\b)", re.MULTILINE)),
    ("fastapi", re.compile(r"^\s*(from fastapi[.\s]|import fastapi\b)", re.MULTILINE)),
    ("express", re.compile(r"""require\(\s*['"]express['"]\s*\)|from\s+['"]express['"]""")),
    # fastify before nextjs/react: a Fastify server may import neither, but a
    # file that imports fastify is a Fastify server regardless of what else it
    # pulls in.
    ("fastify", re.compile(r"""require\(\s*['"]fastify['"]\s*\)|from\s+['"]fastify['"]""")),
    ("angular", re.compile(r"""from\s+['"]@angular/""")),
    ("nextjs", re.compile(r"""from\s+['"]next(/|['"])""")),
    ("react", re.compile(r"""from\s+['"]react['"]|require\(\s*['"]react['"]\s*\)""")),
]


def detect_framework(content: str) -> str | None:
    for name, pattern in _FRAMEWORK_PATTERNS:
        if pattern.search(content):
            return name
    return None


# The only framework names retrieval can act on. rules_store reranks by exact
# string membership against a rule's `frameworks` list, so a value outside this
# set is dead weight at best and misleading in the report at worst.
KNOWN_FRAMEWORKS: frozenset[str] = frozenset(name for name, _ in _FRAMEWORK_PATTERNS)

# The 1B classifier answers with whatever it likes. Observed in real runs:
# "typescript" (a language), "vite" (a build tool), and "next" — which is
# morally right but never string-matches the corpus value "nextjs", so the
# +0.05 framework rerank silently fails to fire.
_FRAMEWORK_ALIASES: dict[str, str] = {
    "next": "nextjs",
    "next.js": "nextjs",
    "nextjs": "nextjs",
    "react.js": "react",
    "reactjs": "react",
    "express.js": "express",
    "expressjs": "express",
    "fast-api": "fastapi",
    "fast api": "fastapi",
    "angularjs": "angular",
    "angular2": "angular",
}


def normalize_framework(value: str | None) -> str | None:
    """Map a model-supplied framework name onto the corpus vocabulary.

    Anything that is not a framework the corpus knows about becomes None. A
    wrong-but-plausible value is worse than no value: it lands in the report as
    fact and can only mis-target the rerank."""
    if not value:
        return None
    name = value.strip().lower()
    name = _FRAMEWORK_ALIASES.get(name, name)
    return name if name in KNOWN_FRAMEWORKS else None


# Narrow deterministic screen for injection phrasing in file paths. Llama
# Guard judges content harm, so a benign file behind a weaponized filename
# sails through it — but no legitimate filename contains these phrases.
_FILENAME_INJECTION_RE = re.compile(
    r"ignore[_\s-]*(all[_\s-]*)?previous|disregard[_\s-]*(all[_\s-]*)?(previous|instructions)"
    r"|system[_\s-]*prompt|jailbreak|disable[_\s-]*(all[_\s-]*)?safety"
    r"|do[_\s-]*not[_\s-]*(review|report|flag)|approve[_\s-]*(everything|all)",
    re.IGNORECASE,
)


async def _guard_segment(gateway: Gateway, file_path: str, segment: str) -> GuardrailResult:
    prompt = _GUARD_TEMPLATE.substitute(file_path=file_path, content=segment)
    text, _ = await gateway.complete_raw(
        "input-guard", prompt, timeout=GUARDRAIL_TIMEOUT, max_tokens=16
    )
    match = _GUARD_VERDICT_RE.search(text)
    if match is None:
        # Unparseable guard output fails closed: treat as unsafe, category unknown
        return GuardrailResult(safe=False, category="unparseable-guard-output")
    if match.group(1).lower() == "safe":
        return GuardrailResult(safe=True)
    category_match = _GUARD_CATEGORY_RE.search(text)
    return GuardrailResult(safe=False, category=category_match.group(1) if category_match else None)


async def guardrail_check(gateway: Gateway, file_path: str, content: str) -> GuardrailResult:
    """Input guardrail (D3): deterministic filename screen, then Llama Guard 3
    via raw completion with the official template.

    Unconditional per PRD: any unsafe verdict halts the file's review. The
    ENTIRE file is scanned in bounded segments (injection can hide anywhere,
    not just in the first 24k chars), and the path is screened too."""
    if _FILENAME_INJECTION_RE.search(file_path):
        return GuardrailResult(safe=False, category="filename-injection")
    if not content:
        return GuardrailResult(safe=True)
    for offset in range(0, len(content), _GUARD_MAX_CONTENT_CHARS):
        segment = content[offset : offset + _GUARD_MAX_CONTENT_CHARS]
        result = await _guard_segment(gateway, file_path, segment)
        if not result.safe:
            return result
    return GuardrailResult(safe=True)


async def classify_file(gateway: Gateway, file_path: str, content: str) -> Classification:
    """Llama 3.2 1B classification with grammar-enforced JSON output."""
    prompt = _CLASSIFIER_TEMPLATE.substitute(
        file_path=file_path,
        content=content[:_CLASSIFY_MAX_CONTENT_CHARS],
    )
    result = await gateway.chat_json(
        "classify",
        [{"role": "user", "content": prompt}],
        Classification,
        timeout=CLASSIFY_TIMEOUT,
        max_tokens=256,
    )
    # Deterministic detection wins outright. Otherwise keep the model's guess
    # only if it names a framework the corpus can actually act on.
    detected = detect_framework(content)
    result.framework = detected if detected is not None else normalize_framework(
        result.framework
    )
    return result


async def retrieve_rules(
    gateway: Gateway,
    source: str,
    language: str,
    risk_categories: list[str],
    framework: str | None,
) -> tuple[list[ReviewWindow], list[list[RetrievedRule]]]:
    """Chunk the file, group chunks into deep-review windows, and retrieve
    top-K rules per window (union of its chunks' per-chunk retrievals,
    deduped by best score — plan D6)."""
    chunks = chunk_file(source, language)
    windows = group_windows(chunks)
    if not windows:
        return [], []

    async with asyncio.timeout(RETRIEVE_TIMEOUT):
        all_chunk_texts = [chunk.text for window in windows for chunk in window.chunks]
        # one batched embedding call rather than N sequential calls
        embeddings = await gateway.embed_queries(all_chunk_texts)

    def _query_all() -> list[list[RetrievedRule]]:
        per_window: list[list[RetrievedRule]] = []
        offset = 0
        with RulesStore() as store:
            for window in windows:
                best: dict[str, RetrievedRule] = {}
                for _chunk in window.chunks:
                    for rule in store.query_similar(
                        embeddings[offset],
                        language,
                        risk_categories or None,
                        framework=framework,
                        k=TOP_K_RULES,
                    ):
                        existing = best.get(rule.rule_id)
                        if existing is None or rule.score > existing.score:
                            best[rule.rule_id] = rule
                    offset += 1
                ranked = sorted(best.values(), key=lambda r: -r.score)[:TOP_K_RULES]
                per_window.append(ranked)
        return per_window

    # sync psycopg work off the event loop (Codex M4 review, finding 8)
    window_rules = await asyncio.to_thread(_query_all)
    return windows, window_rules


_TRIAGE_MAX_CONTENT_CHARS = 24_000
_TRIAGE_WINDOW_SAMPLE_CHARS = 1_500


def _triage_sample(source: str, windows: list[ReviewWindow]) -> str:
    """Representative content spanning every window, so triage cannot be blind
    to a vulnerable tail after a benign prefix. Samples the head of each window
    up to an overall budget."""
    if not windows or len(source) <= _TRIAGE_MAX_CONTENT_CHARS:
        return source[:_TRIAGE_MAX_CONTENT_CHARS]
    per_window = max(400, _TRIAGE_MAX_CONTENT_CHARS // len(windows))
    parts = []
    for w in windows:
        head = w.text[:min(per_window, _TRIAGE_WINDOW_SAMPLE_CHARS)]
        parts.append(f"# lines {w.start_line}-{w.end_line}\n{head}")
    return "\n\n".join(parts)[:_TRIAGE_MAX_CONTENT_CHARS]


async def triage_file(
    gateway: Gateway,
    file_path: str,
    source: str,
    windows: list[ReviewWindow],
    window_rules: list[list[RetrievedRule]],
) -> TriageResult:
    """Granite 3.3 2B: is this file worth the workhorse? Sees a sample from
    every window, so a vulnerable tail after a benign prefix is not missed."""
    titles = sorted({f"- {r.title} ({r.severity})" for rules in window_rules for r in rules})
    prompt = _TRIAGE_TEMPLATE.substitute(
        rule_titles="\n".join(titles) or "- (none retrieved)",
        file_path=file_path,
        content=_triage_sample(source, windows),
    )
    return await gateway.chat_json(
        "triage",
        [{"role": "user", "content": prompt}],
        TriageResult,
        timeout=TRIAGE_TIMEOUT,
        max_tokens=256,
    )


def _format_rules_for_prompt(rules: list[RetrievedRule]) -> str:
    blocks = []
    for i, rule in enumerate(rules, start=1):
        blocks.append(
            f"### Rule {i}: {rule.rule_id}\n"
            f"- severity: {rule.severity}\n"
            f"- title: {rule.title}\n"
            f"- detection criteria:\n{rule.detection_criteria.strip()}\n"
        )
    return "\n".join(blocks)


def _numbered(source: str, start_line: int, end_line: int) -> str:
    lines = source.split("\n")[start_line - 1 : end_line]
    return "\n".join(f"{start_line + i:>5}| {line}" for i, line in enumerate(lines))


async def deep_review_window(
    gateway: Gateway,
    file_path: str,
    language: str,
    source: str,
    window: ReviewWindow,
    rules: list[RetrievedRule],
    reasoning_enabled: bool = DEEP_REVIEW_REASONING_ENABLED,
) -> DeepReviewOutput:
    """Run Nemotron generation with configurable reasoning, then gate evidence.

    json_schema grammar is Plan A; chat_json's extract_json + repair retry is
    Plan B. The deterministic evidence gate runs before candidates enter the
    graph validator, so applicability never belongs to either judge model.
    """
    if not rules:
        return DeepReviewOutput(findings=[])
    prompt = _DEEP_REVIEW_TEMPLATE.substitute(
        rules=_format_rules_for_prompt(rules),
        file_path=file_path,
        language=language,
        numbered_content=_numbered(source, window.start_line, window.end_line),
    )
    output = await gateway.chat_json(
        "deep-review",
        [
            {"role": "system", "content": "/think" if reasoning_enabled else "/no_think"},
            {"role": "user", "content": prompt},
        ],
        DeepReviewOutput,
        timeout=DEEP_REVIEW_TIMEOUT_PER_WINDOW,
        max_tokens=8192,
    )
    gated = []
    for candidate in output.findings:
        rule = find_applicability_rule(candidate.rule_id, rules)
        if rule is None:
            # Without a resolved rule the CWE is unknown, so the per-family
            # predicates cannot run. The GENERIC evidence requirement does not
            # need the rule: a candidate with no sink has cited no location at
            # all, whatever rule it named. Mark it here rather than letting it
            # fall through to a bare "uncited_rule", which would hide that the
            # candidate was also evidence-free. The audit trail is the product;
            # a rejection reason that omits half the reason is a worse artifact
            # than a slightly redundant one.
            if candidate.sink is None:
                gated.append(
                    mark_applicability_rejection(candidate, "applicability_missing_sink")
                )
            else:
                gated.append(candidate)
            continue
        decision = validate_applicability(candidate, source, window, rule)
        if decision.accepted:
            gated.append(candidate)
        else:
            assert decision.reason is not None
            gated.append(mark_applicability_rejection(candidate, decision.reason))
    return DeepReviewOutput(findings=gated)


def _judge_context(finding: dict) -> str:
    """Judge context: the cited rule (full YAML) + the code-verified snippet."""
    return (
        f"Security rule (full definition):\n{finding['grounded_in_rule_chunk']}\n\n"
        f"Verified code snippet from {finding['file_path']} "
        f"(lines {finding['line_start']}-{finding['line_end']}):\n"
        f"{finding['code_snippet']}"
    )


def _judge_response(finding: dict) -> str:
    """The claim under judgment: the finding as the deep reviewer asserted it.

    Framed as a direct-exhibition assertion: the snippet must presently
    contain the vulnerable operation the rule describes. A speculative
    finding ("could become vulnerable if...") is consistent with the rule
    text but NOT with this claim, so the judge can refute it."""
    return (
        f"Security finding: {finding['rule_id']} "
        f"(severity {finding['claimed_severity']}) at "
        f"{finding['file_path']}:{finding['line_start']}-{finding['line_end']}. "
        f"The quoted code snippet itself directly performs the vulnerable "
        f"operation described by this rule's detection criteria — this is not "
        f"a speculative or indirect risk. {finding['explanation']}"
    )


async def judge_finding(gateway: Gateway, finding: dict) -> dict:
    """Try to refute a validated finding; emit only when refutation fails.

    Granite Guardian's groundedness criterion is retained as telemetry, not an
    applicability decision: textual entailment is too weak for that role.
    """
    prompt = _JUDGE_REFUTE_TEMPLATE.substitute(
        rule=finding["grounded_in_rule_chunk"],
        file_path=finding["file_path"],
        line_start=finding["line_start"],
        line_end=finding["line_end"],
        code_snippet=finding["code_snippet"],
        explanation=finding["explanation"],
    )
    started = asyncio.get_running_loop().time()

    async def guardian_signal() -> dict:
        try:
            grounded, score, reasoning = await gateway.judge_groundedness(
                context=_judge_context(finding),
                response=_judge_response(finding),
                timeout=JUDGE_TIMEOUT_PER_FINDING,
            )
            return {
                "grounded": grounded,
                "groundedness_score": score,
                "reasoning": reasoning,
            }
        except GatewayError as exc:
            return {"error": str(exc)}

    # Different local backends serve these models, so collect Guardian's
    # telemetry concurrently instead of doubling per-finding latency.
    guardian_task = asyncio.create_task(guardian_signal())
    try:
        refutation = await gateway.chat_json(
            "deep-review",
            [
                {"role": "system", "content": "/think"},
                {"role": "user", "content": prompt},
            ],
            RefutationVerdict,
            timeout=JUDGE_TIMEOUT_PER_FINDING,
            max_tokens=4096,
        )
    except BaseException:
        guardian_task.cancel()
        with suppress(asyncio.CancelledError):
            await guardian_task
        raise

    remaining = max(
        0.0,
        JUDGE_TIMEOUT_PER_FINDING - (asyncio.get_running_loop().time() - started),
    )
    try:
        guardian = await asyncio.wait_for(guardian_task, timeout=remaining)
    except TimeoutError:
        # Guardian is a secondary signal. Its timeout must not reverse the
        # primary adversarial decision.
        guardian = {"error": "secondary Guardian signal exceeded the judge deadline"}

    survives = not refutation.refuted
    return {
        "grounded": survives,
        # graph.py still applies JUDGE_THRESHOLD. A binary score makes that
        # legacy policy faithfully encode the new survive/refute decision.
        "groundedness_score": 1.0 if survives else 0.0,
        "reasoning": refutation.reasoning,
        "refutation": refutation.model_dump(),
        "guardian_secondary": guardian,
    }
