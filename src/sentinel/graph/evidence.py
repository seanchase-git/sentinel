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

from tree_sitter_language_pack import get_parser

from sentinel.graph.schemas import CandidateFinding, EvidenceLocation
from sentinel.ingest.chunker import ReviewWindow
from sentinel.retrieval.rules_store import RetrievedRule

_CWE_RE = re.compile(r"\bCWE-\d+\b", re.IGNORECASE)
_TLS_DISABLED_RE = re.compile(
    r"\bverify\s*=\s*False\b|\bCERT_NONE\b|\b_create_unverified_context\s*\(|"
    r"DangerousAcceptAnyServerCertificateValidator|"
    r"ServerCertificateCustomValidationCallback\s*=\s*(?:\([^)]*\)|[^=;]+)=>\s*true\b|"
    r"ServerCertificateValidationCallback\s*\+=?\s*(?:\([^)]*\)|[^=;]+)=>\s*true\b",
    re.IGNORECASE,
)
_ENV_READ_RE = re.compile(
    r"\bos\.environ\b|\bos\.getenv\s*\(|\bprocess\.env\b|\bgetenv\s*\(|"
    r"\bEnvironment\.GetEnvironmentVariable\s*\(|\bGetEnvironmentVariable\s*\(",
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
# Language-agnostic query/exec operations. Keep this list NARROW: every verb
# here is accepted as "this line is a query operation" in every language, so a
# generic word admits exactly the candidates the gate exists to reject.
_SHARED_SINK_VERBS = (
    r"execute|executemany|query|raw|extra|system|exec|execSync|spawn|popen|"
    r"run|call|check_output|render_template_string"
)

# C#/.NET-only verbs. These are far too generic to apply universally: under
# IGNORECASE, Write/Parse/Start/Search/Find/Log* match ordinary Python and JS
# calls such as `f.write(user + "\n")`, which let a hallucinated injection
# finding anchored on a benign line satisfy the query-operation precondition.
_CSHARP_SINK_VERBS = (
    r"ExecuteReader(?:Async)?|ExecuteNonQuery(?:Async)?|ExecuteScalar(?:Async)?|"
    r"FromSqlRaw|ExecuteSqlRaw(?:Async)?|SqlQueryRaw|"
    # ADO.NET carries the statement in the command's FIRST constructor argument
    # (new SqlCommand(sql, connection)), which is the most common shape of C#
    # SQL injection. Without these the gate saw no query operation on the sink
    # line and rejected real findings as sink_not_query_operation.
    r"(?:Sql|Npgsql|MySql|Sqlite|Oracle|OleDb|Odbc)(?:Command|DataAdapter)|"
    r"Start|EvaluateAsync|RunAsync|Parse|RenderAsync?|Search|FindAll?|"
    r"SelectNodes?|SelectSingleNode|LoadXml|Write|WriteLine|"
    r"Log(?:Trace|Debug|Information|Warning|Error|Critical)"
)

_INJECTION_SINK_RE = re.compile(
    rf"\b(?:{_SHARED_SINK_VERBS})(?:<[^>]+>)?\s*\(",
    re.IGNORECASE,
)

_CSHARP_INJECTION_SINK_RE = re.compile(
    rf"\b(?:{_SHARED_SINK_VERBS}|{_CSHARP_SINK_VERBS})(?:<[^>]+>)?\s*\("
    r"|\b(?:CommandText|Arguments|Filter)\s*=",
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

_NON_EXECUTED_NODE_TYPES = {
    "comment", "line_comment", "block_comment", "razor_comment",
    "string_literal", "string_literal_content", "verbatim_string_literal",
    "verbatim_string_literal_content", "raw_string_literal",
    "raw_string_literal_content", "interpolated_string_text",
    "text", "raw_text",
}

# String-literal node kinds, split out of _NON_EXECUTED_NODE_TYPES because they
# get a second question asked of them: is this literal an argument to a call
# that actually runs? Comments never get that reprieve.
_STRING_NODE_TYPES = {
    "string_literal", "string_literal_content", "verbatim_string_literal",
    "verbatim_string_literal_content", "raw_string_literal",
    "raw_string_literal_content", "interpolated_string_text",
}

# Nodes that mean "a call happens here", across the four grammars in use.
_INVOCATION_NODE_TYPES = {
    "invocation_expression", "object_creation_expression", "argument", "argument_list",
    "call_expression", "call", "new_expression", "arguments",
}

_PARSER_NAMES = {
    "python": "python", "javascript": "javascript", "typescript": "tsx",
    "csharp": "csharp", "razor": "razor",
}

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
    # The evidence locations as actually FOUND in the file. The model's claimed
    # line drifts, and _line_at recomputes it from where the text really sits.
    # Downstream must carry these rather than the claim, because the judge is
    # told these lines were deterministically verified — passing the unverified
    # claim would make that statement false.
    resolved_source: EvidenceLocation | None = None
    resolved_sink: EvidenceLocation | None = None


Predicate = Callable[
    [CandidateFinding, list[str], ReviewWindow, RetrievedRule, str | None], str | None
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
    _grammar: str | None = None,
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
    _grammar: str | None = None,
) -> str | None:
    assert candidate.sink is not None
    sink_line = lines[candidate.sink.line - 1]
    if _ENV_READ_RE.search(sink_line):
        return "applicability_hardcoded_secret_is_environment_read"
    if not _SECRET_NAME_RE.search(sink_line):
        return "applicability_hardcoded_secret_literal_missing"
    literals = _literal_values(sink_line)
    if not any(len(value.strip()) >= 6 and any(ch.isalpha() for ch in value) for value in literals):
        return "applicability_hardcoded_secret_literal_missing"
    return None


def _literal_values(line: str) -> list[str]:
    """Extract ordinary, verbatim, and raw C# literals conservatively."""
    values = [match.group("value") for match in _STRING_LITERAL_RE.finditer(line)]
    values.extend(match.group(1) for match in re.finditer(r'@"((?:""|[^"])*)"', line))
    values.extend(match.group(1) for match in re.finditer(r'"""+(.*?)"""+', line))
    return values


def _node_is_non_executed(node, grammar: str | None = None) -> bool:
    current = node
    ancestry: list[str] = []
    string_literal_seen = False
    while current is not None:
        kind = current.type.lower()
        ancestry.append(kind)
        if "comment" in kind:
            # A comment never runs, whatever encloses it.
            return True
        if kind in _NON_EXECUTED_NODE_TYPES:
            if kind in _STRING_NODE_TYPES:
                # Keep walking: a literal that is an ARGUMENT to a live call is
                # part of executing code. deep_review.md already draws this
                # line — "a string literal that is never passed to an execution
                # sink is not executable ... a string that is actually passed to
                # a query, process, template, deserializer, renderer, or other
                # execution sink remains eligible" — and rejecting every literal
                # wholesale contradicted it. `JS.InvokeVoidAsync("eval", value)`
                # is the case that exposed it: the dangerous thing IS the quoted
                # argument, and the call around it really does run.
                #
                # Documentation samples are unaffected. A page's own
                # `private const string VulnerableCode = """..."""` has a
                # declaration above it, not an invocation, so it stays rejected.
                string_literal_seen = True
            else:
                return True
        current = current.parent
    if string_literal_seen:
        return not any(kind in _INVOCATION_NODE_TYPES for kind in ancestry)
    if grammar == "razor" and "element" in ancestry:
        # Plain text inside an HTML element is displayed sample content. Real
        # Razor/C# execution has a razor expression/block or C# invocation node
        # between the byte range and the element ancestor.
        return not any(
            kind.startswith("razor_") or kind in {"invocation_expression", "assignment_expression"}
            for kind in ancestry
        )
    return False


_RAZOR_COMMENT_RE = re.compile(r"@\*.*?\*@", re.DOTALL)
_RAZOR_CODE_BLOCK_RE = re.compile(r"^[ \t]*@(?:code|functions)\b[^{]*\{", re.MULTILINE)


def _csharp_block_end(source: str, open_index: int) -> int:
    """Index just past the ``}`` closing the block whose ``{`` is at open_index.

    Brace counting has to skip braces that live inside comments and string
    literals, or a block containing ``"}"`` — or a raw-string code sample, which
    is exactly what these blocks contain — terminates early and the rest of the
    file is misclassified. Returns len(source) for an unterminated block, which
    is the safe reading: the block runs to EOF.
    """
    i, depth, n = open_index, 0, len(source)
    while i < n:
        ch = source[i]
        if ch == "/" and i + 1 < n and source[i + 1] == "/":
            i = source.find("\n", i)
            if i == -1:
                return n
            continue
        if ch == "/" and i + 1 < n and source[i + 1] == "*":
            end = source.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        if source.startswith('"""', i):
            fence = len(source[i:]) - len(source[i:].lstrip('"'))
            closing = source.find('"' * fence, i + fence)
            i = n if closing == -1 else closing + fence
            continue
        if source.startswith('@"', i):
            j = i + 2
            while j < n:
                if source[j] == '"':
                    if j + 1 < n and source[j + 1] == '"':
                        j += 2
                        continue
                    break
                j += 1
            i = j + 1
            continue
        if ch in "\"'":
            j = i + 1
            while j < n and source[j] != ch:
                j += 2 if source[j] == "\\" else 1
            i = j + 1
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def _razor_code_spans(source: str) -> list[tuple[int, int]]:
    """Byte spans of every Razor ``@code``/``@functions`` body in the file.

    The tree-sitter Razor grammar cannot parse a ``@code`` block that contains a
    C# raw string literal: it yields a bare ERROR node covering the region, and
    an ERROR ancestry carries no evidence either way about whether a byte is
    executable. That is not a corner case in real Blazor code — in the
    the-most-vulnerable-dotnet-app benchmark, 43 of 64 ``.razor`` files fail to
    parse and 53 embed their own source as ``private const string ... = \"\"\"...\"\"\"``
    documentation samples.

    Treating those samples as executable would let a reviewer "find" a
    vulnerability in a page's own printed explanation of that vulnerability. The
    body of a ``@code`` block is plain C#, so the C# grammar — which does model
    raw, verbatim, and interpolated string literals — is authoritative there.

    Spans are bounded rather than open-ended. Taking "everything after the first
    @code" as C# misparses markup that follows or sits between code blocks
    (``@functions`` may appear before the markup in a .cshtml page), and would
    let a sample in a trailing ``<pre>`` read as executable C#.
    """
    # A Razor comment can contain anything, including the text "@code {". Search
    # a copy with those regions blanked out, so a commented block is not treated
    # as real C# and its contents judged executable.
    scannable = _RAZOR_COMMENT_RE.sub(lambda m: " " * len(m.group(0)), source)
    spans: list[tuple[int, int]] = []
    for match in _RAZOR_CODE_BLOCK_RE.finditer(scannable):
        open_index = source.rindex("{", match.start(), match.end())
        end_index = _csharp_block_end(source, open_index)
        spans.append(
            (
                len(source[: match.end()].encode("utf-8")),
                len(source[:end_index].encode("utf-8")),
            )
        )
    return spans


def _enclosing_span(spans: list[tuple[int, int]], start: int, end: int) -> tuple[int, int] | None:
    """The code-block span wholly containing [start, end), if any.

    Requiring containment of the WHOLE fragment matters: a fragment that begins
    in markup and runs into a code block must not be judged by the C# tree, and
    one that starts inside a block must not escape it.
    """
    for span_start, span_end in spans:
        if start >= span_start and end <= span_end:
            return (span_start, span_end)
    return None


def _resolve_node(tree, byte_start: int, byte_end: int):
    return tree.root_node.descendant_for_byte_range(byte_start, max(byte_start, byte_end - 1))


def _sink_is_executable(
    candidate: CandidateFinding,
    source: str,
    grammar: str | None,
    rule: RetrievedRule,
) -> bool:
    """Reject operations that appear only as comments, markup, or sample strings."""
    assert candidate.sink is not None
    lines = source.split("\n")
    line = lines[candidate.sink.line - 1]
    needle = candidate.sink.text
    starts = [m.start() for m in re.finditer(re.escape(needle), line)]
    if not starts:
        return False

    syntax = grammar
    if syntax is None:
        syntax = next((lang for lang in rule.languages if lang != "any"), None)
    parser_name = _PARSER_NAMES.get(syntax or "")
    if parser_name is None:
        return not line.lstrip().startswith(("#", "//", "/*", "*", "@*"))
    try:
        tree = get_parser(parser_name).parse(source.encode("utf-8"))
    except Exception:
        return not line.lstrip().startswith(("#", "//", "/*", "*", "@*"))

    # A Razor @code body is C#. Evaluate fragments inside one with the C#
    # grammar, which models raw/verbatim/interpolated literals; markup outside
    # every block stays with the Razor tree.
    source_bytes = source.encode("utf-8")
    code_spans = _razor_code_spans(source) if syntax == "razor" else []
    csharp_trees: dict[int, object] = {}

    prefix = "\n".join(lines[: candidate.sink.line - 1])
    line_byte_base = len(prefix.encode("utf-8")) + (1 if candidate.sink.line > 1 else 0)
    for char_start in starts:
        byte_start = line_byte_base + len(line[:char_start].encode("utf-8"))
        byte_end = byte_start + len(needle.encode("utf-8"))
        span = _enclosing_span(code_spans, byte_start, byte_end)
        if span is not None:
            span_start, span_end = span
            if span_start not in csharp_trees:
                try:
                    csharp_trees[span_start] = get_parser("csharp").parse(
                        source_bytes[span_start:span_end]
                    )
                except Exception:
                    csharp_trees[span_start] = None
            code_tree = csharp_trees[span_start]
            if code_tree is None:
                continue
            node = _resolve_node(code_tree, byte_start - span_start, byte_end - span_start)
            if node is not None and not _node_is_non_executed(node, "csharp"):
                return True
            continue
        node = _resolve_node(tree, byte_start, byte_end)
        if node is not None and not _node_is_non_executed(node, syntax):
            return True
    return False


def _contains_taint(text: str, taints: set[str]) -> bool:
    for taint in taints:
        if not taint:
            continue
        if re.search(rf"(?<![\w$]){re.escape(taint)}(?![\w$])", text):
            return True
    return False


def _mask_non_code(
    line: str, in_block_comment: bool = False, grammar: str | None = None
) -> tuple[str, bool]:
    """Blank out comment and string spans, preserving length and indices.

    Returns the masked line and whether it ends still inside a block comment, so
    a caller can carry that state down a window. Without it the lexer only sees
    one line and cannot know a `/*` opened above, which lets a commented sink be
    picked as the query operation for a call that is properly parameterised.

    Used only to LOCATE the operation, never to read its argument: recognising
    query-text construction depends on seeing the quotes, so the argument is
    still taken from the original text.

    Template literals are masked but their `${...}` holes are NOT. The
    interpolations are executable code and routinely contain the sink itself
    (`` `${db.query(tainted)}` ``); masking them would make a real finding
    unlocatable and turn this hardening into a source of false negatives.

    Comment syntax is per-language and MUST NOT be applied universally. `#`
    opens a comment in Python but is an ES2022 private field in JS/TS
    (`this.#pool.query(...)`) and a preprocessor directive in C#; masking from
    it unconditionally blanked real sinks. Python has no block comments at all,
    so `/*` there is ordinary text — treating it as one let a `/*` inside a
    docstring latch comment mode on and mute every sink below it in the file.
    """
    hash_comments = grammar == "python"
    # C# `#if`/`#region` are directives, and only ever at the start of a line.
    hash_directives = grammar in ("csharp", "razor")
    slash_comments = grammar in ("javascript", "typescript", "csharp", "razor")
    # An unknown grammar masks quotes only. Guessing wrong suppresses a real
    # sink and reports the file clean; declining to guess can at worst let a
    # commented-out sink through to the judge, which is the recoverable error.
    out = list(line)
    i, n = 0, len(line)
    if in_block_comment and slash_comments:
        end = line.find("*/")
        stop = n if end == -1 else end + 2
        for j in range(stop):
            out[j] = " "
        if end == -1:
            return "".join(out), True
        i = stop
    while i < n:
        ch = line[i]
        starts_hash = ch == "#" and (
            hash_comments or (hash_directives and not line[:i].strip())
        )
        starts_slash = (
            slash_comments and ch == "/" and i + 1 < n and line[i + 1] in "/*"
        )
        if starts_hash or starts_slash:
            if starts_slash and line[i + 1] == "*":
                end = line.find("*/", i + 2)
                if end == -1:
                    for j in range(i, n):
                        out[j] = " "
                    return "".join(out), True
                stop = end + 2
            else:
                stop = n
            for j in range(i, stop):
                out[j] = " "
            i = stop
            continue
        if ch == "`":
            j = i + 1
            out[i] = " "
            while j < n and line[j] != "`":
                if line[j] == "$" and j + 1 < n and line[j + 1] == "{":
                    depth, k = 0, j
                    while k < n:
                        if line[k] == "{":
                            depth += 1
                        elif line[k] == "}":
                            depth -= 1
                            if depth == 0:
                                break
                        k += 1
                    j = k + 1  # leave the interpolation intact
                    continue
                out[j] = " "
                j += 2 if line[j] == "\\" else 1
            if j < n:
                out[j] = " "
            i = j + 1
            continue
        if ch in "\"'":
            j = i + 1
            while j < n and line[j] != ch:
                j += 2 if line[j] == "\\" else 1
            for k in range(i, min(j + 1, n)):
                out[k] = " "
            i = j + 1
            continue
        i += 1
    return "".join(out), False


def _block_comment_open_at(
    lines: list[str], line_number: int, grammar: str | None = None
) -> bool:
    """Whether line_number (1-indexed) begins inside a /* ... */ comment."""
    state = False
    for line in lines[: line_number - 1]:
        _, state = _mask_non_code(line, state, grammar)
    return state


def _first_call_argument(
    line: str, in_block_comment: bool = False, grammar: str | None = None
) -> str:
    """Return a conservative first call argument, respecting quotes/nesting."""
    masked, _ = _mask_non_code(line, in_block_comment, grammar)
    sink_re = (
        _CSHARP_INJECTION_SINK_RE
        if grammar in ("csharp", "razor")
        else _INJECTION_SINK_RE
    )
    match = sink_re.search(masked)
    if match is None:
        return ""
    if "=" in match.group(0) and "(" not in match.group(0):
        return line[match.end():]
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
    grammar: str | None = None,
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
    first_arg = _first_call_argument(
        sink_line, _block_comment_open_at(lines, sink.line, grammar), grammar
    )
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
    _grammar: str | None = None,
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
        "CWE-326",
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
    "CWE-90": _injection_text_flow,
    "CWE-91": _injection_text_flow,
    "CWE-94": _injection_text_flow,
    "CWE-117": _injection_text_flow,
    "CWE-643": _injection_text_flow,
    "CWE-917": _injection_text_flow,
    "CWE-1336": _injection_text_flow,
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
    grammar: str | None = None,
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

    executable_candidate = candidate.model_copy(update={"sink": resolved_sink})
    if not _sink_is_executable(executable_candidate, source, grammar, rule):
        return _reject("applicability_sink_not_executable_code")

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
        reason = predicate(resolved_candidate, lines, window, rule, grammar)
        if reason is not None:
            return _reject(reason)
    return ApplicabilityDecision(
        accepted=True,
        resolved_source=resolved_source,
        resolved_sink=resolved_sink,
    )


def mark_applicability_rejection(
    candidate: CandidateFinding, reason: str
) -> CandidateFinding:
    """Attach code-owned rejection metadata without corrupting the rule ID."""
    return candidate.rejected_for_applicability(reason)
