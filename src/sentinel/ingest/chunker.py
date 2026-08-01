"""AST-aware file chunking (tree-sitter) with deep-review window grouping.

Chunks: one per top-level function/class plus a module-level chunk for
imports and loose statements. Adjacent small chunks merge up to
~MERGE_TARGET_TOKENS; oversized ones split by line window. Parse failures
fall back to a sliding line window. Chunks are then grouped into
deep-review windows of at most WINDOW_TOKEN_BUDGET tokens (plan D6): each
window is retrieved and deep-reviewed independently so a large multi-risk
file can't lose rules to another region's top-K budget.
"""

from dataclasses import dataclass, field

from tree_sitter_language_pack import get_parser

# ~4 chars/token is close enough for budgeting purposes
_CHARS_PER_TOKEN = 4
MERGE_TARGET_TOKENS = 1_200
WINDOW_TOKEN_BUDGET = 8_000
FALLBACK_WINDOW_LINES = 80
FALLBACK_OVERLAP_LINES = 15

_TS_LANGUAGE = {"python": "python", "javascript": "javascript", "typescript": "tsx"}

_TOP_LEVEL_NODES = {
    "python": {"function_definition", "class_definition", "decorated_definition"},
    "javascript": {
        "function_declaration", "class_declaration", "generator_function_declaration",
        "lexical_declaration", "variable_declaration", "export_statement",
        "expression_statement",
    },
    "typescript": {
        "function_declaration", "class_declaration", "generator_function_declaration",
        "lexical_declaration", "variable_declaration", "export_statement",
        "expression_statement", "interface_declaration", "type_alias_declaration",
        "enum_declaration", "module", "ambient_declaration",
    },
}


@dataclass
class CodeChunk:
    text: str
    start_line: int  # 1-indexed, inclusive
    end_line: int    # 1-indexed, inclusive

    @property
    def token_estimate(self) -> int:
        return max(1, len(self.text) // _CHARS_PER_TOKEN)


@dataclass
class ReviewWindow:
    chunks: list[CodeChunk] = field(default_factory=list)

    @property
    def start_line(self) -> int:
        return min(c.start_line for c in self.chunks)

    @property
    def end_line(self) -> int:
        return max(c.end_line for c in self.chunks)

    @property
    def token_estimate(self) -> int:
        return sum(c.token_estimate for c in self.chunks)

    @property
    def text(self) -> str:
        return "\n\n".join(c.text for c in self.chunks)


def _line_window_chunks(lines: list[str]) -> list[CodeChunk]:
    chunks = []
    step = FALLBACK_WINDOW_LINES - FALLBACK_OVERLAP_LINES
    for start in range(0, len(lines), step):
        end = min(start + FALLBACK_WINDOW_LINES, len(lines))
        text = "\n".join(lines[start:end])
        if text.strip():
            chunks.append(CodeChunk(text=text, start_line=start + 1, end_line=end))
        if end == len(lines):
            break
    return chunks


def _split_text_to_budget(text: str, budget_chars: int) -> list[str]:
    """Split a single overlong line into <=budget_chars pieces on char count."""
    return [text[i : i + budget_chars] for i in range(0, len(text), budget_chars)] or [""]


def _split_oversized(chunk: CodeChunk, budget_tokens: int) -> list[CodeChunk]:
    if chunk.token_estimate <= budget_tokens:
        return [chunk]
    budget_chars = budget_tokens * _CHARS_PER_TOKEN
    lines = chunk.text.split("\n")
    pieces: list[CodeChunk] = []
    buf: list[str] = []
    buf_start = chunk.start_line

    def flush(end_line: int) -> None:
        nonlocal buf, buf_start
        if buf and "\n".join(buf).strip():
            pieces.append(
                CodeChunk(text="\n".join(buf), start_line=buf_start, end_line=end_line)
            )
        buf = []

    for i, line in enumerate(lines):
        line_no = chunk.start_line + i
        # a single pathological line larger than the budget is split in place
        if len(line) > budget_chars:
            flush(line_no - 1)
            for frag in _split_text_to_budget(line, budget_chars):
                if frag.strip():
                    pieces.append(CodeChunk(text=frag, start_line=line_no, end_line=line_no))
            buf_start = line_no + 1
            continue
        prospective = sum(len(x) + 1 for x in buf) + len(line)
        if buf and prospective > budget_chars:
            flush(line_no - 1)
            buf_start = line_no
        buf.append(line)
    flush(chunk.start_line + len(lines) - 1)
    return pieces or [chunk]


def chunk_file(source: str, language: str) -> list[CodeChunk]:
    """Chunk source text by top-level AST boundaries with fallback."""
    lines = source.split("\n")
    if not source.strip():
        return []
    try:
        parser = get_parser(_TS_LANGUAGE[language])
        tree = parser.parse(source.encode("utf-8"))
        root = tree.root_node
    except Exception:
        return _line_window_chunks(lines)
    if root.has_error and not root.children:
        return _line_window_chunks(lines)

    # Cut the file into contiguous segments at top-level definition
    # boundaries. Gaps between definitions (imports, loose statements,
    # blank lines) become module segments — every chunk's text is an exact
    # slice of the source, so start/end lines always reproduce the text.
    top_level = _TOP_LEVEL_NODES[language]
    def_ranges: list[tuple[int, int]] = []  # 0-indexed rows, inclusive
    for node in root.children:
        start_row, end_row = node.start_point[0], node.end_point[0]
        if node.type in top_level and (end_row - start_row) >= 1:
            if def_ranges and start_row <= def_ranges[-1][1]:
                continue  # overlapping (e.g. decorated) — keep the first
            def_ranges.append((start_row, end_row))

    segments: list[tuple[int, int]] = []
    cursor = 0
    for start_row, end_row in def_ranges:
        if start_row > cursor:
            segments.append((cursor, start_row - 1))
        segments.append((start_row, end_row))
        cursor = end_row + 1
    if cursor <= len(lines) - 1:
        segments.append((cursor, len(lines) - 1))

    def _slice(start_row: int, end_row: int) -> CodeChunk:
        return CodeChunk(
            text="\n".join(lines[start_row : end_row + 1]),
            start_line=start_row + 1,
            end_line=end_row + 1,
        )

    raw_chunks = [
        c for s, e in segments if (c := _slice(s, e)).text.strip()
    ]
    if not raw_chunks:
        return _line_window_chunks(lines)

    # merge adjacent small chunks (re-slicing keeps contiguity), split oversized
    merged: list[CodeChunk] = []
    for chunk in raw_chunks:
        for piece in _split_oversized(chunk, MERGE_TARGET_TOKENS):
            if (
                merged
                and merged[-1].token_estimate + piece.token_estimate <= MERGE_TARGET_TOKENS
                and piece.start_line == merged[-1].end_line + 1
            ):
                merged[-1] = _slice(merged[-1].start_line - 1, piece.end_line - 1)
            else:
                merged.append(piece)
    return merged


def group_windows(chunks: list[CodeChunk]) -> list[ReviewWindow]:
    """Group chunks into deep-review windows under the token budget (D6).

    Any chunk still exceeding the budget (pathological input) is hard-split by
    character count so every emitted window is within budget."""
    windows: list[ReviewWindow] = []
    current = ReviewWindow()
    for chunk in chunks:
        for piece in _split_oversized(chunk, WINDOW_TOKEN_BUDGET):
            if (
                current.chunks
                and current.token_estimate + piece.token_estimate > WINDOW_TOKEN_BUDGET
            ):
                windows.append(current)
                current = ReviewWindow()
            current.chunks.append(piece)
    if current.chunks:
        windows.append(current)
    return windows
