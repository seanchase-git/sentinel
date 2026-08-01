"""Single choke point for all model calls, via the LiteLLM gateway.

Every LLM and embedding request in Sentinel goes through this module —
timeouts, structured output, retry-on-invalid-JSON, and metrics live here.
The base URL always resolves to localhost (PRD: no cloud APIs, ever).
"""

import asyncio
import json
import math
import os
import re
from contextlib import asynccontextmanager
from typing import Any, TypeVar

from openai import APIError, AsyncOpenAI
from pydantic import BaseModel, ValidationError

from sentinel.metrics import MetricsCollector
from sentinel.netguard import require_loopback
from sentinel.settings import (
    EMBED_HARD_INPUT_BYTES,
    EMBED_SOFT_INPUT_BYTES,
    SLOT_ACQUIRE_TIMEOUT,
)

GATEWAY_BASE_URL = os.environ.get("SENTINEL_GATEWAY_BASE_URL", "http://127.0.0.1:8100")
GATEWAY_API_KEY = os.environ.get("SENTINEL_GATEWAY_API_KEY", "sk-sentinel-local-dev")

EMBEDDING_DIM = 768
_DOC_PREFIX = "search_document: "
_QUERY_PREFIX = "search_query: "

# llama.cpp's two ways of saying "this embedding input does not fit"
_EMBED_OVERFLOW_RE = re.compile(
    r"larger than the max context size|too large to process", re.IGNORECASE
)


class _EmbedInputTooLarge(RuntimeError):
    """Internal: embedding input exceeded the backend's context/batch."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


def _truncate_utf8(text: str, max_bytes: int) -> tuple[str, bool]:
    """Cut text to at most max_bytes of UTF-8, never splitting a character.

    Bounding bytes bounds tokens: no tokenizer emits more tokens than the input
    has bytes, since every token maps to at least one. That makes this a
    guarantee rather than the character-count estimate the chunker uses for
    review windows, which under-counts symbol-dense source by up to 2x.
    """
    raw = text.encode("utf-8")
    if len(raw) <= max_bytes:
        return text, False
    return raw[:max_bytes].decode("utf-8", errors="ignore"), True

T = TypeVar("T", bound=BaseModel)


class GatewayError(RuntimeError):
    pass


def _load_slot_limits() -> dict[str, int]:
    """Concurrent slots each backend actually serves, from the registry.

    Read from the same `parallel` field that becomes `-np` in the launch
    command, so the gate cannot drift from how the backend was started. A
    registry that will not load is not fatal here: the gate degrades to
    unlimited, which is exactly the old behaviour. Startup provenance
    enforcement is the registry's job and already runs at the entrypoints.
    """
    try:
        from sentinel.models.registry import load_registry

        return {alias: model.parallel for alias, model in load_registry().models.items()}
    except Exception:
        return {}


def _usage_fields(response: Any, cache_hit: bool) -> tuple[int, int, bool]:
    usage = getattr(response, "usage", None)
    prompt = getattr(usage, "prompt_tokens", 0) or 0
    completion = getattr(usage, "completion_tokens", 0) or 0
    return prompt, completion, cache_hit


def _is_cache_hit(raw_response: Any) -> bool:
    # The LiteLLM proxy sets x-litellm-cache-key on responses served from cache
    return "x-litellm-cache-key" in raw_response.headers


class Gateway:
    def __init__(
        self,
        base_url: str = GATEWAY_BASE_URL,
        api_key: str = GATEWAY_API_KEY,
        metrics: MetricsCollector | None = None,
    ):
        base_url = require_loopback(base_url, what="the LiteLLM gateway")
        # max_retries=0: the per-node timeout is an overall deadline; our own
        # repair loop is the only retry mechanism (Codex M4 review, finding 6)
        self._client = AsyncOpenAI(base_url=base_url, api_key=api_key, max_retries=0)
        self.metrics = metrics or MetricsCollector()
        self._slot_limits = _load_slot_limits()
        self._slots: dict[str, asyncio.Semaphore] = {}

    async def close(self) -> None:
        await self._client.close()

    @asynccontextmanager
    async def _slot(self, model: str):
        """Hold one of the backend's slots for the duration of a call.

        Without this, more concurrent requests than the backend has slots queue
        *inside* llama-server with the connection already open, so the wait is
        billed to the caller's deadline. A refutation with a 300s budget could
        spend all of it behind two deep-review windows and fail having never
        reached a slot — a timeout that reports the model as slow when the model
        never ran. Queue here instead, where the deadline has not started yet.

        This does not reduce throughput: the backend was only ever going to run
        `parallel` requests at once. It moves the waiting to where it can be
        told apart from computing.
        """
        limit = self._slot_limits.get(model)
        if limit is None:
            yield
            return
        sem = self._slots.get(model)
        if sem is None:
            sem = self._slots.setdefault(model, asyncio.Semaphore(limit))
        try:
            async with asyncio.timeout(SLOT_ACQUIRE_TIMEOUT):
                await sem.acquire()
        except TimeoutError as exc:
            self.metrics.increment("slot_starved")
            raise GatewayError(
                f"{model} had no free slot after {SLOT_ACQUIRE_TIMEOUT}s "
                f"(backend serves {limit} concurrent requests). The model did not "
                f"run; this is contention, not latency."
            ) from exc
        try:
            yield
        finally:
            sem.release()

    async def chat_json(
        self,
        model: str,
        messages: list[dict[str, str]],
        schema: type[T],
        timeout: float,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> T:
        """Chat completion constrained to a Pydantic schema via json_schema
        response_format (compiled to a grammar by llama-server). One repair
        retry on validation failure."""
        response_format = {
            "type": "json_schema",
            "json_schema": {
                "name": schema.__name__,
                "schema": schema.model_json_schema(),
                "strict": True,
            },
        }
        attempt_messages = list(messages)
        # Slot first, THEN the clock. `timeout` is the overall deadline for the
        # operation including the repair attempt, but it is a budget for model
        # time, not for waiting behind other files' work.
        async with self._slot(model):
            return await self._chat_json_locked(
                model, attempt_messages, schema, response_format, timeout, max_tokens, temperature
            )

    async def _chat_json_locked(
        self,
        model: str,
        attempt_messages: list[dict[str, str]],
        schema: type[T],
        response_format: dict[str, Any],
        timeout: float,
        max_tokens: int,
        temperature: float,
    ) -> T:
        last_error: Exception | None = None
        try:
            async with asyncio.timeout(timeout):
                for _attempt in range(2):
                    try:
                        raw = await self._client.chat.completions.with_raw_response.create(
                            model=model,
                            messages=attempt_messages,
                            response_format=response_format,
                            timeout=timeout,
                            max_tokens=max_tokens,
                            temperature=temperature,
                        )
                    except APIError as exc:
                        raise GatewayError(f"{model} chat call failed: {exc}") from exc
                    resp = raw.parse()
                    self.metrics.record_model_call(
                        model, *_usage_fields(resp, _is_cache_hit(raw))
                    )
                    text = resp.choices[0].message.content or ""
                    try:
                        return schema.model_validate(extract_json(text))
                    except (ValidationError, ValueError) as exc:
                        last_error = exc
                        attempt_messages = attempt_messages + [
                            {"role": "assistant", "content": text},
                            {
                                "role": "user",
                                "content": (
                                    "Your previous reply was not valid for the required "
                                    f"JSON schema: {exc}. Reply again with ONLY the "
                                    "corrected JSON."
                                ),
                            },
                        ]
        except TimeoutError as exc:
            raise GatewayError(f"{model} chat_json exceeded {timeout}s deadline") from exc
        raise GatewayError(f"{model} returned invalid {schema.__name__} after retry: {last_error}")

    async def chat_text(
        self,
        model: str,
        messages: list[dict[str, str]],
        timeout: float,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> str:
        """Unconstrained chat completion (deep-review Plan B path)."""
        try:
            async with self._slot(model):
                raw = await self._client.chat.completions.with_raw_response.create(
                    model=model,
                    messages=messages,
                    timeout=timeout,
                    max_tokens=max_tokens,
                    temperature=temperature,
                )
        except APIError as exc:
            raise GatewayError(f"{model} chat call failed: {exc}") from exc
        resp = raw.parse()
        self.metrics.record_model_call(model, *_usage_fields(resp, _is_cache_hit(raw)))
        return resp.choices[0].message.content or ""

    async def complete_raw(
        self,
        model: str,
        prompt: str,
        timeout: float,
        max_tokens: int = 512,
        stop: list[str] | None = None,
        logprobs: int | None = None,
    ) -> tuple[str, Any]:
        """Raw text completion for fixed-template classifiers (Llama Guard,
        Granite Guardian). Returns (text, logprobs-or-None)."""
        try:
            async with self._slot(model):
                raw = await self._client.completions.with_raw_response.create(
                    model=model,
                    prompt=prompt,
                    timeout=timeout,
                    max_tokens=max_tokens,
                    stop=stop,
                    logprobs=logprobs,
                    temperature=0.0,
                )
        except APIError as exc:
            raise GatewayError(f"{model} completion call failed: {exc}") from exc
        resp = raw.parse()
        self.metrics.record_model_call(model, *_usage_fields(resp, _is_cache_hit(raw)))
        choice = resp.choices[0]
        return choice.text or "", getattr(choice, "logprobs", None)

    async def judge_groundedness(
        self,
        context: str,
        response: str,
        timeout: float,
        think: bool = True,
    ) -> tuple[bool, float, str]:
        """Granite Guardian 3.3 groundedness check via its official chat
        template (embedded in the GGUF; rendered by llama-server with
        chat_template_kwargs, passed through the gateway).

        The template scores hallucination risk: <score> yes </score> means
        the response is NOT grounded in the context. Returns
        (grounded, groundedness_score = P(score token == 'no'), reasoning).
        """
        try:
            async with self._slot("judge"):
                raw = await self._client.chat.completions.with_raw_response.create(
                    model="judge",
                    messages=[{"role": "assistant", "content": response}],
                    timeout=timeout,
                    max_tokens=2048,
                    temperature=0.0,
                    logprobs=True,
                    top_logprobs=10,
                    extra_body={
                        "chat_template_kwargs": {
                            "guardian_config": {"criteria_id": "groundedness"},
                            "documents": [{"doc_id": "0", "text": context}],
                            "think": think,
                        }
                    },
                )
        except APIError as exc:
            raise GatewayError(f"judge call failed: {exc}") from exc
        resp = raw.parse()
        self.metrics.record_model_call("judge", *_usage_fields(resp, _is_cache_hit(raw)))
        choice = resp.choices[0]
        text = choice.message.content or ""

        # The model's FINAL verdict is the last <score> tag, emitted after the
        # </think> block. Using the last tag prevents an embedded/quoted score
        # inside the rationale (or injected via the untrusted snippet) from
        # overriding the real verdict.
        score_matches = list(re.finditer(r"<score>\s*(yes|no)\s*</score>", text, re.IGNORECASE))
        if not score_matches:
            # Unparseable judge output fails closed: not grounded
            return False, 0.0, f"unparseable judge output: {text[-200:]!r}"
        final = score_matches[-1]
        verdict = final.group(1).lower()

        think_match = re.search(r"<think>(.*?)</think>", text, re.DOTALL)
        reasoning = think_match.group(1).strip() if think_match else ""
        if not reasoning:
            reasoning = f"judge verdict: {verdict}"

        score = _score_from_logprobs(choice)
        if score is None:
            # fallback mapping when logprobs are unavailable
            score = 0.9 if verdict == "no" else 0.1
        grounded = verdict == "no"
        return grounded, score, reasoning

    async def _embed(
        self, texts: list[str], timeout: float, model: str = "nomic-embed"
    ) -> list[list[float]]:
        if not texts:
            return []
        bounded = [_truncate_utf8(t, EMBED_SOFT_INPUT_BYTES) for t in texts]
        truncated = sum(1 for _, was_cut in bounded if was_cut)
        if truncated:
            self.metrics.increment("embed_inputs_truncated", truncated)
        try:
            raw = await self._embed_call(model, [t for t, _ in bounded], timeout)
        except _EmbedInputTooLarge:
            # The soft byte budget is tuned for retrieval quality, not proven
            # against every tokenizer. Fall back to the hard budget, which is
            # under the model's context in bytes and so cannot overflow it in
            # tokens, rather than failing the whole file.
            retry = [_truncate_utf8(t, EMBED_HARD_INPUT_BYTES)[0] for t, _ in bounded]
            self.metrics.increment("embed_overflow_retries")
            try:
                raw = await self._embed_call(model, retry, timeout)
            except _EmbedInputTooLarge as exc:
                raise GatewayError(
                    f"{model} rejected input even at {EMBED_HARD_INPUT_BYTES}-byte "
                    f"cap: {exc.detail}"
                ) from exc
        resp = raw.parse()
        self.metrics.record_model_call(model, *_usage_fields(resp, _is_cache_hit(raw)))
        indices = sorted(d.index for d in resp.data)
        if len(resp.data) != len(texts) or indices != list(range(len(texts))):
            raise GatewayError(
                f"embedding response shape mismatch: {len(texts)} inputs, "
                f"{len(resp.data)} outputs (indices {indices[:5]}...)"
            )
        ordered = sorted(resp.data, key=lambda d: d.index)
        vectors = [item.embedding for item in ordered]
        for vec in vectors:
            if len(vec) != EMBEDDING_DIM:
                raise GatewayError(f"expected {EMBEDDING_DIM}-dim embedding, got {len(vec)}")
        return vectors

    async def _embed_call(self, model: str, texts: list[str], timeout: float) -> Any:
        """One embeddings request, classifying context/batch overflow separately.

        llama.cpp reports an oversized embedding input as 400 "larger than the
        max context size" or 500 "too large to process. increase the physical
        batch size" — both are the same producer-side bug and both are
        retryable at a smaller input budget, unlike a genuine backend failure.
        """
        try:
            return await self._client.embeddings.with_raw_response.create(
                model=model, input=texts, timeout=timeout
            )
        except APIError as exc:
            detail = str(exc)
            if _EMBED_OVERFLOW_RE.search(detail):
                raise _EmbedInputTooLarge(detail) from exc
            raise GatewayError(f"{model} embedding call failed: {exc}") from exc

    async def embed_documents(self, texts: list[str], timeout: float = 60.0) -> list[list[float]]:
        """Embed corpus documents (rules) with the mandatory nomic prefix."""
        return await self._embed([_DOC_PREFIX + t for t in texts], timeout)

    async def embed_query(self, text: str, timeout: float = 60.0) -> list[float]:
        """Embed a retrieval query (code chunk) with the mandatory nomic prefix."""
        return (await self._embed([_QUERY_PREFIX + text], timeout))[0]

    async def embed_queries(self, texts: list[str], timeout: float = 60.0) -> list[list[float]]:
        """Batch-embed retrieval queries (code chunks) with the nomic prefix."""
        return await self._embed([_QUERY_PREFIX + t for t in texts], timeout)


def _score_from_logprobs(choice: Any) -> float | None:
    """Groundedness score = P('no') at the FINAL <score> answer token.

    Reconstructs the generated text from tokens, finds the character offset of
    the last '<score>' tag, and reads the yes/no token at that position —
    ignoring any 'score'/yes/no words that appear earlier in the rationale.
    P(no) is normalized against P(yes) from that token's top_logprobs."""
    logprobs = getattr(choice, "logprobs", None)
    content = getattr(logprobs, "content", None) if logprobs else None
    if not content:
        return None

    # char offset where each token begins, in generation order
    offsets: list[int] = []
    cursor = 0
    for token_info in content:
        offsets.append(cursor)
        cursor += len(token_info.token or "")
    full = "".join(t.token or "" for t in content)

    score_positions = [m.start() for m in re.finditer(r"<score>", full, re.IGNORECASE)]
    if not score_positions:
        return None
    last_tag = score_positions[-1]

    for token_info, start in zip(content, offsets, strict=True):
        if start < last_tag:
            continue
        if (token_info.token or "").strip().lower() in ("yes", "no"):
            p = {"yes": 0.0, "no": 0.0}
            for alt in token_info.top_logprobs or []:
                alt_token = (alt.token or "").strip().lower()
                if alt_token in p:
                    p[alt_token] = max(p[alt_token], math.exp(alt.logprob))
            if p["yes"] == 0.0 and p["no"] == 0.0:
                p[(token_info.token or "").strip().lower()] = math.exp(token_info.logprob)
            total = p["yes"] + p["no"]
            if total <= 0:
                return None
            return p["no"] / total
    return None


def extract_json(text: str) -> Any:
    """Parse model output as JSON, tolerating <think> blocks and prose around
    the final JSON object (deep-review Plan B)."""
    text = text.strip()
    # Try the whole string first — a valid JSON body may legitimately contain
    # the literal "</think>" inside a code_snippet string.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Strip only an anchored leading <think>...</think> reasoning block.
    stripped = re.sub(r"^\s*<think>.*?</think>\s*", "", text, count=1, flags=re.DOTALL)
    if stripped != text:
        try:
            return json.loads(stripped.strip())
        except json.JSONDecodeError:
            text = stripped.strip()
    # Fall back to the LAST valid top-level {...} or [...] block in the text —
    # reasoning models sometimes emit a draft object before the final one.
    # A stack-based scan finds sequential top-level blocks (never blocks
    # nested inside an already-matched candidate).
    def _match_block(start: int) -> int | None:
        """Return the end index (inclusive) of a balanced block at start."""
        stack: list[str] = []
        in_string = False
        escape = False
        pairs = {"{": "}", "[": "]"}
        for i in range(start, len(text)):
            ch = text[i]
            if escape:
                escape = False
                continue
            if ch == "\\":
                escape = in_string
                continue
            if ch == '"':
                in_string = not in_string
                continue
            if in_string:
                continue
            if ch in pairs:
                stack.append(pairs[ch])
            elif ch in ("}", "]"):
                if not stack or ch != stack.pop():
                    return None  # mismatched nesting
                if not stack:
                    return i
        return None

    _sentinel = object()
    last_valid: Any = _sentinel
    pos = 0
    while pos < len(text):
        if text[pos] in "{[":
            end = _match_block(pos)
            if end is not None:
                try:
                    last_valid = json.loads(text[pos : end + 1])
                    pos = end + 1
                    continue
                except json.JSONDecodeError:
                    pass
        pos += 1
    if last_valid is not _sentinel:
        return last_valid
    raise ValueError(f"no valid JSON found in model output ({text[:120]!r}...)")
