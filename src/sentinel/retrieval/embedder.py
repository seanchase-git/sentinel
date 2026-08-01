"""nomic-embed-text-v1.5 client with mandatory task prefixes.

Nomic embeddings are trained with task prefixes: documents (rules) must be
embedded with ``search_document: `` and queries (code chunks) with
``search_query: ``. Mixing them up silently degrades retrieval quality.

Routed through the LiteLLM gateway (:8100) since M4; SENTINEL_EMBED_BASE_URL
can point back at the raw :8095 backend for gateway-less debugging.
"""

import os

import httpx

from sentinel.netguard import require_loopback

EMBEDDING_DIM = 768
DEFAULT_BASE_URL = os.environ.get("SENTINEL_EMBED_BASE_URL", "http://127.0.0.1:8100")
DEFAULT_MODEL = os.environ.get("SENTINEL_EMBED_MODEL", "nomic-embed")
DEFAULT_API_KEY = os.environ.get("SENTINEL_GATEWAY_API_KEY", "sk-sentinel-local-dev")

_DOC_PREFIX = "search_document: "
_QUERY_PREFIX = "search_query: "


class EmbeddingError(RuntimeError):
    pass


class Embedder:
    def __init__(
        self,
        base_url: str = DEFAULT_BASE_URL,
        model: str = DEFAULT_MODEL,
        api_key: str | None = DEFAULT_API_KEY,
        timeout: float = 60.0,
    ):
        # This client transmits source code, so it is bound by the air-gap
        # guarantee exactly as the gateway is. SENTINEL_EMBED_BASE_URL used to be
        # an unchecked escape hatch straight off the machine.
        base_url = require_loopback(base_url, what="the embedding endpoint")
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self._client = httpx.Client(base_url=base_url, timeout=timeout, headers=headers)
        self._model = model

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> "Embedder":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def _embed(self, texts: list[str]) -> list[list[float]]:
        if not texts:
            return []
        try:
            resp = self._client.post(
                "/v1/embeddings", json={"model": self._model, "input": texts}
            )
            resp.raise_for_status()
        except httpx.HTTPError as exc:
            raise EmbeddingError(f"embedding request failed: {exc}") from exc
        payload = resp.json()
        data = sorted(payload["data"], key=lambda d: d["index"])
        vectors = [item["embedding"] for item in data]
        if len(vectors) != len(texts):
            raise EmbeddingError(f"expected {len(texts)} embeddings, got {len(vectors)}")
        for vec in vectors:
            if len(vec) != EMBEDDING_DIM:
                raise EmbeddingError(f"expected {EMBEDDING_DIM}-dim embedding, got {len(vec)}")
        return vectors

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        """Embed rule texts (stored in the corpus)."""
        return self._embed([_DOC_PREFIX + t for t in texts])

    def embed_query(self, text: str) -> list[float]:
        """Embed a code chunk used to search the corpus."""
        return self._embed([_QUERY_PREFIX + text])[0]
