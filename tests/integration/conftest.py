"""Integration-test gating: skip when live services are down, unless
SENTINEL_IT_REQUIRED=1 (the make test-integration path), where missing
services are failures — the gate must not pass vacuously."""

import os

import httpx
import pytest

REQUIRED = os.environ.get("SENTINEL_IT_REQUIRED") == "1"


def _fail_or_skip(reason: str) -> None:
    if REQUIRED:
        pytest.fail(f"SENTINEL_IT_REQUIRED=1 but {reason}")
    pytest.skip(reason)


def require_backend(port: int, name: str) -> None:
    try:
        httpx.get(f"http://127.0.0.1:{port}/health", timeout=2).raise_for_status()
    except httpx.HTTPError:
        _fail_or_skip(f"backend {name} (:{port}) is not healthy")


def require_db() -> None:
    try:
        import psycopg

        with psycopg.connect("postgresql:///sentinel_rules", connect_timeout=2):
            pass
    except Exception as exc:
        _fail_or_skip(f"sentinel_rules database unavailable: {exc}")


def require_gateway() -> None:
    try:
        httpx.get("http://127.0.0.1:8100/health/liveliness", timeout=2).raise_for_status()
    except httpx.HTTPError:
        _fail_or_skip("LiteLLM gateway (:8100) is not healthy")


@pytest.fixture
def embedder_backend() -> None:
    # the Embedder routes through the gateway since M4
    require_gateway()
    require_backend(8095, "nomic-embed")


@pytest.fixture
def gateway() -> None:
    require_gateway()


@pytest.fixture
def full_stack() -> None:
    """All six backends + gateway + database — required for E2E review."""
    require_gateway()
    require_db()
    for port, name in [
        (8090, "deep-review"), (8091, "input-guard"), (8092, "triage"),
        (8093, "judge"), (8094, "classify"), (8095, "nomic-embed"),
    ]:
        require_backend(port, name)


@pytest.fixture
def rules_db() -> None:
    require_db()
