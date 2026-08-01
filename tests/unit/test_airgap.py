"""The air-gap claim, checked instead of asserted.

The README leads with "no code leaves the machine". That is the single claim a
reader has the least ability to verify and the most reason to care about, so it
gets a test rather than a paragraph.

This pins every configured endpoint to loopback. It does NOT prove the process
opens no sockets at runtime; that lives in the integration suite, where the
stack is actually up. What it does prove is that nothing in the committed
configuration points off-box, which is the way this property would realistically
regress: someone adds a hosted fallback model and nobody notices.
"""

from __future__ import annotations

import ipaddress
import re
from pathlib import Path
from urllib.parse import urlparse

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
CONFIG_DIR = REPO_ROOT / "config"

_URL_RE = re.compile(r"https?://[^\s\"'`)]+")

# Documentation links are prose, not endpoints. Rules cite CWE and OWASP pages
# and a review never fetches them.
_DOC_ONLY_SUFFIXES = (".md", ".txt")


def _is_loopback(host: str) -> bool:
    if host in {"localhost", "localhost.localdomain"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _urls_in(text: str) -> list[str]:
    return _URL_RE.findall(text)


@pytest.mark.parametrize(
    "config_name", ["litellm.yaml", "models.yaml", "redis-cache.conf"]
)
def test_every_configured_endpoint_is_loopback(config_name: str):
    path = CONFIG_DIR / config_name
    if not path.exists():
        pytest.skip(f"{config_name} not present")
    offenders = [
        url
        for url in _urls_in(path.read_text())
        if not _is_loopback(urlparse(url).hostname or "")
    ]
    assert offenders == [], (
        f"{config_name} points at a non-loopback endpoint: {offenders}. "
        "Sentinel must not be able to send source code off the machine."
    )


def test_gateway_base_url_is_loopback():
    from sentinel.models.gateway import GATEWAY_BASE_URL

    host = urlparse(GATEWAY_BASE_URL).hostname or ""
    assert _is_loopback(host), (
        f"gateway base URL {GATEWAY_BASE_URL} is not loopback"
    )


def test_litellm_declares_no_hosted_provider():
    """A hosted provider needs no api_base, so a loopback scan alone misses it."""
    config = yaml.safe_load((CONFIG_DIR / "litellm.yaml").read_text())
    for entry in config.get("model_list", []):
        params = entry.get("litellm_params", {})
        api_base = params.get("api_base")
        assert api_base, (
            f"model {entry.get('model_name')!r} declares no api_base, so LiteLLM "
            "would route it to a hosted provider"
        )
        assert _is_loopback(urlparse(api_base).hostname or ""), (
            f"model {entry.get('model_name')!r} routes to {api_base}"
        )


def test_no_provider_credentials_are_configured():
    """An API key for a hosted provider has no legitimate reason to exist here."""
    suspicious = re.compile(
        r"\b(OPENAI|ANTHROPIC|AZURE|COHERE|GOOGLE|GEMINI|MISTRAL|HUGGINGFACE|HF)"
        r"_?(API)?_?KEY\b",
        re.IGNORECASE,
    )
    for path in CONFIG_DIR.rglob("*"):
        if not path.is_file() or path.suffix in _DOC_ONLY_SUFFIXES:
            continue
        hits = suspicious.findall(path.read_text(errors="replace"))
        assert not hits, f"{path.name} references a hosted-provider credential: {hits}"


# --- Enforcement, not just configuration -------------------------------------
#
# The tests above check what is committed. They passed while
# SENTINEL_EMBED_BASE_URL=https://example.invalid pointed the embedder at a
# remote host, because a scan of committed config cannot see an environment
# override. The claim is now enforced at construction, and these are the tests
# that would have caught the gap.


def test_gateway_refuses_a_remote_base_url():
    from sentinel.models.gateway import Gateway
    from sentinel.netguard import AirGapViolation

    with pytest.raises(AirGapViolation, match="not loopback"):
        Gateway(base_url="https://api.example.com/v1")


def test_embedder_refuses_a_remote_base_url():
    from sentinel.netguard import AirGapViolation
    from sentinel.retrieval.embedder import Embedder

    with pytest.raises(AirGapViolation, match="not loopback"):
        Embedder(base_url="https://api.example.com")


def test_embedder_env_override_cannot_send_code_off_box(monkeypatch):
    """The exact hole an audit found: one env var and source code leaves."""
    import importlib

    from sentinel.netguard import AirGapViolation

    monkeypatch.setenv("SENTINEL_EMBED_BASE_URL", "https://example.invalid")
    import sentinel.retrieval.embedder as embedder_mod

    importlib.reload(embedder_mod)
    try:
        with pytest.raises(AirGapViolation):
            embedder_mod.Embedder()
    finally:
        monkeypatch.delenv("SENTINEL_EMBED_BASE_URL", raising=False)
        importlib.reload(embedder_mod)


@pytest.mark.parametrize(
    "url",
    [
        "http://127.0.0.1:8100",
        "http://localhost:8095",
        "http://[::1]:8100",
    ],
)
def test_loopback_forms_are_accepted(url: str):
    from sentinel.netguard import require_loopback

    assert require_loopback(url, what="test") == url


def test_remote_is_allowed_only_behind_an_explicit_opt_out(monkeypatch, capsys):
    """The escape hatch must exist, be deliberate, and announce what it costs."""
    from sentinel.netguard import ALLOW_REMOTE_ENV, require_loopback

    monkeypatch.setenv(ALLOW_REMOTE_ENV, "1")
    url = require_loopback("https://api.example.com", what="the gateway")
    assert url == "https://api.example.com"
    warning = capsys.readouterr().err
    assert "air-gap guarantee does not apply" in warning
