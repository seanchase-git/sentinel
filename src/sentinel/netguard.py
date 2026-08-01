"""Enforce the air-gap claim instead of documenting it.

The README says every model call resolves to loopback and no code leaves the
machine. That was true of the defaults and false as an invariant: both model
clients read a base URL from the environment, so one variable pointed a client
carrying source code at an arbitrary host, and nothing objected.

A property a security tool advertises has to be enforced by the tool. Every
client that transmits source code routes its base URL through require_loopback
at construction, so a non-loopback endpoint fails loudly at startup rather than
silently exfiltrating on the first review.

The escape hatch is deliberately ugly. SENTINEL_ALLOW_REMOTE_MODELS=1 is named
for what it does, has to be set on purpose, and prints what it gives up.
"""

from __future__ import annotations

import ipaddress
import os
import sys
from urllib.parse import urlparse

ALLOW_REMOTE_ENV = "SENTINEL_ALLOW_REMOTE_MODELS"

_LOOPBACK_NAMES = frozenset({"localhost", "localhost.localdomain", "ip6-localhost"})


class AirGapViolation(RuntimeError):
    """A model client was pointed off-box while the air-gap guarantee is active."""


def is_loopback(host: str | None) -> bool:
    if not host:
        return False
    if host.lower() in _LOOPBACK_NAMES:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def remote_models_allowed() -> bool:
    return os.environ.get(ALLOW_REMOTE_ENV, "").strip().lower() in {"1", "true", "yes"}


def require_loopback(base_url: str, *, what: str) -> str:
    """Return base_url, or raise if it would send source code off the machine.

    Read at construction time rather than per request, so a misconfiguration is
    a startup failure instead of a partial review that already leaked.
    """
    host = urlparse(base_url).hostname
    if is_loopback(host):
        return base_url

    if remote_models_allowed():
        # Loud on purpose. Somebody turned off the only property that makes this
        # tool usable on code that cannot leave the building.
        print(
            f"WARNING: {ALLOW_REMOTE_ENV} is set and {what} points at {base_url!r}. "
            f"Source code will be transmitted to a host that is not this machine. "
            f"Sentinel's air-gap guarantee does not apply to this run.",
            file=sys.stderr,
        )
        return base_url

    raise AirGapViolation(
        f"{what} is configured as {base_url!r}, which is not loopback. Sentinel "
        f"sends source code to this endpoint, so it refuses to start. Point it at "
        f"127.0.0.1, or set {ALLOW_REMOTE_ENV}=1 if you genuinely intend to send "
        f"your source off this machine."
    )
