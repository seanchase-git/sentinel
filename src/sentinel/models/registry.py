"""Backend model registry with Section 1532 provenance enforcement.

Loads config/models.yaml, validates every model against the allowed-origins
list, and provides llama-server launch plans for scripts/start-backends.sh.
"""

import sys
from pathlib import Path

import yaml
from pydantic import BaseModel, ConfigDict, Field

REPO_ROOT = Path(__file__).resolve().parents[3]
DEFAULT_MODELS_CONFIG = REPO_ROOT / "config" / "models.yaml"


class ProvenanceError(RuntimeError):
    """A configured model violates the origin allowlist (NDAA Section 1532)."""


class BackendModel(BaseModel):
    model_config = ConfigDict(extra="forbid")

    alias: str
    role: str
    developer: str
    origin: str
    hf_repo: str
    gguf: Path
    port: int = Field(ge=1024, le=65535)
    mode: str = Field(pattern="^(chat|embedding)$")
    ctx: int = Field(ge=512)
    parallel: int = Field(ge=1, le=16)
    extra_flags: list[str] = Field(default_factory=list)

    @property
    def gguf_path(self) -> Path:
        return self.gguf.expanduser()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}/v1"

    def launch_command(self) -> list[str]:
        cmd = [
            "llama-server",
            "--host", "127.0.0.1",
            "--port", str(self.port),
            "-m", str(self.gguf_path),
            "-c", str(self.ctx),
            "-np", str(self.parallel),
            "--jinja",
            "-fa", "on",
        ]
        if self.mode == "embedding":
            cmd.append("--embedding")
        cmd.extend(self.extra_flags)
        return cmd


class Registry(BaseModel):
    allowed_origins: list[str]
    models: dict[str, BackendModel]

    def get(self, alias: str) -> BackendModel:
        return self.models[alias]


def load_registry(config_path: Path = DEFAULT_MODELS_CONFIG) -> Registry:
    """Load and validate the registry; raise ProvenanceError on any
    disallowed-origin model. This runs at every entrypoint that touches
    model backends — a non-allowlisted model must never start."""
    raw = yaml.safe_load(config_path.read_text(encoding="utf-8"))
    allowed = raw.get("allowed_origins", [])
    models = {
        alias: BackendModel(alias=alias, **spec) for alias, spec in raw.get("models", {}).items()
    }
    for model in models.values():
        if model.origin not in allowed:
            raise ProvenanceError(
                f"model {model.alias!r} ({model.hf_repo}, developer {model.developer}) has "
                f"origin {model.origin!r}, which is not in allowed_origins {allowed}. "
                "FY2026 NDAA Section 1532 prohibits covered-nation AI models in this "
                "environment; remove the model or correct its provenance metadata."
            )
    return Registry(allowed_origins=allowed, models=models)


def main() -> None:
    """CLI helper for shell scripts.

    launch-plan: print one line per model: alias<TAB>port<TAB>command...
    """
    if len(sys.argv) < 2 or sys.argv[1] != "launch-plan":
        print("usage: python -m sentinel.models.registry launch-plan [alias ...]", file=sys.stderr)
        raise SystemExit(2)
    registry = load_registry()
    aliases = sys.argv[2:] or list(registry.models)
    for alias in aliases:
        if alias not in registry.models:
            print(f"unknown model alias: {alias}", file=sys.stderr)
            raise SystemExit(2)
        model = registry.get(alias)
        if not model.gguf_path.is_file():
            print(f"missing GGUF for {alias}: {model.gguf_path}", file=sys.stderr)
            raise SystemExit(1)
        print("\t".join([alias, str(model.port), " ".join(model.launch_command())]))


if __name__ == "__main__":
    main()
