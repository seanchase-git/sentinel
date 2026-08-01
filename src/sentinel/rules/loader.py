"""Load and validate the YAML rules corpus from the rules/ tree."""

from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from sentinel.rules.schema import Rule, RuleValidationError


class _StrictLoader(yaml.SafeLoader):
    """SafeLoader that rejects duplicate mapping keys.

    Plain safe_load keeps the last duplicate silently, which would let the
    parsed rule (what goes in the DB) disagree with the verbatim yaml_body
    (what reports show as grounding provenance)."""


def _construct_mapping_no_dupes(loader: _StrictLoader, node, deep=False):
    seen = set()
    for key_node, _ in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in seen:
            raise yaml.YAMLError(f"duplicate key {key!r} at {key_node.start_mark}")
        seen.add(key)
    return yaml.SafeLoader.construct_mapping(loader, node, deep)


_StrictLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping_no_dupes
)


@dataclass
class LoadResult:
    rules: list[Rule] = field(default_factory=list)
    errors: list[RuleValidationError] = field(default_factory=list)
    # rule id → source file, for provenance and duplicate detection
    sources: dict[str, Path] = field(default_factory=dict)
    # raw YAML text per rule id — stored verbatim in the DB and reports
    yaml_bodies: dict[str, str] = field(default_factory=dict)


def iter_rule_files(rules_dir: Path) -> Iterator[Path]:
    yield from sorted(rules_dir.rglob("*.yaml"))
    yield from sorted(rules_dir.rglob("*.yml"))


def load_rules(rules_dir: Path) -> LoadResult:
    """Walk rules_dir recursively, parsing and validating every YAML file.

    Invalid files are collected as errors, never silently skipped; duplicate
    rule ids are errors on the second occurrence.
    """
    result = LoadResult()
    if not rules_dir.is_dir():
        raise FileNotFoundError(f"rules directory not found: {rules_dir}")

    for path in iter_rule_files(rules_dir):
        text = path.read_text(encoding="utf-8")
        try:
            data = yaml.load(text, Loader=_StrictLoader)  # noqa: S506 — SafeLoader subclass
        except yaml.YAMLError as exc:
            result.errors.append(RuleValidationError(str(path), f"invalid YAML: {exc}"))
            continue
        if not isinstance(data, dict):
            result.errors.append(
                RuleValidationError(str(path), "rule file must contain a YAML mapping")
            )
            continue
        try:
            rule = Rule.from_yaml_dict(data, path=str(path))
        except RuleValidationError as exc:
            result.errors.append(exc)
            continue
        if rule.id in result.sources:
            result.errors.append(
                RuleValidationError(
                    str(path),
                    f"duplicate rule id {rule.id!r} (first seen in {result.sources[rule.id]})",
                )
            )
            continue
        result.rules.append(rule)
        result.sources[rule.id] = path
        result.yaml_bodies[rule.id] = text
    return result
