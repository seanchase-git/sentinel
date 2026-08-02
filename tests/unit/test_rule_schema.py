from pathlib import Path

import pytest

from sentinel.rules.categories import RISK_CATEGORIES, derive_risk_categories
from sentinel.rules.loader import load_rules
from sentinel.rules.schema import Rule, RuleValidationError, Severity

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES_DIR = REPO_ROOT / "rules"
BAD_RULES_DIR = Path(__file__).parent / "fixtures" / "rules_bad"


def _valid_rule_dict(**overrides):
    base = {
        "id": "test-rule-example",
        "taxonomy": [{"owasp": "A03:2021"}, {"cwe": "CWE-89"}],
        "title": "Example rule for testing",
        "severity": "high",
        "languages": ["python"],
        "description": "A description long enough to satisfy the schema minimum length.",
        "detection_criteria": "Detection criteria long enough to satisfy the minimum.",
        "example_vulnerable": "do_bad_thing(x)",
        "example_secure": "do_good_thing(x)",
    }
    base.update(overrides)
    return base


class TestRuleSchema:
    def test_valid_rule_parses(self):
        rule = Rule.from_yaml_dict(_valid_rule_dict())
        assert rule.severity is Severity.HIGH
        # CWE-89 is specific → derives {injection}; the broad A03 fallback
        # (injection+xss) must NOT apply when a CWE mapping exists
        assert rule.risk_categories == ["injection"]

    def test_embedding_text_concatenates_prd_fields(self):
        rule = Rule.from_yaml_dict(_valid_rule_dict())
        assert rule.title in rule.embedding_text
        assert rule.description in rule.embedding_text
        assert rule.detection_criteria in rule.embedding_text

    def test_invalid_severity_rejected(self):
        with pytest.raises(RuleValidationError):
            Rule.from_yaml_dict(_valid_rule_dict(severity="apocalyptic"))

    def test_unknown_language_rejected(self):
        with pytest.raises(RuleValidationError):
            Rule.from_yaml_dict(_valid_rule_dict(languages=["cobol"]))

    def test_csharp_language_is_supported(self):
        rule = Rule.from_yaml_dict(_valid_rule_dict(languages=["csharp"]))
        assert rule.languages == ["csharp"]

    def test_unknown_taxonomy_kind_rejected(self):
        with pytest.raises(RuleValidationError):
            Rule.from_yaml_dict(_valid_rule_dict(taxonomy=[{"sans": "top25"}]))

    def test_explicit_risk_categories_merge_with_derived(self):
        rule = Rule.from_yaml_dict(_valid_rule_dict(risk_categories=["auth"]))
        assert set(rule.risk_categories) == {"auth", "injection"}

    def test_cwe_categories_take_priority_over_owasp_fallback(self):
        # CWE-79 → xss only, even though A03 broadly spans injection+xss
        rule = Rule.from_yaml_dict(
            _valid_rule_dict(taxonomy=[{"owasp": "A03:2021"}, {"cwe": "CWE-79"}])
        )
        assert rule.risk_categories == ["xss"]

    def test_owasp_fallback_applies_without_cwe_mapping(self):
        rule = Rule.from_yaml_dict(_valid_rule_dict(taxonomy=[{"owasp": "A10:2021"}]))
        assert rule.risk_categories == ["ssrf"]

    def test_malformed_taxonomy_values_rejected(self):
        with pytest.raises(RuleValidationError):
            Rule.from_yaml_dict(_valid_rule_dict(taxonomy=[{"owasp": "A03:not-a-year"}]))
        with pytest.raises(RuleValidationError):
            Rule.from_yaml_dict(_valid_rule_dict(taxonomy=[{"cwe": "89"}]))

    def test_duplicate_yaml_keys_rejected(self, tmp_path: Path):
        from sentinel.rules.loader import load_rules as _load

        dup_dir = tmp_path / "rules"
        dup_dir.mkdir()
        (dup_dir / "dup.yaml").write_text(
            "id: dup-rule-one\nid: dup-rule-two\ntitle: Duplicate id keys\n"
        )
        result = _load(dup_dir)
        assert result.rules == []
        assert len(result.errors) == 1
        assert "duplicate key" in str(result.errors[0])

    def test_unknown_risk_category_rejected(self):
        with pytest.raises(RuleValidationError):
            Rule.from_yaml_dict(_valid_rule_dict(risk_categories=["quantum"]))

    def test_no_derivable_categories_rejected(self):
        with pytest.raises(RuleValidationError):
            Rule.from_yaml_dict(_valid_rule_dict(taxonomy=[{"owasp": "A99:2021"}]))

    def test_extra_fields_rejected(self):
        with pytest.raises(RuleValidationError):
            Rule.from_yaml_dict(_valid_rule_dict(cve="CVE-2024-0001"))

    def test_severity_rank_ordering(self):
        ranks = [s.rank for s in (Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
        assert ranks == sorted(ranks) and len(set(ranks)) == 4


class TestCategoryDerivation:
    def test_owasp_a03_derives_injection(self):
        assert "injection" in derive_risk_categories([{"owasp": "A03:2021"}])

    def test_cwe_798_derives_secrets(self):
        assert derive_risk_categories([{"cwe": "CWE-798"}]) == {"secrets"}

    def test_unknown_ids_derive_nothing(self):
        assert derive_risk_categories([{"owasp": "A99:2021"}, {"cwe": "CWE-99999"}]) == set()

    def test_all_derived_categories_are_known(self):
        from sentinel.rules.categories import _CWE_MAP, _OWASP_MAP

        for mapping in (_OWASP_MAP, _CWE_MAP):
            for cats in mapping.values():
                assert cats <= RISK_CATEGORIES


class TestCorpusLoader:
    def test_shipped_corpus_is_valid(self):
        result = load_rules(RULES_DIR)
        assert result.errors == []
        assert len(result.rules) >= 10

    def test_shipped_corpus_ids_unique_and_yaml_preserved(self):
        result = load_rules(RULES_DIR)
        assert len(result.rules) == len(result.sources)
        for rule in result.rules:
            assert rule.id in result.yaml_bodies
            assert rule.title in result.yaml_bodies[rule.id]

    def test_broken_fixture_rule_rejected(self):
        result = load_rules(BAD_RULES_DIR)
        assert result.rules == []
        assert len(result.errors) == 1
        assert "missing-fields.yaml" in str(result.errors[0])

    def test_missing_dir_raises(self):
        with pytest.raises(FileNotFoundError):
            load_rules(Path("/nonexistent/rules"))
