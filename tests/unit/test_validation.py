import pytest

from sentinel.graph.nodes import KNOWN_FRAMEWORKS, normalize_framework
from sentinel.graph.schemas import CandidateFinding
from sentinel.graph.validation import validate_findings
from sentinel.retrieval.rules_store import RetrievedRule

SOURCE = '''import sqlite3

def get_user(user_id):
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return cursor.fetchone()

def greet(name):
    return f"hello {name}"
'''

RULE = RetrievedRule(
    rule_id="owasp-a03-sql-injection-python-string-format",
    title="SQL Injection via Python String Formatting",
    severity="high",
    description="desc",
    detection_criteria="criteria",
    yaml_body="id: owasp-a03-sql-injection-python-string-format\nreferences:\n  - CWE-89 https://cwe.mitre.org/data/definitions/89.html",
    languages=["python"],
    frameworks=[],
    risk_categories=["injection"],
    score=0.9,
)


def _candidate(**overrides) -> CandidateFinding:
    base = dict(
        rule_id=RULE.rule_id,
        line_start=4,
        line_end=4,
        code_snippet='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        severity="high",
        explanation="user_id is interpolated into the SQL string via f-string.",
    )
    base.update(overrides)
    return CandidateFinding(**base)


def test_valid_finding_accepted_with_recomputed_lines():
    out = validate_findings([_candidate(line_start=1, line_end=1)], SOURCE, "app.py", [RULE])
    assert not out.rejected
    f = out.accepted[0]
    # model claimed line 1; validator recomputes from the located snippet
    assert f["line_start"] == 4 and f["line_end"] == 4
    assert f["grounded_in_rule_chunk"] == RULE.yaml_body
    assert f["severity"] == "high" and f["claimed_severity"] == "high"


def test_uncited_rule_rejected():
    out = validate_findings(
        [_candidate(rule_id="totally-different-nonexistent-thing")], SOURCE, "app.py", [RULE]
    )
    assert not out.accepted
    assert out.rejected[0]["reason"].startswith("uncited_rule")


def test_near_miss_rule_id_snapped_unambiguously():
    # model transcribes the id imperfectly; exactly one close retrieved match
    typo = "owasp-a14-sql-injection-python-string-format"  # a03 -> a14
    out = validate_findings([_candidate(rule_id=typo)], SOURCE, "app.py", [RULE])
    assert out.accepted, "unambiguous near-miss should snap to the retrieved rule"
    f = out.accepted[0]
    assert f["rule_id"] == RULE.rule_id
    assert any("rule_id_corrected" in n for n in f.get("validator_notes", []))


def test_ambiguous_near_miss_rejected():
    rule_b = RetrievedRule(
        **{**RULE.__dict__, "rule_id": "owasp-a03-sql-injection-python-string-concat"}
    )
    # citation is close to BOTH ids → ambiguous → not snapped
    typo = "owasp-a03-sql-injection-python-string-formatx"
    out = validate_findings([_candidate(rule_id=typo)], SOURCE, "app.py", [RULE, rule_b])
    # either it snaps to the single closest, or rejects as ambiguous; assert it
    # never silently attaches to the wrong rule without a correction note
    if out.accepted:
        assert any("rule_id_corrected" in n for n in out.accepted[0].get("validator_notes", []))


def test_missing_snippet_rejected():
    out = validate_findings(
        [_candidate(code_snippet="os.system(user_input)")], SOURCE, "app.py", [RULE]
    )
    assert not out.accepted
    assert out.rejected[0]["reason"].startswith("snippet_not_found")


def test_whitespace_normalized_snippet_replaced_with_exact_source():
    paraphrased = '  cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  '
    out = validate_findings([_candidate(code_snippet=paraphrased)], SOURCE, "app.py", [RULE])
    assert out.accepted
    f = out.accepted[0]
    # emitted snippet must be the verbatim source line, not the model's version
    assert f["code_snippet"] == '    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")'
    assert f["line_start"] == 4


def test_invented_cve_rejected():
    out = validate_findings(
        [_candidate(explanation="This matches CVE-2023-99999, a known SQLi flaw.")],
        SOURCE,
        "app.py",
        [RULE],
    )
    assert not out.accepted
    assert out.rejected[0]["reason"].startswith("invented_cve")


def test_cve_present_in_rule_allowed():
    rule = RetrievedRule(**{**RULE.__dict__, "yaml_body": RULE.yaml_body + "\nCVE-2023-99999"})
    out = validate_findings(
        [_candidate(explanation="Matches CVE-2023-99999 per the rule.")],
        SOURCE,
        "app.py",
        [rule],
    )
    assert out.accepted and not out.rejected


def test_severity_mismatch_recorded_not_clamped_silently():
    out = validate_findings([_candidate(severity="critical")], SOURCE, "app.py", [RULE])
    f = out.accepted[0]
    assert f["severity"] == "high"            # rule's declared severity is emitted
    assert f["claimed_severity"] == "critical"  # model's claim preserved for judge/audit
    assert any("severity_mismatch" in n for n in f.get("validator_notes", []))


def test_duplicate_rule_location_deduped():
    out = validate_findings([_candidate(), _candidate()], SOURCE, "app.py", [RULE])
    assert len(out.accepted) == 1
    assert out.rejected[0]["reason"].startswith("duplicate_finding")


REPEATED_SOURCE = '''def a(user_id):
    cursor.execute(f"SELECT * FROM t WHERE id = {user_id}")

def b(user_id):
    cursor.execute(f"SELECT * FROM t WHERE id = {user_id}")
'''


def test_snippet_located_within_window_nearest_claimed_line():
    snippet = 'cursor.execute(f"SELECT * FROM t WHERE id = {user_id}")'
    # two identical sinks (lines 2 and 5); a candidate claiming line 5 must map
    # to the second occurrence, constrained to its window (lines 4-5)
    cand = CandidateFinding(
        rule_id=RULE.rule_id, line_start=5, line_end=5,
        code_snippet=snippet, severity="high", explanation="sqli",
    )
    out = validate_findings(
        [cand], REPEATED_SOURCE, "app.py", [],
        candidate_windows=[0], window_rules=[[RULE]], window_bounds=[(4, 5)],
    )
    assert out.accepted, out.rejected
    assert out.accepted[0]["line_start"] == 5


def test_window_scoped_rule_citation():
    # candidate cites a rule retrieved only for window 1, but came from window 0
    rule_b = RetrievedRule(**{**RULE.__dict__, "rule_id": "cwe-79-xss-javascript-innerhtml"})
    cand = _candidate(rule_id=rule_b.rule_id)
    out = validate_findings(
        [cand], SOURCE, "app.py", [],
        candidate_windows=[0], window_rules=[[RULE], [rule_b]],
        window_bounds=[(1, 8), (9, 12)],
    )
    assert not out.accepted
    assert out.rejected[0]["reason"].startswith("uncited_rule")


def test_normalized_match_tolerates_blank_lines():
    src = "def f():\n    a()\n\n    b()\n"
    cand = CandidateFinding(
        rule_id=RULE.rule_id, line_start=2, line_end=3,
        code_snippet="a()\nb()", severity="high", explanation="x",
    )
    out = validate_findings([cand], src, "app.py", [RULE])
    assert out.accepted, out.rejected
    # emitted snippet is the exact source span including the blank line
    assert out.accepted[0]["code_snippet"] == "    a()\n\n    b()"


class TestFrameworkNormalization:
    """rules_store reranks by exact string membership against a rule's
    `frameworks` list, so a framework value outside the corpus vocabulary can
    only mis-target or no-op. Observed from the 1B classifier on real runs:
    'typescript' (a language), 'vite' (a build tool), 'next' (right idea, wrong
    string, so the +0.05 boost never fired)."""

    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("next", "nextjs"),
            ("Next.js", "nextjs"),
            ("NEXTJS", "nextjs"),
            ("reactjs", "react"),
            ("Express.js", "express"),
            ("fast-api", "fastapi"),
            ("  flask  ", "flask"),
            ("ASP.NET Core", "aspnetcore"),
            ("Blazor", "aspnetcore"),
        ],
    )
    def test_aliases_map_onto_corpus_vocabulary(self, raw, expected):
        assert normalize_framework(raw) == expected

    @pytest.mark.parametrize(
        "raw", ["typescript", "javascript", "vite", "webpack", "svelte", "rails", "", None]
    )
    def test_non_corpus_values_become_none(self, raw):
        # languages, build tools, and frameworks with no rules in the corpus all
        # drop: claiming one in the report would be misleading and the rerank
        # has nothing to match it against.
        assert normalize_framework(raw) is None

    def test_every_known_framework_normalizes_to_itself(self):
        for name in KNOWN_FRAMEWORKS:
            assert normalize_framework(name) == name

    def test_known_frameworks_matches_detector_vocabulary(self):
        # the detector and the fallback must agree, or deterministic detection
        # could produce a value the fallback would have rejected
        assert KNOWN_FRAMEWORKS == {
            "flask", "django", "fastapi", "express", "fastify", "angular", "nextjs",
            "react", "aspnetcore",
        }

    def test_every_known_framework_is_declared_by_at_least_one_rule(self):
        # a framework the detector can produce but no rule declares is dead
        # weight: the +0.05 rerank in rules_store can never fire for it.
        from pathlib import Path

        from sentinel.rules.loader import load_rules

        result = load_rules(Path(__file__).resolve().parents[2] / "rules")
        declared = {fw for r in result.rules for fw in r.frameworks}
        assert KNOWN_FRAMEWORKS <= declared, KNOWN_FRAMEWORKS - declared


class TestElidedSnippetRecovery:
    """deep_review quotes source with '...' standing in for omitted lines even
    when told not to. That used to fail the finding outright, discarding valid
    findings over formatting. The gap is forgiven; every quoted line must still
    be real source, in order."""

    SRC = "\n".join([
        "const express = require('express');",      # 1
        "function registerAdmin(app) {",            # 2
        "  app.get('/admin/users', (req, res) => {",  # 3
        "    const rows = db.all('users');",        # 4
        "    log('served');",                       # 5
        "    res.json(rows);",                      # 6
        "  });",                                    # 7
        "}",                                        # 8
    ])

    def _candidate(self, snippet, line_start=3):
        return CandidateFinding(
            rule_id=RULE.rule_id,
            file_path="admin.js",
            line_start=line_start,
            line_end=line_start,
            code_snippet=snippet,
            severity=RULE.severity,
            explanation="admin route without an auth check",
        )

    def test_elided_snippet_is_recovered_with_real_source(self):
        snippet = "  app.get('/admin/users', (req, res) => {\n    ...\n    res.json(rows);"
        out = validate_findings([self._candidate(snippet)], self.SRC, "admin.js", [RULE])
        assert len(out.accepted) == 1, out.rejected
        f = out.accepted[0]
        assert f["line_start"] == 3 and f["line_end"] == 6
        # emitted snippet is the verbatim bracketed span, elision gone
        assert "..." not in f["code_snippet"]
        assert f["code_snippet"] == "\n".join(self.SRC.split("\n")[2:6])
        assert any("elided_snippet" in n for n in f.get("validator_notes", []))

    @pytest.mark.parametrize(
        "marker", ["...", "…", "// ...", "# ...", "/* ... */", "    ..."]
    )
    def test_common_elision_markers_all_recognised(self, marker):
        snippet = f"  app.get('/admin/users', (req, res) => {{\n{marker}\n    res.json(rows);"
        out = validate_findings([self._candidate(snippet)], self.SRC, "admin.js", [RULE])
        assert len(out.accepted) == 1, f"{marker!r} not handled: {out.rejected}"

    def test_fabricated_line_across_an_elision_is_still_rejected(self):
        # the gap is forgiven, invented content is not
        snippet = "  app.get('/admin/users', (req, res) => {\n    ...\n    res.send(SECRET_KEY);"
        out = validate_findings([self._candidate(snippet)], self.SRC, "admin.js", [RULE])
        assert out.accepted == []
        assert "snippet_not_found" in out.rejected[0]["reason"]

    def test_fragments_must_appear_in_order(self):
        # res.json comes AFTER app.get in the source; reversed must not match
        snippet = "    res.json(rows);\n    ...\n  app.get('/admin/users', (req, res) => {"
        out = validate_findings([self._candidate(snippet)], self.SRC, "admin.js", [RULE])
        assert out.accepted == []

    def test_elision_without_a_second_fragment_is_not_a_match(self):
        snippet = "  app.get('/admin/users', (req, res) => {\n    ..."
        out = validate_findings([self._candidate(snippet)], self.SRC, "admin.js", [RULE])
        # single fragment: the normal locators govern, and they find line 3 only
        if out.accepted:
            assert out.accepted[0]["line_end"] == 3


class TestFrameworkDetection:
    """Deterministic detection beats asking a 1B model. Fastify and Angular were
    added once the corpus had rules for them: detecting a framework nothing
    declares only produces a value the rerank cannot use."""

    def test_fastify_detected(self):
        from sentinel.graph.nodes import detect_framework

        assert detect_framework("const fastify = require('fastify')({})") == "fastify"
        assert detect_framework("import Fastify from 'fastify';") == "fastify"

    def test_angular_detected(self):
        from sentinel.graph.nodes import detect_framework

        src = "import { Component } from '@angular/core';\n@Component({})\nexport class A {}"
        assert detect_framework(src) == "angular"

    def test_fastify_not_confused_with_fastapi(self):
        from sentinel.graph.nodes import detect_framework

        assert detect_framework("from fastapi import FastAPI") == "fastapi"

    def test_unknown_framework_returns_none(self):
        from sentinel.graph.nodes import detect_framework

        assert detect_framework("const x = require('lodash');") is None

    @pytest.mark.parametrize(
        "source",
        [
            "using Microsoft.AspNetCore.Mvc;\npublic class Users : ControllerBase {}",
            'var app = WebApplication.CreateBuilder(args).Build();\napp.MapGet("/", () => 1);',
            '@page "/users"\n@inject NavigationManager Navigation',
            "public sealed class Widget : ComponentBase { private IJSRuntime JS = null!; }",
        ],
    )
    def test_aspnetcore_detected_across_hosting_models(self, source):
        from sentinel.graph.nodes import detect_framework

        assert detect_framework(source) == "aspnetcore"

    def test_plain_csharp_library_is_not_aspnetcore(self):
        from sentinel.graph.nodes import detect_framework

        assert detect_framework("namespace Acme; public sealed class Calculator {}") is None


class TestInlineElidedBody:
    """The elision shape that actually occurs in practice is a collapsed brace
    body on one line, not a standalone '...' line:
        app.post('/items', async (req) => { ... });
    This shape accounts for a large share of snippet_not_found rejections, and
    correct findings were being thrown away over formatting rather than
    substance."""

    SRC = "\n".join(
        ["function register(app) {"]                      # 1
        + ["  app.post('/items', async (req) => {"]   # 2
        + [f"    step{i}();" for i in range(3)]            # 3-5
        + ["  });"]                                        # 6
        + ["}"]                                            # 7
    )
    LONG = "\n".join(
        ["  app.put('/items/:id', async (req) => {"]  # 1
        + [f"    line{i}();" for i in range(80)]           # 2-81
        + ["  });"]                                        # 82
    )

    def _cand(self, snippet, line=2):
        return CandidateFinding(
            rule_id=RULE.rule_id, line_start=line, line_end=line,
            code_snippet=snippet, severity=RULE.severity, explanation="no auth",
        )

    def test_inline_collapsed_body_recovered(self):
        snip = "app.post('/items', async (req) => { ... });"
        out = validate_findings([self._cand(snip)], self.SRC, "admin.js", [RULE])
        assert len(out.accepted) == 1, out.rejected
        f = out.accepted[0]
        assert (f["line_start"], f["line_end"]) == (2, 6)
        assert "..." not in f["code_snippet"]

    def test_oversized_body_falls_back_to_the_signature_line(self):
        # 82-line handler exceeds the max span; citing 82 lines is not a
        # citation, but dropping a real finding is worse. Cite the declaration.
        snip = "app.put('/items/:id', async (req) => { ... });"
        out = validate_findings([self._cand(snip, line=1)], self.LONG, "admin.js", [RULE])
        assert len(out.accepted) == 1, out.rejected
        f = out.accepted[0]
        assert (f["line_start"], f["line_end"]) == (1, 1)
        assert f["code_snippet"].strip().startswith("app.put(")

    def test_inline_elision_with_fabricated_signature_still_rejected(self):
        snip = "app.patch('/admin/nonexistent', async (req) => { ... });"
        out = validate_findings([self._cand(snip)], self.SRC, "admin.js", [RULE])
        assert out.accepted == []
        assert "snippet_not_found" in out.rejected[0]["reason"]


class TestFrameworkMismatchRejection:
    """Retrieval offers rules by language and risk category, so a Django rule
    reaches a file importing sqlite3 and a Next.js rule reaches every Fastify
    server. The model cites them and the judge finds them textually grounded.
    Observed live: cwe-89-sql-injection-django-raw cited in a file with no
    Django, and cwe-306-missing-authentication-nextjs-api cited on Fastify."""

    def _rule(self, frameworks):
        return RetrievedRule(**{**RULE.__dict__, "frameworks": frameworks})

    def test_wrong_framework_rejected(self):
        rule = self._rule(["django"])
        out = validate_findings(
            [_candidate()], SOURCE, "app.py", [rule], detected_framework="fastapi"
        )
        assert out.accepted == []
        assert out.rejected[0]["reason"].startswith("framework_mismatch")

    def test_matching_framework_accepted(self):
        rule = self._rule(["django"])
        out = validate_findings(
            [_candidate()], SOURCE, "app.py", [rule], detected_framework="django"
        )
        assert out.accepted, out.rejected

    def test_one_of_several_declared_frameworks_matches(self):
        rule = self._rule(["express", "fastify"])
        out = validate_findings(
            [_candidate()], SOURCE, "app.py", [rule], detected_framework="fastify"
        )
        assert out.accepted, out.rejected

    def test_unknown_framework_stays_permissive(self):
        # detection deliberately reports nothing rather than guess; rejecting
        # here would cost recall on every file the detector cannot resolve
        rule = self._rule(["django"])
        out = validate_findings(
            [_candidate()], SOURCE, "app.py", [rule], detected_framework=None
        )
        assert out.accepted, out.rejected

    def test_language_level_rule_never_rejected(self):
        # rules with frameworks: [] apply everywhere
        out = validate_findings(
            [_candidate()], SOURCE, "app.py", [self._rule([])], detected_framework="django"
        )
        assert out.accepted, out.rejected


class TestApplicabilityEvidenceGate:
    @staticmethod
    def _window(source):
        from sentinel.ingest.chunker import CodeChunk, ReviewWindow

        return ReviewWindow(
            chunks=[CodeChunk(text=source, start_line=1, end_line=len(source.split("\n")))]
        )

    @staticmethod
    def _evidence_candidate(source_text="user_id", source_line=3, sink_line=4, **overrides):
        from sentinel.graph.schemas import EvidenceLocation

        values = {
            "untrusted_source": EvidenceLocation(line=source_line, text=source_text),
            "sink": EvidenceLocation(
                line=sink_line,
                text='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            ),
        }
        values.update(overrides)
        return _candidate(**values)

    def test_missing_sink_has_distinct_first_class_audit_reason(self):
        from sentinel.graph.evidence import (
            mark_applicability_rejection,
            validate_applicability,
        )

        candidate = _candidate()
        decision = validate_applicability(candidate, SOURCE, self._window(SOURCE), RULE)
        assert decision.reason == "applicability_missing_sink"
        marked = mark_applicability_rejection(candidate, decision.reason)

        outcome = validate_findings([marked], SOURCE, "app.py", [RULE])
        assert outcome.accepted == []
        assert outcome.rejected[0]["reason"] == "applicability_missing_sink"
        assert outcome.rejected[0]["candidate"]["rule_id"] == RULE.rule_id

    def test_flow_rule_with_sink_but_no_source_has_distinct_reason(self):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        candidate = _candidate(sink=EvidenceLocation(line=4, text="cursor.execute"))
        decision = validate_applicability(candidate, SOURCE, self._window(SOURCE), RULE)
        assert decision.reason == "applicability_missing_untrusted_source"

    def test_claimed_source_text_must_exist_at_claimed_line(self):
        from sentinel.graph.evidence import validate_applicability

        candidate = self._evidence_candidate(source_text="request.args['id']")
        decision = validate_applicability(candidate, SOURCE, self._window(SOURCE), RULE)
        assert decision.reason == "applicability_source_text_mismatch"

    def test_tls_requires_explicit_disablement(self):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        rule = RetrievedRule(
            **{
                **RULE.__dict__,
                "rule_id": "cwe-295-tls-verify-disabled-python",
                "yaml_body": "id: tls\n- cwe: CWE-295",
                "risk_categories": ["crypto"],
            }
        )
        safe = 'response = requests.get("https://example.test")'
        candidate = _candidate(
            rule_id=rule.rule_id,
            code_snippet=safe,
            line_start=1,
            line_end=1,
            untrusted_source=EvidenceLocation(line=1, text="requests.get"),
            sink=EvidenceLocation(line=1, text="requests.get"),
        )
        decision = validate_applicability(candidate, safe, self._window(safe), rule)
        assert decision.reason == "applicability_tls_not_explicitly_disabled"

        unsafe = 'response = requests.get("https://example.test", verify=False)'
        candidate = candidate.model_copy(
            update={
                "code_snippet": unsafe,
                "untrusted_source": None,
                "sink": EvidenceLocation(line=1, text="requests.get"),
            }
        )
        assert validate_applicability(candidate, unsafe, self._window(unsafe), rule).accepted

    def test_hardcoded_secret_rejects_environment_read_and_accepts_literal(self):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        rule = RetrievedRule(
            **{
                **RULE.__dict__,
                "rule_id": "cwe-798-hardcoded-secrets-python",
                "yaml_body": "id: secret\n- cwe: CWE-798",
                "risk_categories": ["secrets"],
            }
        )
        env = 'api_key = os.getenv("API_KEY")'
        candidate = _candidate(
            rule_id=rule.rule_id,
            code_snippet=env,
            line_start=1,
            line_end=1,
            untrusted_source=EvidenceLocation(line=1, text="os.getenv"),
            sink=EvidenceLocation(line=1, text="api_key"),
        )
        decision = validate_applicability(candidate, env, self._window(env), rule)
        assert decision.reason == "applicability_hardcoded_secret_is_environment_read"

        literal = 'api_key = "s3cr3t-value"'
        candidate = candidate.model_copy(
            update={
                "code_snippet": literal,
                "untrusted_source": None,
            }
        )
        assert validate_applicability(candidate, literal, self._window(literal), rule).accepted

    def test_nearby_evidence_resolution_is_used_by_rule_predicate(self):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        source = '# TLS client\nresponse = requests.get("https://example.test", verify=False)'
        rule = RetrievedRule(
            **{
                **RULE.__dict__,
                "rule_id": "cwe-295-tls-verify-disabled-python",
                "yaml_body": "id: tls\n- cwe: CWE-295",
                "risk_categories": ["crypto"],
            }
        )
        candidate = _candidate(
            rule_id=rule.rule_id,
            code_snippet=source.split("\n")[1],
            line_start=1,
            line_end=1,
            untrusted_source=None,
            sink=EvidenceLocation(line=1, text="requests.get"),
        )
        decision = validate_applicability(candidate, source, self._window(source), rule)
        assert decision.accepted, decision.reason

    def test_injection_requires_flow_into_query_text_not_parameters(self):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        parameterized = "\n".join(
            [
                "user_id = request.args['id']",
                'cursor.execute("SELECT * FROM users WHERE id = ?", [user_id])',
            ]
        )
        candidate = _candidate(
            line_start=2,
            line_end=2,
            code_snippet=parameterized.split("\n")[1],
            untrusted_source=EvidenceLocation(line=1, text="request.args['id']"),
            sink=EvidenceLocation(line=2, text="cursor.execute"),
        )
        decision = validate_applicability(
            candidate, parameterized, self._window(parameterized), RULE
        )
        assert decision.reason == "applicability_injection_no_query_text_flow"

        interpolated = "\n".join(
            [
                "user_id = request.args['id']",
                'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            ]
        )
        candidate = candidate.model_copy(update={"code_snippet": interpolated.split("\n")[1]})
        assert validate_applicability(
            candidate, interpolated, self._window(interpolated), RULE
        ).accepted

    def test_auth_finding_requires_missing_enforcement_reason(self):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        source = "app.get('/admin', handler)"
        rule = RetrievedRule(
            **{
                **RULE.__dict__,
                "rule_id": "cwe-306-missing-authentication-express",
                "yaml_body": "id: auth\n- cwe: CWE-306",
                "risk_categories": ["auth"],
            }
        )
        candidate = _candidate(
            rule_id=rule.rule_id,
            code_snippet=source,
            line_start=1,
            line_end=1,
            untrusted_source=EvidenceLocation(line=1, text="'/admin'"),
            sink=EvidenceLocation(line=1, text="app.get"),
        )
        decision = validate_applicability(candidate, source, self._window(source), rule)
        assert decision.reason == "applicability_auth_enforcement_reason_missing"
        candidate = candidate.model_copy(
            update={"auth_missing_enforcement_reason": "No middleware is attached to the route."}
        )
        assert validate_applicability(candidate, source, self._window(source), rule).accepted

    @pytest.mark.parametrize("cwe", ["CWE-306", "CWE-862", "CWE-639"])
    def test_access_control_accepts_sink_and_reason_without_source(self, cwe):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        source = "app.get('/internal/accounts', handler)"
        rule = RetrievedRule(
            **{
                **RULE.__dict__,
                "rule_id": f"{cwe.lower()}-access-control-test",
                "yaml_body": f"id: auth\n- cwe: {cwe}",
                "risk_categories": ["auth"],
            }
        )
        candidate = _candidate(
            rule_id=rule.rule_id,
            code_snippet=source,
            line_start=1,
            line_end=1,
            untrusted_source=None,
            sink=EvidenceLocation(line=1, text="app.get"),
            auth_missing_enforcement_reason=(
                "No middleware, route preHandler, or inline enforcement covers this route."
            ),
        )
        decision = validate_applicability(candidate, source, self._window(source), rule)
        assert decision.accepted, decision.reason

    @pytest.mark.parametrize(
        "cwe,rule_id,source,sink_text",
        [
            (
                "CWE-942",
                "cwe-942-cors-wildcard-credentials-express",
                "app.use(cors({ origin: true, credentials: true }))",
                "cors",
            ),
            (
                "CWE-338",
                "cwe-338-insecure-random-javascript",
                "const resetToken = Math.random().toString(36)",
                "Math.random",
            ),
        ],
    )
    def test_property_rules_accept_sink_without_untrusted_source(
        self, cwe, rule_id, source, sink_text
    ):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        rule = RetrievedRule(
            **{
                **RULE.__dict__,
                "rule_id": rule_id,
                "yaml_body": f"id: property\n- cwe: {cwe}",
                "risk_categories": ["config"],
            }
        )
        candidate = _candidate(
            rule_id=rule.rule_id,
            code_snippet=source,
            line_start=1,
            line_end=1,
            untrusted_source=None,
            sink=EvidenceLocation(line=1, text=sink_text),
        )
        decision = validate_applicability(candidate, source, self._window(source), rule)
        assert decision.accepted, decision.reason

    @pytest.mark.parametrize(
        "cwe",
        [
            "CWE-208",
            "CWE-295",
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
        ],
    )
    def test_audited_property_cwes_are_classified_sink_only(self, cwe):
        from sentinel.graph.evidence import requires_untrusted_source

        rule = RetrievedRule(
            **{
                **RULE.__dict__,
                "rule_id": f"{cwe.lower()}-property-test",
                "yaml_body": f"id: property\n- cwe: {cwe}",
            }
        )
        assert requires_untrusted_source(rule) is False

    def test_command_argument_list_is_not_command_text_flow(self):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        source = "\n".join(
            [
                "host = request.args['host']",
                'subprocess.run(["ping", "-c", "1", host], check=True)',
            ]
        )
        rule = RetrievedRule(
            **{
                **RULE.__dict__,
                "rule_id": "cwe-78-command-injection-test",
                "yaml_body": "id: command\n- cwe: CWE-78",
            }
        )
        candidate = _candidate(
            rule_id=rule.rule_id,
            line_start=2,
            line_end=2,
            code_snippet=source.split("\n")[1],
            untrusted_source=EvidenceLocation(line=1, text="request.args['host']"),
            sink=EvidenceLocation(line=2, text="subprocess.run"),
        )
        decision = validate_applicability(candidate, source, self._window(source), rule)
        assert decision.reason == "applicability_injection_no_query_text_flow"

    def test_nosql_query_object_flow_is_not_forced_into_text_model(self):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        source = "\n".join(
            [
                "const user = await User.findOne({",
                "  username: req.body.username,",
                "  password: req.body.password,",
                "});",
            ]
        )
        rule = RetrievedRule(
            **{
                **RULE.__dict__,
                "rule_id": "cwe-943-nosql-injection-express-mongo",
                "yaml_body": "id: nosql\n- cwe: CWE-943",
            }
        )
        candidate = _candidate(
            rule_id=rule.rule_id,
            line_start=1,
            line_end=4,
            code_snippet=source,
            untrusted_source=EvidenceLocation(line=2, text="req.body.username"),
            sink=EvidenceLocation(line=1, text="User.findOne"),
        )
        decision = validate_applicability(candidate, source, self._window(source), rule)
        assert decision.accepted, decision.reason


class TestApplicabilityPipelineWiring:
    def test_model_schema_cannot_supply_applicability_rejection_reason(self):
        schema = CandidateFinding.model_json_schema()
        assert "applicability_rejection_reason" not in schema["properties"]
        assert "_applicability_rejection_reason" not in schema["properties"]

    @pytest.mark.asyncio
    async def test_valid_structured_evidence_survives_deep_review_gate(self):
        from sentinel.graph.nodes import deep_review_window
        from sentinel.graph.schemas import DeepReviewOutput, EvidenceLocation
        from sentinel.ingest.chunker import CodeChunk, ReviewWindow

        class FakeGateway:
            async def chat_json(self, _model, _messages, _schema, **_kwargs):
                return DeepReviewOutput(
                    findings=[
                        _candidate(
                            untrusted_source=EvidenceLocation(line=3, text="user_id"),
                            sink=EvidenceLocation(line=4, text="cursor.execute"),
                        )
                    ]
                )

        window = ReviewWindow(
            chunks=[CodeChunk(text=SOURCE, start_line=1, end_line=len(SOURCE.split("\n")))]
        )
        output = await deep_review_window(
            FakeGateway(), "app.py", "python", SOURCE, window, [RULE]
        )
        assert output.findings[0].rule_id == RULE.rule_id

    @pytest.mark.asyncio
    async def test_deep_review_reasoning_defaults_off_and_marks_rejection(self):
        from sentinel.graph.nodes import deep_review_window
        from sentinel.graph.schemas import DeepReviewOutput
        from sentinel.ingest.chunker import CodeChunk, ReviewWindow

        class FakeGateway:
            messages = None

            async def chat_json(self, _model, messages, _schema, **_kwargs):
                self.messages = messages
                return DeepReviewOutput(findings=[_candidate()])

        gateway = FakeGateway()
        window = ReviewWindow(
            chunks=[CodeChunk(text=SOURCE, start_line=1, end_line=len(SOURCE.split("\n")))]
        )
        output = await deep_review_window(
            gateway, "app.py", "python", SOURCE, window, [RULE]
        )
        assert gateway.messages[0] == {"role": "system", "content": "/no_think"}
        assert output.findings[0].rule_id == RULE.rule_id
        assert (
            output.findings[0].applicability_rejection_reason
            == "applicability_missing_sink"
        )

    @pytest.mark.asyncio
    async def test_near_miss_rule_id_cannot_bypass_applicability_gate(self):
        from sentinel.graph.nodes import deep_review_window
        from sentinel.graph.schemas import DeepReviewOutput
        from sentinel.ingest.chunker import CodeChunk, ReviewWindow

        class FakeGateway:
            async def chat_json(self, _model, _messages, _schema, **_kwargs):
                return DeepReviewOutput(
                    findings=[
                        _candidate(rule_id="owasp-a14-sql-injection-python-string-format")
                    ]
                )

        window = ReviewWindow(
            chunks=[CodeChunk(text=SOURCE, start_line=1, end_line=len(SOURCE.split("\n")))]
        )
        output = await deep_review_window(
            FakeGateway(), "app.py", "python", SOURCE, window, [RULE]
        )
        assert output.findings[0].rule_id == "owasp-a14-sql-injection-python-string-format"
        assert (
            output.findings[0].applicability_rejection_reason
            == "applicability_missing_sink"
        )

    @pytest.mark.asyncio
    async def test_deep_review_reasoning_can_be_enabled_explicitly(self):
        from sentinel.graph.nodes import deep_review_window
        from sentinel.graph.schemas import DeepReviewOutput
        from sentinel.ingest.chunker import CodeChunk, ReviewWindow

        class FakeGateway:
            messages = None

            async def chat_json(self, _model, messages, _schema, **_kwargs):
                self.messages = messages
                return DeepReviewOutput(findings=[])

        gateway = FakeGateway()
        window = ReviewWindow(chunks=[CodeChunk(text="x = 1", start_line=1, end_line=1)])
        await deep_review_window(
            gateway, "app.py", "python", "x = 1", window, [RULE], reasoning_enabled=True
        )
        assert gateway.messages[0] == {"role": "system", "content": "/think"}


class TestCSharpApplicability:
    @staticmethod
    def _rule(cwe: str, rule_id: str = "csharp-test-rule") -> RetrievedRule:
        return RetrievedRule(
            **{
                **RULE.__dict__,
                "rule_id": rule_id,
                "yaml_body": f"id: {rule_id}\ntaxonomy:\n  - cwe: {cwe}",
                "languages": ["csharp"],
                "frameworks": ["aspnetcore"],
            }
        )

    @staticmethod
    def _window(source: str):
        from sentinel.ingest.chunker import CodeChunk, ReviewWindow

        return ReviewWindow(
            chunks=[CodeChunk(text=source, start_line=1, end_line=len(source.split("\n")))]
        )

    def test_csharp_interpolated_sql_flow_and_parameter_control(self):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        rule = self._rule("CWE-89", "cwe-89-sql-injection-csharp")
        vulnerable = "\n".join(
            [
                "var name = request.Query[\"name\"];",
                'var sql = $"SELECT * FROM Users WHERE Name = \'{name}\'";',
                "command.CommandText = sql;",
            ]
        )
        candidate = _candidate(
            rule_id=rule.rule_id,
            line_start=3,
            line_end=3,
            code_snippet="command.CommandText = sql;",
            untrusted_source=EvidenceLocation(line=1, text='request.Query["name"]'),
            sink=EvidenceLocation(line=3, text="CommandText"),
        )
        assert validate_applicability(
            candidate, vulnerable, self._window(vulnerable), rule, grammar="csharp"
        ).accepted

        parameterized = "\n".join(
            [
                "var name = request.Query[\"name\"];",
                'command.CommandText = "SELECT * FROM Users WHERE Name = @name";',
                'command.Parameters.AddWithValue("@name", name);',
            ]
        )
        candidate = candidate.model_copy(
            update={
                "line_start": 2,
                "line_end": 2,
                "code_snippet": parameterized.split("\n")[1],
                "sink": EvidenceLocation(line=2, text="CommandText"),
            }
        )
        decision = validate_applicability(
            candidate, parameterized, self._window(parameterized), rule, grammar="csharp"
        )
        assert decision.reason == "applicability_injection_no_query_text_flow"

    def test_ado_net_command_constructor_is_a_query_operation(self):
        """`new SqlCommand(sql, connection)` is the commonest C# SQLi shape.

        ADO.NET puts the statement in the command's first constructor argument
        rather than in a method call or a CommandText assignment, so a gate that
        only knew Execute*/CommandText/FromSqlRaw saw no query operation on the
        sink line and rejected real findings as sink_not_query_operation.
        """
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        rule = self._rule("CWE-89", "cwe-89-sql-injection-csharp")
        source = "\n".join(
            [
                'var name = Request.Query["name"];',
                'var query = $"SELECT * FROM Users WHERE Name = \'{name}\'";',
                "await using var command = new SqlCommand(query, connection);",
            ]
        )
        candidate = _candidate(
            rule_id=rule.rule_id,
            line_start=3,
            line_end=3,
            code_snippet="await using var command = new SqlCommand(query, connection);",
            untrusted_source=EvidenceLocation(line=1, text='Request.Query["name"]'),
            sink=EvidenceLocation(line=3, text="SqlCommand"),
        )
        decision = validate_applicability(
            candidate, source, self._window(source), rule, grammar="csharp"
        )
        assert decision.accepted, decision.reason

    def test_ado_net_parameterised_command_is_still_rejected(self):
        """The constructor shape must not become a blanket pass."""
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        rule = self._rule("CWE-89", "cwe-89-sql-injection-csharp")
        parameterised = (
            'await using var command = new SqlCommand("SELECT * FROM Users '
            'WHERE Name = @name", connection);'
        )
        source = "\n".join(
            [
                'var name = Request.Query["name"];',
                parameterised,
                'command.Parameters.AddWithValue("@name", name);',
            ]
        )
        candidate = _candidate(
            rule_id=rule.rule_id,
            line_start=2,
            line_end=2,
            code_snippet=parameterised,
            untrusted_source=EvidenceLocation(line=1, text='Request.Query["name"]'),
            sink=EvidenceLocation(line=2, text="SqlCommand"),
        )
        decision = validate_applicability(
            candidate, source, self._window(source), rule, grammar="csharp"
        )
        assert decision.reason == "applicability_injection_no_query_text_flow"

    def test_template_literal_interpolation_is_not_masked_away(self):
        """`${...}` inside a template literal is executable code, not a string.

        Masking the whole literal would hide the sink that lives in the hole and
        turn a hardening measure into a false-negative source for JavaScript,
        where this shape is the normal way to build a query.
        """
        from sentinel.graph.evidence import _first_call_argument, _mask_non_code

        line = "const value = `${db.query(taintedSql)}`;"
        masked, still_open = _mask_non_code(line)
        assert "db.query(taintedSql)" in masked, "interpolation must survive masking"
        assert still_open is False
        assert _first_call_argument(line) == "taintedSql"

    def test_block_comment_opened_on_an_earlier_line_is_carried_forward(self):
        """A line-only lexer cannot see a `/*` opened above it.

        Without that state the commented call is picked as the query operation
        for a statement that is properly parameterised, which is fail-open.
        """
        from sentinel.graph.evidence import _block_comment_open_at, _first_call_argument

        lines = [
            "/*",
            "SqlCommand(user, conn) */ var c = new SqlCommand(safeSql, conn);",
        ]
        assert _block_comment_open_at(lines, 2, "csharp") is True
        assert _first_call_argument(lines[1], True, "csharp") == "safeSql"
        # and without the carried state it would wrongly read the commented call
        assert _first_call_argument(lines[1], False, "csharp") == "user"

    def test_commented_sink_cannot_supply_the_argument_for_a_real_one(self):
        """Locate the operation in CODE, not in a comment on the same line.

        The executability check accepts any occurrence of the sink text on the
        line, so if the argument is read from the FIRST regex hit anywhere, a
        commented-out call can donate a tainted argument to a real call that is
        properly parameterised — the finding then passes on evidence from two
        different constructs.
        """
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        rule = self._rule("CWE-89", "cwe-89-sql-injection-csharp")
        real_call = (
            '/* new SqlCommand(name, connection) */ using var c = new SqlCommand('
            '"SELECT * FROM Users WHERE Name = @name", connection);'
        )
        source = "\n".join([
            'var name = Request.Query["name"];',
            real_call,
            'c.Parameters.AddWithValue("@name", name);',
        ])
        candidate = _candidate(
            rule_id=rule.rule_id,
            line_start=2,
            line_end=2,
            code_snippet=real_call,
            untrusted_source=EvidenceLocation(line=1, text='Request.Query["name"]'),
            sink=EvidenceLocation(line=2, text="SqlCommand"),
        )
        decision = validate_applicability(
            candidate, source, self._window(source), rule, grammar="csharp"
        )
        assert not decision.accepted
        assert decision.reason == "applicability_injection_no_query_text_flow"

    @pytest.mark.parametrize(
        "source,sink_text,grammar",
        [
            ("// Process.Start(request.Command);", "Process.Start", "csharp"),
            ('var sample = "Process.Start(request.Command);";', "Process.Start", "csharp"),
            ("<pre>Process.Start(request.Command);</pre>", "Process.Start", "razor"),
        ],
    )
    def test_displayed_or_nonexecuted_operations_are_rejected(self, source, sink_text, grammar):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        rule = self._rule("CWE-78", "cwe-78-command-injection-csharp")
        candidate = _candidate(
            rule_id=rule.rule_id,
            line_start=1,
            line_end=1,
            code_snippet=source,
            untrusted_source=EvidenceLocation(line=1, text="request.Command"),
            sink=EvidenceLocation(line=1, text=sink_text),
        )
        decision = validate_applicability(
            candidate, source, self._window(source), rule, grammar=grammar
        )
        assert decision.reason == "applicability_sink_not_executable_code"

    def test_string_constructed_then_passed_to_execution_sink_is_allowed(self):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        rule = self._rule("CWE-78", "cwe-78-command-injection-csharp")
        source = "\n".join(
            [
                "var host = request.Query[\"host\"];",
                'var command = $"ping {host}";',
                "Process.Start(command);",
            ]
        )
        candidate = _candidate(
            rule_id=rule.rule_id,
            line_start=3,
            line_end=3,
            code_snippet="Process.Start(command);",
            untrusted_source=EvidenceLocation(line=1, text='request.Query["host"]'),
            sink=EvidenceLocation(line=3, text="Process.Start"),
        )
        decision = validate_applicability(
            candidate, source, self._window(source), rule, grammar="csharp"
        )
        assert decision.accepted, decision.reason

    def test_csharp_environment_secret_and_certificate_controls_are_clean(self):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        secret_rule = self._rule("CWE-798", "cwe-798-hardcoded-secrets-csharp")
        env = 'var apiKey = Environment.GetEnvironmentVariable("SERVICE_API_KEY");'
        secret = _candidate(
            rule_id=secret_rule.rule_id,
            line_start=1,
            line_end=1,
            code_snippet=env,
            untrusted_source=None,
            sink=EvidenceLocation(line=1, text="apiKey"),
        )
        assert validate_applicability(
            secret, env, self._window(env), secret_rule, grammar="csharp"
        ).reason == "applicability_hardcoded_secret_is_environment_read"

        cert_rule = self._rule("CWE-295", "cwe-295-certificate-validation-bypass-csharp")
        secure = (
            "handler.ServerCertificateCustomValidationCallback = "
            "(_, _, _, errors) => errors == SslPolicyErrors.None;"
        )
        cert = _candidate(
            rule_id=cert_rule.rule_id,
            line_start=1,
            line_end=1,
            code_snippet=secure,
            untrusted_source=None,
            sink=EvidenceLocation(line=1, text="ServerCertificateCustomValidationCallback"),
        )
        assert validate_applicability(
            cert, secure, self._window(secure), cert_rule, grammar="csharp"
        ).reason == "applicability_tls_not_explicitly_disabled"

    @pytest.mark.parametrize(
        "cwe,source,sink",
        [
            ("CWE-347", "var token = handler.ReadJwtToken(input);", "ReadJwtToken"),
            ("CWE-352", "app.MapPost(\"/pay\", Pay).DisableAntiforgery();", "DisableAntiforgery"),
            ("CWE-915", "app.MapPut(\"/user\", (User user) => Save(user));", "MapPut"),
            ("CWE-942", "policy.SetIsOriginAllowed(_ => true);", "SetIsOriginAllowed"),
        ],
    )
    def test_csharp_property_shapes_accept_sink_without_source(self, cwe, source, sink):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        rule = self._rule(cwe)
        candidate = _candidate(
            rule_id=rule.rule_id,
            line_start=1,
            line_end=1,
            code_snippet=source,
            untrusted_source=None,
            sink=EvidenceLocation(line=1, text=sink),
        )
        decision = validate_applicability(
            candidate, source, self._window(source), rule, grammar="csharp"
        )
        assert decision.accepted, decision.reason

    def test_csharp_flow_shape_requires_source(self):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation

        source = "await httpClient.GetAsync(url);"
        rule = self._rule("CWE-918", "cwe-918-ssrf-csharp")
        candidate = _candidate(
            rule_id=rule.rule_id,
            line_start=1,
            line_end=1,
            code_snippet=source,
            untrusted_source=None,
            sink=EvidenceLocation(line=1, text="GetAsync"),
        )
        assert validate_applicability(
            candidate, source, self._window(source), rule, grammar="csharp"
        ).reason == "applicability_missing_untrusted_source"


class TestRazorCodeBlockIsParsedAsCSharp:
    """A Blazor page that documents its own vulnerability must not be flagged for it.

    The tree-sitter Razor grammar cannot parse a ``@code`` block containing a C#
    raw string literal — it emits a bare ERROR node, whose ancestry proves
    nothing either way, so displayed sample code read as executable. Real Blazor
    hits this constantly: in the-most-vulnerable-dotnet-app benchmark, 43 of 64
    .razor files fail to parse and 53 embed their own source as
    ``private const string VulnerableCode = \"\"\"...\"\"\"`` teaching material.

    The body of a ``@code`` block is plain C#, so it is parsed with the C#
    grammar, which does model raw/verbatim/interpolated literals. Markup above
    the block still goes through the Razor grammar.
    """

    SOURCE = '\n'.join([
        '@page "/stored-xss"',
        "",
        "@foreach (var comment in comments)",
        "{",
        "    <div>@((MarkupString)comment.Text)</div>",
        "}",
        "",
        "@code {",
        '    private const string VulnerableCode = """',
        "// DANGEROUS: displaying raw HTML",
        "<div>@((MarkupString)comment.Text)</div>",
        '""";',
        "",
        '    [SupplyParameterFromQuery(Name = "q")]',
        "    public string? Query { get; set; }",
        "",
        "    private List<Comment> comments = new();",
        "}",
    ])

    @staticmethod
    def _candidate(line: int):
        from sentinel.graph.schemas import EvidenceLocation

        source_lines = TestRazorCodeBlockIsParsedAsCSharp.SOURCE.split("\n")
        return _candidate(
            rule_id="cwe-79-aspnetcore-raw-rendering",
            line_start=line,
            line_end=line,
            code_snippet=source_lines[line - 1],
            untrusted_source=EvidenceLocation(line=14, text="SupplyParameterFromQuery"),
            sink=EvidenceLocation(line=line, text="MarkupString"),
        )

    @staticmethod
    def _rule():
        return RetrievedRule(
            **{
                **RULE.__dict__,
                "rule_id": "cwe-79-aspnetcore-raw-rendering",
                "yaml_body": "id: cwe-79-aspnetcore-raw-rendering\ntaxonomy:\n  - cwe: CWE-79",
                "languages": ["csharp"],
                "frameworks": ["aspnetcore"],
            }
        )

    def test_real_markup_render_is_executable(self):
        from sentinel.graph.evidence import _sink_is_executable

        assert _sink_is_executable(self._candidate(5), self.SOURCE, "razor", self._rule())

    def test_sample_inside_raw_string_in_code_block_is_not_executable(self):
        from sentinel.graph.evidence import _sink_is_executable

        assert not _sink_is_executable(self._candidate(11), self.SOURCE, "razor", self._rule())

    def test_markup_after_a_code_block_is_not_judged_as_csharp(self):
        """A @code body is bounded; the markup after it is still markup.

        Taking "everything after the first @code" as C# misparses trailing
        markup, so a sample in a <pre> after the block reads as executable C#.
        Razor also permits @functions BEFORE the markup, which puts the whole
        page on the wrong side of that boundary.
        """
        from sentinel.graph.evidence import _sink_is_executable
        from sentinel.graph.schemas import EvidenceLocation

        source = "\n".join([
            "@functions {",
            "    private int Count = 0;",
            "}",
            "",
            "<pre>new SqlCommand(name, connection)</pre>",
        ])
        candidate = _candidate(
            rule_id="cwe-89-sql-injection-csharp",
            line_start=5,
            line_end=5,
            code_snippet="<pre>new SqlCommand(name, connection)</pre>",
            untrusted_source=None,
            sink=EvidenceLocation(line=5, text="SqlCommand"),
        )
        assert not _sink_is_executable(candidate, source, "razor", self._rule())

    def test_brace_inside_a_raw_string_does_not_end_the_code_block(self):
        """The samples these pages hold are full of braces.

        If brace counting does not skip strings and comments, the block ends at
        the first `}` inside a sample and everything after it is misclassified.
        """
        from sentinel.graph.evidence import _razor_code_spans

        source = "\n".join([
            "@code {",
            '    private const string S = """',
            "if (x) { call(); }",
            '""";',
            "    private int After = 1;",
            "}",
        ])
        spans = _razor_code_spans(source)
        assert len(spans) == 1
        start, end = spans[0]
        # the span must still contain the declaration that follows the sample
        assert b"After" in source.encode()[start:end]

    def test_a_quoted_argument_to_a_live_call_is_executable(self):
        """`JS.InvokeVoidAsync("eval", x)` — the danger IS the quoted argument.

        deep_review.md already says a string "actually passed to a query,
        process, template, deserializer, renderer, or other execution sink
        remains eligible". Rejecting every literal wholesale contradicted the
        contract the model is held to and killed a real Blazor finding.
        """
        from sentinel.graph.evidence import _sink_is_executable
        from sentinel.graph.schemas import EvidenceLocation

        source = "\n".join([
            "@code {",
            "    private string Script = string.Empty;",
            '    private Task Run() => JS.InvokeVoidAsync("eval", Script).AsTask();',
            "}",
        ])
        candidate = _candidate(
            rule_id="cwe-79-blazor-unsafe-js-interop",
            line_start=3,
            line_end=3,
            code_snippet=source.split("\n")[2],
            untrusted_source=None,
            sink=EvidenceLocation(line=3, text="eval"),
        )
        assert _sink_is_executable(candidate, source, "razor", self._rule())

    def test_a_literal_that_reaches_no_call_is_still_rejected(self):
        """The documentation-sample rejection must survive the reprieve above."""
        from sentinel.graph.evidence import _sink_is_executable
        from sentinel.graph.schemas import EvidenceLocation

        source = 'var sample = "Process.Start(request.Command);";'
        candidate = _candidate(
            rule_id="cwe-78-command-injection-csharp",
            line_start=1,
            line_end=1,
            code_snippet=source,
            untrusted_source=None,
            sink=EvidenceLocation(line=1, text="Process.Start"),
        )
        assert not _sink_is_executable(candidate, source, "csharp", self._rule())

    def test_code_block_inside_a_razor_comment_is_not_real_csharp(self):
        """@* ... *@ can contain anything, including the text "@code {".

        Treating a commented block as a real C# region would parse its contents
        with the C# tree and let the commented sink read as executable.
        """
        from sentinel.graph.evidence import _razor_code_spans, _sink_is_executable
        from sentinel.graph.schemas import EvidenceLocation

        source = "\n".join([
            '@page "/x"',
            "@code {",
            "    private int A = 1;",
            "}",
            "",
            "@*",
            "@code { var c = new SqlCommand(userInput, conn); }",
            "*@",
        ])
        assert len(_razor_code_spans(source)) == 1, "the commented block is not a block"

        candidate = _candidate(
            rule_id="cwe-89-sql-injection-csharp",
            line_start=7,
            line_end=7,
            code_snippet=source.split("\n")[6],
            untrusted_source=None,
            sink=EvidenceLocation(line=7, text="SqlCommand"),
        )
        assert not _sink_is_executable(candidate, source, "razor", self._rule())

    def test_gate_rejects_the_documented_sample(self):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.ingest.chunker import CodeChunk, ReviewWindow

        line_count = len(self.SOURCE.split("\n"))
        window = ReviewWindow(
            chunks=[CodeChunk(text=self.SOURCE, start_line=1, end_line=line_count)]
        )
        decision = validate_applicability(
            self._candidate(11), self.SOURCE, window, self._rule(), grammar="razor"
        )
        assert decision.reason == "applicability_sink_not_executable_code"


class TestResolvedEvidenceReachesTheJudge:
    """The judge is told these lines were verified, so they must be the found ones.

    _line_at tolerates the model's line drifting by a few lines and recomputes
    the line from where the text actually sits. If the finding then carries the
    model's CLAIMED line instead, judge_refute.md's promise — "located in this
    file by a deterministic checker" — is false for that line, and the judge
    reasons about a location nothing verified.
    """

    def test_applicability_returns_the_located_lines(self):
        from sentinel.graph.evidence import validate_applicability
        from sentinel.graph.schemas import EvidenceLocation
        from sentinel.ingest.chunker import CodeChunk, ReviewWindow

        rule = RetrievedRule(
            **{
                **RULE.__dict__,
                "rule_id": "cwe-89-sql-injection-csharp",
                "yaml_body": "id: cwe-89-sql-injection-csharp\ntaxonomy:\n  - cwe: CWE-89",
                "languages": ["csharp"],
            }
        )
        source = "\n".join([
            "// comment header the model points at",
            'var name = Request.Query["name"];',
            'var query = $"SELECT * FROM Users WHERE Name = \'{name}\'";',
            "await using var command = new SqlCommand(query, connection);",
        ])
        window = ReviewWindow(chunks=[CodeChunk(text=source, start_line=1, end_line=4)])
        candidate = _candidate(
            rule_id=rule.rule_id,
            line_start=4,
            line_end=4,
            code_snippet="await using var command = new SqlCommand(query, connection);",
            # claims line 1 for a source that actually lives on line 2
            untrusted_source=EvidenceLocation(line=1, text='Request.Query["name"]'),
            sink=EvidenceLocation(line=4, text="SqlCommand"),
        )
        decision = validate_applicability(candidate, source, window, rule, grammar="csharp")
        assert decision.accepted, decision.reason
        assert decision.resolved_source is not None
        assert decision.resolved_source.line == 2, "must report where the text was FOUND"
        assert decision.resolved_sink is not None
        assert decision.resolved_sink.line == 4

    def test_auth_enforcement_reason_is_rendered_for_the_judge(self):
        """Access-control findings have no source; the reason IS the evidence."""
        from sentinel.graph.nodes import _format_evidence

        rendered = _format_evidence(
            {
                "untrusted_source": None,
                "sink": {"line": 12, "text": "MapDelete"},
                "auth_missing_enforcement_reason": "no [Authorize] on the route",
            }
        )
        assert "sink — line 12: MapDelete" in rendered
        assert "no [Authorize] on the route" in rendered

    def test_evidence_renders_placeholder_when_nothing_recorded(self):
        from sentinel.graph.nodes import _format_evidence

        assert _format_evidence({}) == "(none recorded)"


class TestRefutationJudge:
    @staticmethod
    def _finding():
        return {
            "rule_id": RULE.rule_id,
            "claimed_severity": "high",
            "file_path": "app.py",
            "line_start": 4,
            "line_end": 4,
            "code_snippet": _candidate().code_snippet,
            "explanation": _candidate().explanation,
            "grounded_in_rule_chunk": RULE.yaml_body,
        }

    @pytest.mark.asyncio
    async def test_failed_refutation_survives_even_if_guardian_disagrees(self):
        from sentinel.graph.nodes import judge_finding
        from sentinel.graph.schemas import RefutationVerdict

        class FakeGateway:
            async def chat_json(self, model, messages, schema, **_kwargs):
                assert model == "deep-review"
                assert messages[0]["content"] == "/think"
                assert schema is RefutationVerdict
                return RefutationVerdict(
                    refuted=False,
                    confidence=0.82,
                    reasoning="No concrete safe mechanism is visible.",
                )

            async def judge_groundedness(self, **_kwargs):
                return False, 0.02, "textual entailment signal disagrees"

        verdict = await judge_finding(FakeGateway(), self._finding())
        assert verdict["grounded"] is True
        assert verdict["groundedness_score"] == 1.0
        assert verdict["guardian_secondary"]["grounded"] is False

    @pytest.mark.asyncio
    async def test_concrete_refutation_rejects_even_if_guardian_confirms(self):
        from sentinel.graph.nodes import judge_finding
        from sentinel.graph.schemas import RefutationVerdict

        class FakeGateway:
            async def chat_json(self, _model, _messages, _schema, **_kwargs):
                return RefutationVerdict(
                    refuted=True,
                    confidence=0.97,
                    reasoning="The untrusted value is passed only as a bound parameter.",
                )

            async def judge_groundedness(self, **_kwargs):
                return True, 0.99, "textually grounded"

        verdict = await judge_finding(FakeGateway(), self._finding())
        assert verdict["grounded"] is False
        assert verdict["groundedness_score"] == 0.0
        assert verdict["guardian_secondary"]["grounded"] is True
