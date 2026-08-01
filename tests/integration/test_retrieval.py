from pathlib import Path

import pytest

from sentinel.retrieval.embedder import EMBEDDING_DIM, Embedder
from sentinel.retrieval.rules_store import RulesStore
from sentinel.rules.loader import load_rules

pytestmark = pytest.mark.integration

REPO_ROOT = Path(__file__).resolve().parents[2]

FLASK_SQLI_SNIPPET = '''
@app.route("/user/<user_id>")
def show_user(user_id):
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")
    return jsonify(cursor.fetchone())
'''


def test_embedding_dimension(embedder_backend):
    with Embedder() as embedder:
        vec = embedder.embed_query("SELECT * FROM users")
    assert len(vec) == EMBEDDING_DIM


def test_corpus_loaded(rules_db):
    corpus = load_rules(REPO_ROOT / "rules")
    with RulesStore() as store:
        assert store.count() == len(corpus.rules)


def test_sqli_snippet_retrieves_sqli_rule_first(embedder_backend, rules_db):
    with Embedder() as embedder:
        vec = embedder.embed_query(FLASK_SQLI_SNIPPET)
    with RulesStore() as store:
        results = store.query_similar(vec, "python", ["injection"], k=5)
    assert results, "no rules retrieved"
    ids = [r.rule_id for r in results]
    # top result must be a SQL-injection rule (the corpus has several close
    # SQLi variants; any is a correct match for a SQLi snippet)
    assert "sql-injection" in ids[0], f"top result {ids[0]} is not a SQLi rule"
    # the specific string-format rule this snippet exemplifies is in the top 5
    assert "owasp-a03-sql-injection-python-string-format" in ids


def test_category_filter_ranks_matching_rules_first(embedder_backend, rules_db):
    with Embedder() as embedder:
        vec = embedder.embed_query(FLASK_SQLI_SNIPPET)
    with RulesStore() as store:
        results = store.query_similar(vec, "python", ["injection"], k=10)
    category_hits = [r for r in results if "injection" in r.risk_categories]
    n = len(category_hits)
    assert results[:n] == category_hits, "category-matching rules must rank before backfill"


def test_language_filter_is_hard(embedder_backend, rules_db):
    with Embedder() as embedder:
        vec = embedder.embed_query("element.innerHTML = userValue")
    with RulesStore() as store:
        results = store.query_similar(vec, "python", None, k=20)
    assert all("python" in r.languages or "any" in r.languages for r in results)


def test_all_rules_self_retrieve_in_top10(embedder_backend, rules_db):
    # Every rule must rank its own vulnerable example in the top 10 of a
    # 48-rule corpus (≈ top 21%), comfortably inside the K=20 used in review.
    # Injection-family rules compete with several close siblings, so top-1 is
    # not always achievable; top-10 proves the rule isn't buried.
    corpus = load_rules(REPO_ROOT / "rules")
    failures = []
    with Embedder() as embedder, RulesStore() as store:
        for rule in corpus.rules:
            vec = embedder.embed_query(rule.example_vulnerable)
            language = next((lang for lang in rule.languages if lang != "any"), "python")
            retrieved = store.query_similar(vec, language, rule.risk_categories, k=20)
            rank = next(
                (i + 1 for i, r in enumerate(retrieved) if r.rule_id == rule.id), None
            )
            if rank is None or rank > 10:
                failures.append((rule.id, rank))
    assert not failures, f"rules failed top-10 self-retrieval: {failures}"
