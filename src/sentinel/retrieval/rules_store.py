"""Postgres + pgvector persistence and retrieval for the rules corpus."""

import json
import os
from dataclasses import dataclass

import psycopg
from pgvector.psycopg import register_vector
from psycopg.rows import dict_row

from sentinel.rules.schema import Rule

DEFAULT_DSN = os.environ.get("SENTINEL_DB_DSN", "postgresql:///sentinel_rules")



@dataclass
class RetrievedRule:
    rule_id: str
    title: str
    severity: str
    description: str
    detection_criteria: str
    yaml_body: str
    languages: list[str]
    frameworks: list[str]
    risk_categories: list[str]
    score: float


# advisory lock key for corpus reloads — one full reload at a time
_CORPUS_RELOAD_LOCK = 0x53454E54  # 'SENT'


class RulesStore:
    def __init__(self, dsn: str = DEFAULT_DSN, statement_timeout_ms: int = 15_000):
        # autocommit: reads never leave an implicit transaction open (a failed
        # query would otherwise poison the connection); writes use explicit
        # transaction blocks below.
        self._conn = psycopg.connect(dsn, row_factory=dict_row, autocommit=True)
        # bound any single query so a stuck retrieval can't hang a review
        # (SET does not accept bound parameters; the value is a validated int)
        self._conn.execute(f"SET statement_timeout = {int(statement_timeout_ms)}")
        register_vector(self._conn)

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "RulesStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def replace_corpus(
        self,
        rules: list[Rule],
        yaml_bodies: dict[str, str],
        embeddings: dict[str, list[float]],
    ) -> tuple[int, int]:
        """Atomically upsert all rules and delete stale ones in a single
        transaction, serialized by an advisory lock so concurrent reloads
        can't interleave. Returns (upserted, deleted)."""
        with self._conn.transaction():
            with self._conn.cursor() as cur:
                cur.execute("SELECT pg_advisory_xact_lock(%s)", (_CORPUS_RELOAD_LOCK,))
            upserted = self._upsert_rules(rules, yaml_bodies, embeddings)
            with self._conn.cursor() as cur:
                cur.execute(
                    "DELETE FROM rules WHERE NOT (id = ANY(%s))",
                    ([r.id for r in rules],),
                )
                deleted = cur.rowcount
        return upserted, deleted

    def _upsert_rules(
        self,
        rules: list[Rule],
        yaml_bodies: dict[str, str],
        embeddings: dict[str, list[float]],
    ) -> int:
        rows = [
            (
                rule.id,
                yaml_bodies[rule.id],
                rule.title,
                rule.description,
                rule.detection_criteria,
                rule.severity.value,
                rule.languages,
                rule.frameworks,
                rule.risk_categories,
                json.dumps(rule.taxonomy),
                json.dumps([ref.model_dump() for ref in rule.references]),
                embeddings[rule.id],
            )
            for rule in rules
        ]
        with self._conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO rules (id, yaml_body, title, description, detection_criteria,
                                   severity, languages, frameworks, risk_categories,
                                   taxonomy, refs, embedding)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                ON CONFLICT (id) DO UPDATE SET
                    yaml_body = EXCLUDED.yaml_body,
                    title = EXCLUDED.title,
                    description = EXCLUDED.description,
                    detection_criteria = EXCLUDED.detection_criteria,
                    severity = EXCLUDED.severity,
                    languages = EXCLUDED.languages,
                    frameworks = EXCLUDED.frameworks,
                    risk_categories = EXCLUDED.risk_categories,
                    taxonomy = EXCLUDED.taxonomy,
                    refs = EXCLUDED.refs,
                    embedding = EXCLUDED.embedding,
                    updated_at = NOW()
                """,
                rows,
            )
        return len(rows)

    def count(self) -> int:
        with self._conn.cursor() as cur:
            cur.execute("SELECT count(*) AS n FROM rules")
            return cur.fetchone()["n"]

    def list_rules(self) -> list[dict]:
        with self._conn.cursor() as cur:
            cur.execute(
                """
                SELECT id, title, severity, languages, frameworks, risk_categories, taxonomy
                FROM rules ORDER BY taxonomy->0, id
                """
            )
            return cur.fetchall()

    FRAMEWORK_BOOST = 0.05

    def query_similar(
        self,
        query_embedding: list[float],
        language: str,
        risk_categories: list[str] | None = None,
        framework: str | None = None,
        k: int = 20,
    ) -> list[RetrievedRule]:
        """Top-K rules by cosine similarity with a language hard filter.

        Rules whose risk_categories overlap the classifier's categories rank
        first (by similarity); remaining slots are backfilled language-only so
        a classifier miss can't blind the review (plan contract). A matching
        framework adds a +0.05 soft score boost within each tier.

        When the framework is known, rules declaring a DIFFERENT framework are
        excluded outright rather than merely down-weighted. Validation already
        rejects a finding whose cited rule targets another framework, so those
        rules can only ever produce a rejection: retrieving them spends top-K
        slots that an applicable rule could have used. Language-level rules
        (empty `frameworks`) always stay eligible, and an unknown framework
        keeps the old permissive behaviour."""
        framework_clause = (
            "AND (cardinality(frameworks) = 0 OR %(fw)s = ANY(frameworks))"
            if framework
            else ""
        )
        base_sql = f"""
            SELECT id, title, severity, description, detection_criteria, yaml_body,
                   languages, frameworks, risk_categories,
                   1 - (embedding <=> %(q)s::vector) AS score
            FROM rules
            WHERE (%(lang)s = ANY(languages) OR 'any' = ANY(languages))
            {framework_clause}
            {{category_clause}}
            ORDER BY embedding <=> %(q)s::vector
            LIMIT %(k)s
        """
        params: dict = {"q": query_embedding, "lang": language, "k": k}
        if framework:
            params["fw"] = framework

        rows: list[dict] = []
        if risk_categories:
            with self._conn.cursor() as cur:
                cur.execute(
                    base_sql.format(category_clause="AND risk_categories && %(cats)s"),
                    {**params, "cats": risk_categories},
                )
                rows = cur.fetchall()
        n_filtered = len(rows)
        if len(rows) < k:
            seen = {r["id"] for r in rows}
            with self._conn.cursor() as cur:
                cur.execute(base_sql.format(category_clause=""), params)
                rows.extend(r for r in cur.fetchall() if r["id"] not in seen)
            rows = rows[:k]

        if framework:
            for row in rows:
                if framework in (row["frameworks"] or []):
                    row["score"] = float(row["score"]) + self.FRAMEWORK_BOOST
            # re-rank within tiers: category-filtered rules keep priority
            rows = sorted(rows[:n_filtered], key=lambda r: -float(r["score"])) + sorted(
                rows[n_filtered:], key=lambda r: -float(r["score"])
            )

        return [
            RetrievedRule(
                rule_id=r["id"],
                title=r["title"],
                severity=r["severity"],
                description=r["description"],
                detection_criteria=r["detection_criteria"],
                yaml_body=r["yaml_body"],
                languages=r["languages"],
                frameworks=r["frameworks"],
                risk_categories=r["risk_categories"],
                score=float(r["score"]),
            )
            for r in rows
        ]
