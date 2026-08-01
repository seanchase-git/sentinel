-- Sentinel rules corpus schema (database: sentinel_rules)
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE IF NOT EXISTS rules (
    id TEXT PRIMARY KEY,
    yaml_body TEXT NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    detection_criteria TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    languages TEXT[] NOT NULL,
    frameworks TEXT[] NOT NULL DEFAULT '{}',
    risk_categories TEXT[] NOT NULL,
    taxonomy JSONB NOT NULL,
    -- PRD names this column "references"; renamed because REFERENCES is a
    -- reserved word in PostgreSQL's grammar (plan deviation D4).
    refs JSONB,
    embedding vector(768) NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS rules_embedding_idx ON rules USING hnsw (embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS rules_languages_idx ON rules USING GIN (languages);
CREATE INDEX IF NOT EXISTS rules_frameworks_idx ON rules USING GIN (frameworks);
CREATE INDEX IF NOT EXISTS rules_risk_categories_idx ON rules USING GIN (risk_categories);
CREATE INDEX IF NOT EXISTS rules_severity_idx ON rules (severity);
