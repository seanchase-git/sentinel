#!/usr/bin/env bash
# Idempotent Postgres setup for Sentinel: database, pgvector extension, schema.
set -euo pipefail

DB_NAME="${SENTINEL_DB_NAME:-sentinel_rules}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if ! pg_isready -q; then
    echo "error: Postgres is not running (try: brew services start postgresql@17)" >&2
    exit 1
fi

if ! psql -lqt | cut -d '|' -f 1 | grep -qw "$DB_NAME"; then
    createdb "$DB_NAME"
    echo "created database $DB_NAME"
fi

psql -v ON_ERROR_STOP=1 -q -d "$DB_NAME" -f "$SCRIPT_DIR/schema.sql"
echo "schema applied to $DB_NAME"
