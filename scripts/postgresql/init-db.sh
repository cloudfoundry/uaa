#!/usr/bin/env bash

set -euo pipefail

# See docs/testing.md, sections on "test pollution" and "parallelism"
NUM_OF_DATABASES_TO_CREATE=24

function initDB() {
  psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DROP DATABASE IF EXISTS uaa;
    CREATE DATABASE uaa;
    DROP USER IF EXISTS root;
    CREATE USER root WITH SUPERUSER PASSWORD '$POSTGRES_PASSWORD';
    SHOW max_connections;
EOSQL
}

function createDB() {
  DATABASE_NAME="uaa_${1}"
  echo "Creating PostgreSQL database with name ${DATABASE_NAME}"
  psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    DROP DATABASE IF EXISTS $DATABASE_NAME;
    CREATE DATABASE $DATABASE_NAME;
EOSQL
}

initDB

for db_id in `seq 1 $NUM_OF_DATABASES_TO_CREATE`; do
  createDB $db_id
done