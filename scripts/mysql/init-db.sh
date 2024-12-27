#!/usr/bin/env bash

set -euo pipefail

# See docs/testing.md, sections on "test pollution" and "parallelism"
NUM_OF_DATABASES_TO_CREATE=24

function initDB() {
  mysql -uroot -pchangeme <<-EOSQL
  SET GLOBAL max_connections = 250;
  DROP DATABASE IF EXISTS uaa;
  CREATE DATABASE uaa DEFAULT CHARACTER SET utf8mb4;
EOSQL
}

function createDB() {
  DATABASE_NAME="uaa_${1}"
  echo "Creating MySQL database with name ${DATABASE_NAME}"
  mysql  -uroot -pchangeme <<-EOSQL
    DROP DATABASE IF EXISTS $DATABASE_NAME;
    CREATE DATABASE $DATABASE_NAME DEFAULT CHARACTER SET utf8mb4;
EOSQL
}

function setTimezone() {
  # If the "TZ" env var is set in the container definition, then set the
  # DB at the given timezone. When "TZ" is unset, use the DB default (UTC).
  #
  # This is important because the database should run in the same timezone as the UAA,
  # and, in the case of tests, the same timezone as the JVM running the tests.
  #
  # We achieve consistency by changing the timezone inside the DB; because setting
  # it in the container is complicated. The container is missing the `timedatectl`
  # binary ; and the script runs as the mysql user which does not have sudo privileges.
  if [[ -n "$TZ" ]]; then
    echo "Setting DB timezone to: $TZ"
    mysql -uroot -pchangeme <<-EOSQL
    SET GLOBAL time_zone = "$TZ";
EOSQL
  fi
}



initDB

for db_id in `seq 1 $NUM_OF_DATABASES_TO_CREATE`; do
  createDB $db_id
done