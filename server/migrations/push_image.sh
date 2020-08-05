#!/usr/bin/env bash
set -eu -o pipefail

UAA_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../.." && pwd )"

DOCKER_ROOT="${UAA_DIR}/server/migrations"
DOCKER_IMAGE="${IMAGE_TAG:-"swaggoner/uaa_flyway_migrations"}"

"${UAA_DIR}/scripts/gradle" clean shadowJar

cp -v "${UAA_DIR}/server/build/libs/UAA-FlywayMigrationRunner-0.0.0-all.jar" "${DOCKER_ROOT}"

docker build --tag ${DOCKER_IMAGE} "${DOCKER_ROOT}"

docker push "${DOCKER_IMAGE}"
