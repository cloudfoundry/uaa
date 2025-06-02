#!/bin/bash

set -xeu -o pipefail
DB="${1:-hsqldb}"
BOOT="${2:-false}"

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

CONTAINER_SCRIPT_DIR='/root/uaa'
GRADLE_LOCK_DIR='/root/uaa/.gradle/'

case "${DB}" in
    hsqldb)
        DB_IMAGE_NAME=postgresql # we don't have a container image for hsqldb, and can use any image
        PROFILE_NAME="$DB"
        ;;

    percona)
        DB_IMAGE_NAME="$DB"
        PROFILE_NAME=mysql
        ;;

    postgresql)
        DB_IMAGE_NAME="$DB"
        PROFILE_NAME="$DB"
        ;;

    mysql|mysql-8)
        DB_IMAGE_NAME=mysql-8
        PROFILE_NAME=mysql
        ;;

    mysql-5)
        DB_IMAGE_NAME=mysql
        PROFILE_NAME=mysql
        ;;

    *)
        echo "ERROR: '$DB' is not a known database type. Supported types are: hsqldb, percona, postgresql, mysql"
        exit 1
esac

if [[ -z "${DOCKER_IMAGE+x}" ]]; then
    DOCKER_IMAGE="cfidentity/uaa-${DB_IMAGE_NAME}"
fi
echo "Using docker image: ${DOCKER_IMAGE}"
docker pull ${DOCKER_IMAGE}
docker run --privileged -t -i --shm-size=1G \
  -v "${SCRIPT_DIR}":"${CONTAINER_SCRIPT_DIR}" \
  -v "${GRADLE_LOCK_DIR}" \
  --env DB="${DB}" \
  --env RUN_TESTS="${RUN_TESTS:-true}" \
  --publish 8081:8080 \
  "${DOCKER_IMAGE}" \
  /root/uaa/scripts/integration-tests.sh "${PROFILE_NAME}" "${CONTAINER_SCRIPT_DIR}" ${BOOT}
