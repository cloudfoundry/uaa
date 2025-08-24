#!/bin/bash

set -xeu
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

CONTAINER_SCRIPT_DIR='/root/uaa'
GRADLE_LOCK_DIR='/root/uaa/.gradle/'

DB="${1:-hsqldb}"

case "${DB}" in
    hsqldb)
        DB_IMAGE_NAME=postgresql # we don't have a container image for hsqldb, and can use any image
        DB=hsqldb
        PROFILE_NAME=hsqldb
        ;;

    percona)
        DB_IMAGE_NAME=percona
        DB=percona
        PROFILE_NAME=mysql
        ;;

    postgresql|postgresql-15|postgresql-11)
        DB_IMAGE_NAME=$1
        DB=postgresql
        PROFILE_NAME=postgresql
        ;;

    mysql|mysql-8)
        DB_IMAGE_NAME=mysql-8
        DB=mysql
        PROFILE_NAME=mysql
        ;;

    mysql-5)
        DB_IMAGE_NAME=mysql
        DB=mysql
        PROFILE_NAME=mysql
        ;;

    *)
        echo $"ERROR: $1 is not a known database type. Supported types are: hsqldb, percona, postgresql, mysql"
        exit 1
esac

if [[ -z "${DOCKER_IMAGE+x}" ]]; then
    DOCKER_IMAGE="cfidentity/uaa-${DB_IMAGE_NAME}"
fi

docker run \
  --privileged \
  --tty \
  --interactive \
  --shm-size=1G \
  --volume "${SCRIPT_DIR}":"${CONTAINER_SCRIPT_DIR}" \
  --volume "${GRADLE_LOCK_DIR}" \
  --env DB="${DB}" \
  "${DOCKER_IMAGE}" \
  /root/uaa/scripts/unit-tests.sh "${PROFILE_NAME}" "${CONTAINER_SCRIPT_DIR}"
