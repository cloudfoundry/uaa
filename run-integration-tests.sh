#!/bin/bash

set -xeu -o pipefail
DB="${1:-hsqldb}"

UAA_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONTAINER_MOUNT_POINT='/root/uaa'

UAA_DIR_BASENAME="$(basename "${UAA_DIR}")"
if [[ ("${UAA_DIR_BASENAME}" != 'lts-uaa') && ("${UAA_DIR_BASENAME}" != 'uaa') ]];
then
    echo 'The script must be at the root of the lts-uaa repo' >&2
    exit 1
fi

function UAA_DIR_is_a_git_submodule {
    [[ -f .git ]]
    return "$?"
}

if UAA_DIR_is_a_git_submodule; then
   VOLUME_TO_ATTACH=$(cd "${UAA_DIR}/../.." && pwd)
   CONTAINER_SCRIPT_DIR="${CONTAINER_MOUNT_POINT}/src/uaa/scripts"
   CONTAINER_GRADLE_LOCK_DIR="${CONTAINER_MOUNT_POINT}/src/uaa/.gradle/"
else
   VOLUME_TO_ATTACH="${UAA_DIR}"
   CONTAINER_SCRIPT_DIR="${CONTAINER_MOUNT_POINT}/scripts"
   CONTAINER_GRADLE_LOCK_DIR="${CONTAINER_MOUNT_POINT}/.gradle/"
fi

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
docker pull "${DOCKER_IMAGE}"
docker run --privileged --tty --interactive --shm-size=1G \
  --volume "${VOLUME_TO_ATTACH}:${CONTAINER_MOUNT_POINT}" \
  --volume "${CONTAINER_GRADLE_LOCK_DIR}" \
  --env DB="${DB}" \
  "${DOCKER_IMAGE}" \
  "${CONTAINER_SCRIPT_DIR}/integration-tests.sh" "${PROFILE_NAME},default"
