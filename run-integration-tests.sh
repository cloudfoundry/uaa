#!/bin/bash

set -xeu
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

DB_IMAGE_NAME="${1}"
PROFILE_NAME="${2}"
DB="${3}"

CONTAINER_SCRIPT_DIR='/root/uaa'
GRADLE_LOCK_DIR='/root/uaa/.gradle/'

docker run --privileged -t -i --shm-size=1G \
  -v "${SCRIPT_DIR}":"${CONTAINER_SCRIPT_DIR}" \
  -v "${GRADLE_LOCK_DIR}" \
  --env DB=${DB} \
  "cfidentity/uaa-${DB_IMAGE_NAME}" \
  /root/uaa/scripts/integration-tests.sh "${PROFILE_NAME}",default "${CONTAINER_SCRIPT_DIR}"
