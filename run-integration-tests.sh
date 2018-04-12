#!/bin/bash

set -xeu
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

DB_IMAGE_NAME="$1"
CONTAINER_SCRIPT_DIR='/root/uaa'

docker run --privileged -t -i --shm-size=1G  -v "${SCRIPT_DIR}":"${CONTAINER_SCRIPT_DIR}" "cfidentity/uaa-${DB_IMAGE_NAME}" /root/uaa/scripts/integration-tests.sh "${DB_IMAGE_NAME}",default "${CONTAINER_SCRIPT_DIR}"
