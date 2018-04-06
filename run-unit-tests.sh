#!/bin/bash

set -xeu
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

DB_IMAGE_NAME="$1"

docker run --privileged -t -i --shm-size=1G  -v ${SCRIPT_DIR}:/root/uaa cfidentity/uaa-${DB_IMAGE_NAME} /root/uaa/scripts/unit-tests.sh ${DB_IMAGE_NAME},default