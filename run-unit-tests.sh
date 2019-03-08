#!/bin/bash

set -xeu
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

CONTAINER_SCRIPT_DIR='/root/uaa'
GRADLE_LOCK_DIR='/root/uaa/.gradle/'

case "$1" in
    hsqldb)
        DB_IMAGE_NAME=postgresql
        PROFILE_NAME=hsqldb
        ;;

    percona)
        DB_IMAGE_NAME=percona
        PROFILE_NAME=mysql
        ;;

    postgresql|sqlserver|mysql)
        DB_IMAGE_NAME=$1
        PROFILE_NAME=$1
        ;;

    *)
        echo $"$1 is not a known database type. Supported types are: hsqldb, percona, postgresql, sqlserver, mysql"
        exit 1
esac

docker run --privileged -t -i --shm-size=1G  -v "${SCRIPT_DIR}":"${CONTAINER_SCRIPT_DIR}" -v "${GRADLE_LOCK_DIR}" "cfidentity/uaa-${DB_IMAGE_NAME}" /root/uaa/scripts/unit-tests.sh "${PROFILE_NAME}",default "${CONTAINER_SCRIPT_DIR}"
