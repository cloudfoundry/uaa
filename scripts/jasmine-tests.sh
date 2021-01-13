#!/usr/bin/env bash
set -xeu
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
CONTAINER_SCRIPT_DIR='/root/uaa'
DOCKER_IMAGE='cfidentity/uaa-singular'

if grep -q docker /proc/1/cgroup; then
   echo inside docker
   pushd ${CONTAINER_SCRIPT_DIR}/uaa
   npm ci
   npm test
   popd
else
   echo on host
   pushd ${SCRIPT_DIR}
   docker run \
  --privileged \
  --tty \
  --interactive \
  --volume "${SCRIPT_DIR}/..":"${CONTAINER_SCRIPT_DIR}" \
   "${DOCKER_IMAGE}" \
   /root/uaa/scripts/jasmine-tests.sh
   popd
fi
