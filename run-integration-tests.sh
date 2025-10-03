#!/bin/bash
set -eu -o pipefail

#######################################
# main function to run the integration tests
#######################################
main() {
  local script_dir;  script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
  source "${script_dir}/scripts/lib_timer.sh"
  start_timer

  local container_script_dir="/root/uaa"
  local gradle_lock_dir="/root/uaa/.gradle/"
  local run_as_boot="${2:-false}"
  source "${script_dir}/scripts/lib_database_variants.sh"
  parse_db_name "${1:-}"

  echo "Using docker image: ${DOCKER_IMAGE}, DB=${DB}, PROFILE_NAME=${PROFILE_NAME}"
  echo

  docker pull "${DOCKER_IMAGE}"
  docker run \
    --privileged \
    --tty \
    --interactive \
    --platform linux/amd64 \
    --shm-size=1G \
    --volume "${script_dir}":"${container_script_dir}" \
    --volume "${gradle_lock_dir}" \
    --env DB="${DB}" \
    --env RUN_TESTS="${RUN_TESTS:-true}" \
    --publish 8081:8080 \
    "${DOCKER_IMAGE}" \
    /root/uaa/scripts/integration_tests.sh "${PROFILE_NAME}" "${run_as_boot}"
}

main "$@"