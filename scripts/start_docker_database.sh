#!/bin/bash
set -eu -o pipefail

#######################################
# main function to start a docker container with the specified database
# usage: start_docker_database.sh [db_name]
#   db_name: one of "mysql(-*)", "postgres(-*)", etc. (default: "mysql")
#######################################
main() {
  local uaa_dir;  uaa_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )/.." && pwd )"

  local container_script_dir="/root/uaa"
  local gradle_lock_dir="/root/uaa/.gradle/"
  source "${uaa_dir}/scripts/lib_database_variants.sh"
  # Override default to mysql if no argument provided, since there is no hsqldb database to start
  parse_db_name "${1:-mysql}"
  local db_port; db_port=$(database_port "${1:-mysql}")

  echo "Using docker image: ${DOCKER_IMAGE}, DB=${DB}, PROFILE_NAME=${PROFILE_NAME}"
  echo

  echo "To test against this ${PROFILE_NAME} database run with profile:"
  echo "  docker exec -it $(docker ps | grep ${DOCKER_IMAGE} | tail -n 1 | awk '{print $1}') bash"
  echo "  ./gradlew -Dspring.profiles.active=${PROFILE_NAME} test"
  echo "  ./gradlew -Dspring.profiles.active=${PROFILE_NAME} integrationTest"
  echo

  docker pull "${DOCKER_IMAGE}"
  docker run \
    --privileged \
    --tty \
    --interactive \
    --platform linux/amd64 \
    --shm-size=1G \
    --volume "${uaa_dir}":"${container_script_dir}" \
    --volume "${gradle_lock_dir}" \
    --env DB="${DB}" \
    --publish "${db_port}:${db_port}" \
    "${DOCKER_IMAGE}"
}

main "$@"
