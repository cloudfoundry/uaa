#!/usr/bin/env bash
set -eu

#######################################
# The main function to run the unit tests within a container
# Global env vars:
#   UAA_GRADLE_UNIT_TEST_COMMAND: Gradle command to run unit tests (default: test)
#       this could include :cloudfoundry-identity-server:test --tests to run specific tests
#######################################
function main() {
  local script_dir; script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
  source "${script_dir}/lib_db_helper.sh"
  source "${script_dir}/lib_ldap_helper.sh"
  source "${script_dir}/lib_util_helper.sh"
  display_memory

  local test_profile="${1:-hsqldb}"
  setup_hosts_file
  boot_db "${DB}" # DB is set in the Dockerfile for each image

  pushd "$(dirname ${script_dir})"
    start_ldap

    set -x
    ./gradlew "-Dspring.profiles.active=${test_profile}" \
            "-Djava.security.egd=file:/dev/./urandom" \
            ${UAA_GRADLE_UNIT_TEST_COMMAND:-test} \
            --stacktrace  \
            --no-daemon \
            --console=plain
  popd
}

main "$@"
