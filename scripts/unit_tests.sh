#!/usr/bin/env bash
set -eu

#######################################
# The main function to run the unit tests within a container
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
    # The default max heap size for Gradle is 512MB, increase to avoid DaemonDisappearedException
    export GRADLE_OPTS="-Xmx2048m"
    ./gradlew "-Dspring.profiles.active=${test_profile}" \
            "-Djava.security.egd=file:/dev/./urandom" \
            test \
            --stacktrace  \
            --console=plain
  popd
}

main "$@"
