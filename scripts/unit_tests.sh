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
    echo "Setting Gradle build heap to ${gradle_heap:=512m}"
    echo "Setting Gradle test heap to ${gradle_test_heap:=512m}"
    echo "Setting Gradle metaspace to ${gradle_metaspace:=128m}"

    ./gradlew "-Dspring.profiles.active=${test_profile}" \
                "-Djava.security.egd=file:/dev/./urandom" \
                "-Dorg.gradle.jvmargs=-Dfile.encoding=utf8 -Xms64m -Xmx${gradle_heap} -XX:MaxMetaspaceSize=${gradle_metaspace} -XX:+UseG1GC -XX:MaxGCPauseMillis=100" \
                assemble compileTestJava \
                --stacktrace  \
                --no-daemon \
                --console=plain

    ./gradlew "-Dspring.profiles.active=${test_profile}" \
            "-Djava.security.egd=file:/dev/./urandom" \
            "-Dorg.gradle.jvmargs=-Dfile.encoding=utf8 -Xms64m -Xmx${gradle_test_heap} -XX:MaxMetaspaceSize=${gradle_metaspace} -XX:+UseG1GC -XX:MaxGCPauseMillis=100" \
            ${UAA_GRADLE_UNIT_TEST_COMMAND:-test} \
            --stacktrace  \
            --no-daemon \
            --console=plain
  popd
}

main "$@"
