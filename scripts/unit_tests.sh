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

  # See https://docs.gradle.org/9.2.0/userguide/config_gradle.html#sec:configuring_jvm_memory
  echo "Setting Gradle daemon heap to ${gradle_heap:=1024m}"
  echo "Setting test worker heap to ${gradle_test_heap:=640m}"

  set -x
  ./gradlew -Dspring.profiles.active="${test_profile}" \
            -Djava.security.egd=file:/dev/./urandom \
            "-Dorg.gradle.jvmargs=-Dfile.encoding=utf8 -Xms64m -Xmx${gradle_heap} -XX:MaxMetaspaceSize=384m -XX:+UseG1GC -XX:MaxGCPauseMillis=100" \
            clean compileTestJava \
            --no-watch-fs \
            --no-daemon \
            --no-configuration-cache \
            --max-workers=2 \
            --stacktrace \
            --console=plain

    ./gradlew -Dspring.profiles.active="${test_profile}" \
            -Djava.security.egd=file:/dev/./urandom \
            "-Dorg.gradle.jvmargs=-Dfile.encoding=utf8 -Xms64m -Xmx${gradle_test_heap} -XX:MaxMetaspaceSize=384m -XX:+UseG1GC -XX:MaxGCPauseMillis=100 -XX:ParallelGCThreads=2 -XX:CICompilerCount=2 -Djdk.lang.processReaperUseDefaultStackSize=true" \
            -Dorg.gradle.daemon.idletimeout=300000 \
            -Dorg.gradle.parallel=false \
            -Dorg.gradle.workers.max=2 \
            ${UAA_GRADLE_UNIT_TEST_COMMAND:-test} \
            --no-watch-fs \
            --no-daemon \
            --no-configuration-cache \
            --max-workers=2 \
            --stacktrace \
            --console=plain

    { set +x; } 2>/dev/null
  popd
}

main "$@"
