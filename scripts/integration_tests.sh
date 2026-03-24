#!/usr/bin/env bash
set -eu

#######################################
# The main function to run the integration tests within a container
# Global env vars:
#   UAA_GRADLE_INT_TEST_COMMAND: Gradle command to run integration tests (default: integrationTest)
#       this could include :cloudfoundry-identity-server:integrationTest --tests to run specific tests
#   gradle_heap: JVM heap size for Gradle daemon (default: 1024m)
#   gradle_test_heap: JVM heap size for Gradle test workers (default: 640m)
# UAA boot is started and stopped by the integrationTest task in uaa/build.gradle (doFirst/doLast).
#######################################
function main() {
  local script_dir; script_dir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
  source "${script_dir}/lib_db_helper.sh"
  source "${script_dir}/lib_ldap_helper.sh"
  source "${script_dir}/lib_util_helper.sh"
  display_memory

  local test_profile="${1:-hsqldb}"

  setup_hosts_file
  boot_db "${DB:-hsqldb}" # DB is set in the Dockerfile for each image

  pushd "$(dirname ${script_dir})"
    start_ldap

    # Memory settings optimized for Gradle 9.0 with Kotlin 2.2
    # Boot server needs enough memory to handle test requests without crashing
    # Increased Gradle daemon heap to 1GB to prevent hanging with 2 workers
    # --no-configuration-cache prevents stale Kotlin compiler state reuse between daemon processes
    # logging.manager is set to org.apache.logging.log4j.jul.LogManager to prevent log4j2 from using java.util.logging
    # See https://docs.gradle.org/9.2.0/userguide/config_gradle.html#sec:configuring_jvm_memory
    echo "Setting Gradle daemon heap to ${gradle_heap:=1024m}"
    echo "Setting test worker heap to ${gradle_test_heap:=640m}"

    if [[ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]]; then
      export DBUS_SESSION_BUS_ADDRESS=/dev/null
    fi

    if [[ "${RUN_TESTS:-true}" = 'true' ]]; then
      set -x
      # Assemble and compile production code and tests
      ./gradlew -Dspring.profiles.active="${test_profile}" \
        -Djava.security.egd=file:/dev/./urandom \
        -Dorg.gradle.jvmargs="-Dfile.encoding=utf8 -Xms64m -Xmx${gradle_heap} -XX:MaxMetaspaceSize=384m -XX:+UseG1GC -XX:MaxGCPauseMillis=100" \
        assemble compileTestJava \
        --no-watch-fs \
        --no-daemon \
        --no-configuration-cache \
        --max-workers=2 \
        --stacktrace \
        --console=plain

      # integrationTest doFirst in uaa/build.gradle starts UAA and waits for it
      ./gradlew \
        -Dspring.profiles.active="${test_profile}" \
        -Djava.security.egd=file:/dev/./urandom \
        -Dorg.gradle.jvmargs="-Dfile.encoding=utf8 -Xms64m -Xmx${gradle_test_heap} -XX:MaxMetaspaceSize=128m -XX:+UseG1GC -XX:MaxGCPauseMillis=100 -XX:ParallelGCThreads=2 -XX:CICompilerCount=2 -Djdk.lang.processReaperUseDefaultStackSize=true" \
        -Dorg.gradle.daemon.idletimeout=300000 \
        -Dorg.gradle.parallel=false \
        -Dorg.gradle.workers.max=2 \
        ${UAA_GRADLE_INT_TEST_COMMAND:-integrationTest} \
        --no-watch-fs \
        --no-daemon \
        --no-configuration-cache \
        --max-workers=2 \
        --stacktrace \
        --console=plain

      { set +x; } 2>/dev/null
    else
      set -x
      echo "./gradlew -Dspring.profiles.active=${test_profile} ${UAA_GRADLE_INT_TEST_COMMAND:-integrationTest} --console=plain"
      bash
    fi
  popd
}

main "$@"
