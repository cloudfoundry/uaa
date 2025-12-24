#!/usr/bin/env bash
set -eu

#######################################
# The main function to run the integration tests within a container
# Global env vars:
#   UAA_GRADLE_INT_TEST_COMMAND: Gradle command to run integration tests (default: integrationTest)
#       this could include :cloudfoundry-identity-server:integrationTest --tests to run specific tests
#   jvm_heap: JVM heap size for UAA boot server (default: 640m)
#   jvm_metaspace: JVM metaspace size for UAA boot server (default: 192m)
#   gradle_heap: JVM heap size for Gradle daemon (default: 1024m)
#   gradle_test_heap: JVM heap size for Gradle test workers (default: 640m)
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

    local wd launch_boot assemble_code integration_test_code
    wd=$(pwd)
    temp_dir=${script_dir}/tmp
    mkdir -p "${temp_dir}"
    
    # Memory settings optimized for Gradle 9.0 with Kotlin 2.2
    # Boot server needs enough memory to handle test requests without crashing
    # Increased Gradle daemon heap to 1GB to prevent hanging with 2 workers
    # --no-configuration-cache prevents stale Kotlin compiler state reuse between daemon processes
    # logging.manager is set to org.apache.logging.log4j.jul.LogManager to prevent log4j2 from using java.util.logging
    # See https://docs.gradle.org/9.2.0/userguide/config_gradle.html#sec:configuring_jvm_memory
    echo "Setting boot heap to ${jvm_heap:=640m}"
    echo "Setting boot metaspace to ${jvm_metaspace:=192m}"
    echo "Setting Gradle daemon heap to ${gradle_heap:=1024m}"
    echo "Setting test worker heap to ${gradle_test_heap:=640m}"

    if [[ "${RUN_TESTS:-true}" = 'true' ]]; then
      set -x
      # Explicit Gradle daemon memory with additional GC tuning
      ./gradlew -Dspring.profiles.active="${test_profile}" \
        -Djava.security.egd=file:/dev/./urandom \
        -Dorg.gradle.jvmargs="-Dfile.encoding=utf8 -Xms64m -Xmx${gradle_heap} -XX:MaxMetaspaceSize=384m -XX:+UseG1GC -XX:MaxGCPauseMillis=100" \
        assemble \
        --no-watch-fs \
        --no-daemon \
        --no-configuration-cache \
        --max-workers=2 \
        --stacktrace \
        --console=plain

      # Start and ensure the boot server is running before integration tests
      nohup java \
        -XX:+UseG1GC \
        -XX:G1HeapRegionSize=1m \
        -Xms64m -Xmx${jvm_heap} \
        -XX:MaxMetaspaceSize=${jvm_metaspace} \
        -XX:MetaspaceSize=${jvm_metaspace} \
        -XX:+UseStringDeduplication \
        -XX:MaxGCPauseMillis=200 \
        -XX:+HeapDumpOnOutOfMemoryError \
        -XX:HeapDumpPath="${wd}" \
        -DCLOUDFOUNDRY_CONFIG_PATH="${wd}/scripts/boot" \
        -Dlogging.config="${wd}/scripts/boot/log4j2.properties" \
        -Dlog4j.configurationFile="${wd}/scripts/boot/log4j2.properties" \
        -Dlog4j2.formatMsgNoLookups=true \
        -Djava.util.logging.manager=org.apache.logging.log4j.jul.LogManager \
        -DSECRETS_DIR="${wd}/scripts/boot" \
        -Djava.security.egd=file:/dev/./urandom \
        -Djava.io.tmpdir="${temp_dir}" \
        -Dorg.bouncycastle.native.loader.install_dir="${temp_dir}" \
        -Dmetrics.perRequestMetrics=true \
        -Dserver.servlet.context-path=/uaa \
        -Dserver.tomcat.basedir="${wd}/scripts/boot/tomcat" \
        -Dsmtp.host=localhost \
        -Dsmtp.port=2525 \
        -Dspring.profiles.active="${test_profile}" \
        -Dstatsd.enabled=true \
        -Dfile.encoding=UTF-8 \
        -Duser.country=US \
        -Duser.language=en \
        -Duser.variant \
        -jar "${wd}/uaa/build/libs/cloudfoundry-identity-uaa-0.0.0.war" \
        > boot.log 2>&1 &
      echo $! > boot.pid
      { set +x; } 2>/dev/null

      if is_boot_running ; then
        echo "Boot started. Can continue to run tests."
      else
        echo "Boot did not start, failing"
        cat boot.log
        exit 1
      fi

      if [[ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]]; then
        export DBUS_SESSION_BUS_ADDRESS=/dev/null
      fi

      set -x
      # Explicit memory limits for test JVMs with GC tuning and classloader fixes
      # All flags required to prevent classloading deadlocks and thread starvation during test init
      # --no-configuration-cache prevents stale Kotlin compiler state reuse between daemon processes
      ./gradlew \
        -Dspring.profiles.active="${test_profile}" \
        -DskipUaaAutoStart=true \
        --no-daemon \
        --no-configuration-cache \
        compileTestJava

      # Explicit memory limits for test JVMs with GC tuning and classloader fixes
      # All flags required to prevent classloading deadlocks and thread starvation during test init
      ./gradlew \
        -Dspring.profiles.active="${test_profile}" \
        -Djava.security.egd=file:/dev/./urandom \
        -DskipUaaAutoStart=true \
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
      
      # Clean up: kill the boot server
      if [[ -f boot.pid ]]; then
        local pid; pid=$(cat boot.pid)
        echo "Sending SIGKILL (kill -9) to UAA process (pid=${pid})"
        kill -9 "${pid}" || true
        rm boot.pid
      fi
    else
      set -x
      echo "./gradlew \
                -Dspring.profiles.active=${test_profile} \
                -DskipUaaAutoStart=true \
                ${UAA_GRADLE_INT_TEST_COMMAND:-integrationTest} \
                --console=plain"
      bash
    fi
  popd
}

main "$@"
