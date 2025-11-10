#!/usr/bin/env bash
set -eu

#######################################
# The main function to run the integration tests within a container
# Global env vars:
#   UAA_GRADLE_INT_TEST_COMMAND: Gradle command to run integration tests (default: integrationTest)
#       this could include :cloudfoundry-identity-server:integrationTest --tests to run specific tests
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
    echo "Setting heap to ${jvm_heap:=768m}"
    echo "Setting metaspace to ${jvm_metaspace:=256m}"

    readonly launch_boot="nohup java \
               -XX:+UseG1GC -XX:G1HeapRegionSize=1m \
               -Xmx${jvm_heap} \
               -XX:MaxMetaspaceSize=${jvm_metaspace} \
               -XX:+HeapDumpOnOutOfMemoryError \
               -XX:HeapDumpPath=${wd} \
               -DCLOUDFOUNDRY_CONFIG_PATH=${wd}/scripts/boot \
               -Dlogging.config=${wd}/scripts/boot/log4j2.properties \
               -Dlog4j.configurationFile=${wd}/scripts/boot/log4j2.properties \
               -Dlog4j2.formatMsgNoLookups=true \
               -DSECRETS_DIR=${wd}/scripts/boot \
               -Djava.security.egd=file:/dev/./urandom \
               -Djava.io.tmpdir=${temp_dir} \
               -Dorg.bouncycastle.native.loader.install_dir=${temp_dir} \
               -Dmetrics.perRequestMetrics=true \
               -Dserver.servlet.context-path=/uaa \
               -Dserver.tomcat.basedir=${wd}/scripts/boot/tomcat \
               -Dsmtp.host=localhost \
               -Dsmtp.port=2525 \
               -Dspring.profiles.active=${test_profile} \
               -Dstatsd.enabled=true \
               -Dfile.encoding=UTF-8 \
               -Duser.country=US \
               -Duser.language=en \
               -Duser.variant \
               -jar ${wd}/uaa/build/libs/cloudfoundry-identity-uaa-0.0.0.war \
               > boot.log 2>&1 &"

    readonly assemble_code="./gradlew '-Dspring.profiles.active=${test_profile}' \
                '-Djava.security.egd=file:/dev/./urandom' \
                assemble \
                --no-watch-fs \
                --no-daemon \
                --max-workers=4 \
                --stacktrace \
                --console=plain"

    readonly integration_test_code="./gradlew \
                '-Dspring.profiles.active=${test_profile}' \
                '-Djava.security.egd=file:/dev/./urandom' \
                '-DskipUaaAutoStart=true' \
                ${UAA_GRADLE_INT_TEST_COMMAND:-integrationTest} \
                --no-watch-fs \
                --no-daemon \
                --max-workers=4 \
                --stacktrace \
                --console=plain"

    set -x
    if [[ "${RUN_TESTS:-true}" = 'true' ]]; then
      eval "$assemble_code"

      # Start and ensure the boot server is running before integration tests
      eval "$launch_boot"
      echo $! > boot.pid
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
      eval "$integration_test_code"

      # Clean up: kill the boot server
      if [[ -f boot.pid ]]; then
        local pid; pid=$(cat boot.pid)
        echo "Sending SIGKILL (kill -9) to UAA process (pid=${pid})"
        kill -9 "${pid}" || true
        rm boot.pid
      fi
    else
      echo "$integration_test_code"
      bash
    fi
  popd
}

main "$@"