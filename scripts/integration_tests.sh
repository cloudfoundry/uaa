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
    readonly launch_boot="nohup java -DCLOUDFOUNDRY_CONFIG_PATH=${wd}/scripts/boot \
                               -DSECRETS_DIR=${wd}/scripts/boot \
                               -Djava.security.egd=file:/dev/./urandom \
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
                               -Duser.variant -jar ${wd}/uaa/build/libs/cloudfoundry-identity-uaa-0.0.0.war > boot.log 2>&1 &"

    readonly assemble_code="./gradlew '-Dspring.profiles.active=${test_profile}' \
                '-Djava.security.egd=file:/dev/./urandom' \
                assemble \
                --max-workers=4 \
                --stacktrace \
                --console=plain"

    readonly integration_test_code="./gradlew '-Dspring.profiles.active=${test_profile}' \
                '-Djava.security.egd=file:/dev/./urandom' \
                '-DskipUaaAutoStart=true' \
                ${UAA_GRADLE_INT_TEST_COMMAND:-integrationTest} \
                --stacktrace \
                --console=plain"

    set -x
    # The default max heap size for Gradle is 512MB, increase to avoid DaemonDisappearedException
    export GRADLE_OPTS="-Xmx2048m"
    if [[ "${RUN_TESTS:-true}" = 'true' ]]; then
      eval "$assemble_code"

      # Always start the boot server before running integration tests
      eval "$launch_boot"
      echo $! > boot.pid
      if is_boot_running ; then
        echo "Boot started. Can continue to run tests."
      else
        echo "Boot did not start - failing"
        cat boot.log
        exit 1
      fi
      
      eval "$integration_test_code"
      
      # Clean up: kill the boot server
      if [[ -f boot.pid ]]; then
        kill -9 "$(cat boot.pid)" || true
        rm boot.pid
      fi
    else
      echo "$integration_test_code"
      bash
    fi
  popd
}

main "$@"