#!/usr/bin/env bash
set -eu

#######################################
# Integration tests against standalone Apache Tomcat (same line as Spring Boot's tomcat-embed).
# Same container setup as integration_tests.sh (DB, LDAP, /etc/hosts).
#
# Env:
#   UAA_GRADLE_INT_TEST_COMMAND — Gradle task for ITs (default: integrationTest)
#   gradle_heap / gradle_test_heap — JVM heaps for Gradle
#   UAA_INTEGRATION_SERVER — this script sets it to external for Gradle
#   UAA_PORT — HTTP port (default 8080; Tomcat server.xml must match if changed)
#   UAA_VERBOSE_TESTS — default on (per-test lines in Gradle); set to 0/false/off to disable
#######################################

function download_and_extract_tomcat() {
  local version="$1"
  local build_dir="$2"
  local major="${version%%.*}"
  local tarball="apache-tomcat-${version}.tar.gz"
  local url="https://dlcdn.apache.org/tomcat/tomcat-${major}/v${version}/bin/${tarball}"
  local cache="${build_dir}/${tarball}"

  mkdir -p "${build_dir}"
  if [[ ! -f "${cache}" ]]; then
    echo "Downloading ${url}"
    curl -fsSL "${url}" -o "${cache}"
  fi
  echo "Extracting Tomcat ${version} to ${build_dir}"
  tar -xzf "${cache}" -C "${build_dir}"
}

function wait_for_uaa_http() {
  local url="$1"
  local max_wait="${2:-300}"
  local i=0
  while [[ "${i}" -lt "${max_wait}" ]]; do
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" "${url}" 2>/dev/null || echo "000")
    if [[ "${code}" =~ ^(200|302|301|303)$ ]]; then
      echo "UAA responded HTTP ${code} at ${url}"
      return 0
    fi
    sleep 1
    i=$((i + 1))
  done
  echo "Timeout waiting for ${url}"
  return 1
}

function stop_tomcat_for_script() {
  local script_dir="$1"
  local repo_root="$2"
  local tomcat_root="$3"
  if [[ -f "${repo_root}/build/catalina.integration.pid" ]]; then
    kill "$(cat "${repo_root}/build/catalina.integration.pid")" 2>/dev/null || true
    rm -f "${repo_root}/build/catalina.integration.pid"
  fi
  export CATALINA_HOME="${tomcat_root}"
  CATALINA_HOME="${tomcat_root}" "${script_dir}/kill_tomcat.sh" || true
}

function main() {
  local script_dir
  script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  # shellcheck source=scripts/lib_db_helper.sh
  source "${script_dir}/../lib_db_helper.sh"
  # shellcheck source=scripts/lib_ldap_helper.sh
  source "${script_dir}/../lib_ldap_helper.sh"
  # shellcheck source=scripts/lib_util_helper.sh
  source "${script_dir}/../lib_util_helper.sh"
  display_memory

  local test_profile="${1:-hsqldb}"
  export UAA_INTEGRATION_SERVER=external
  local uaa_port="${UAA_PORT:-8080}"

  setup_hosts_file
  boot_db "${DB:-hsqldb}"

  local repo_root
  repo_root="$(dirname "$(dirname "${script_dir}")")"
  pushd "${repo_root}" >/dev/null

  # Free UAA_PORT before any long Gradle work: a failed prior run may have left Tomcat (or
  # another process) bound; otherwise wait_for_uaa_http could succeed against a stale instance.
  rm -f "${repo_root}/build/catalina.integration.pid"
  (
    export UAA_PORT="${uaa_port}"
    unset CATALINA_HOME
    "${script_dir}/kill_tomcat.sh"
  ) || true

  local tomcat_root=""
  trap '[[ -n "${tomcat_root}" ]] && stop_tomcat_for_script "${script_dir}" "${repo_root}" "${tomcat_root}"' EXIT

  start_ldap

  echo "Setting Gradle daemon heap to ${gradle_heap:=1024m}"
  echo "Setting test worker heap to ${gradle_test_heap:=640m}"

  if [[ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]]; then
    export DBUS_SESSION_BUS_ADDRESS=/dev/null
  fi

  if [[ "${RUN_TESTS:-true}" != 'true' ]]; then
    echo "RUN_TESTS=false; dropping to shell"
    trap - EXIT
    bash
    popd >/dev/null
    return 0
  fi

  set -x
  ./gradlew writeTomcatDistributionVersion \
    -Dorg.gradle.jvmargs="-Dfile.encoding=utf8 -Xms64m -Xmx${gradle_heap} -XX:MaxMetaspaceSize=384m -XX:+UseG1GC -XX:MaxGCPauseMillis=100" \
    --no-watch-fs \
    --no-daemon \
    --no-configuration-cache \
    --max-workers=2 \
    --stacktrace \
    --console=plain

  local tomcat_version
  tomcat_version="$(cat build/tomcat-distribution.version)"
  echo "Tomcat distribution version (from BOM): ${tomcat_version}"

  tomcat_root="$(pwd)/build/apache-tomcat-${tomcat_version}"
  if [[ ! -x "${tomcat_root}/bin/catalina.sh" ]]; then
    rm -rf "${tomcat_root}"
    download_and_extract_tomcat "${tomcat_version}" "$(pwd)/build"
  fi

  ./gradlew -Dspring.profiles.active="${test_profile}" \
    -Djava.security.egd=file:/dev/./urandom \
    -Dorg.gradle.jvmargs="-Dfile.encoding=utf8 -Xms64m -Xmx${gradle_heap} -XX:MaxMetaspaceSize=384m -XX:+UseG1GC -XX:MaxGCPauseMillis=100" \
    assemble compileTestJava :cloudfoundry-identity-uaa:bootWar \
    --no-watch-fs \
    --no-daemon \
    --no-configuration-cache \
    --max-workers=2 \
    --stacktrace \
    --console=plain

  local boot_dir
  boot_dir="$(pwd)/scripts/boot"
  local log4j="${boot_dir}/log4j2.properties"
  local war_file
  war_file="$(pwd)/uaa/build/libs/cloudfoundry-identity-uaa-0.0.0.war"

  export CATALINA_HOME="${tomcat_root}"
  export CATALINA_BASE="${tomcat_root}"
  export UAA_PORT="${uaa_port}"

  # Do not use `set -u` in setenv.sh: Tomcat sources it, then setclasspath.sh tests unset
  # JRE_HOME with `[ -z "$JRE_HOME" ]`, which fails under nounset before Tomcat starts.
  # Match UaaBootApplication.main() and integration java -jar (uaa/build.gradle) for Spring context.
  cat > "${tomcat_root}/bin/setenv.sh" <<EOF
#!/usr/bin/env sh
export JAVA_OPTS="\${JAVA_OPTS:-}"
export CATALINA_OPTS="\${CATALINA_OPTS:-} -DCLOUDFOUNDRY_CONFIG_PATH=${boot_dir} -DSECRETS_DIR=${boot_dir} -Dserver.servlet.context-path=/uaa -Dsmtp.host=localhost -Dsmtp.port=2525 -Dspring.profiles.active=${test_profile} -Djava.security.egd=file:/dev/./urandom -Dlogging.config=${log4j} -Dstatsd.enabled=true -Dzones.paths.enabled=true -Dspring.main.allow-bean-definition-overriding=true -Dspring.main.allow-circular-references=true"
EOF
  chmod +x "${tomcat_root}/bin/setenv.sh"

  # Force absolute URLs in redirect Location headers. Otherwise Tomcat may emit path-only
  # Location values (useRelativeRedirects), and Apache HttpClient 5 fails with
  # "Target host is not specified" (e.g. FormLoginIntegrationTests after login).
  mkdir -p "${tomcat_root}/conf/Catalina/localhost"
  cat > "${tomcat_root}/conf/Catalina/localhost/uaa.xml" <<'CTX'
<?xml version="1.0" encoding="UTF-8"?>
<Context useRelativeRedirects="false" failCtxIfServletStartFails="true" />
CTX

  rm -rf "${tomcat_root}/webapps/uaa" "${tomcat_root}/webapps/uaa.war" 2>/dev/null || true
  cp -f "${war_file}" "${tomcat_root}/webapps/uaa.war"

  "${script_dir}/kill_tomcat.sh" || true

  local catalina_log
  catalina_log="$(pwd)/build/catalina.integration.log"
  rm -f "${catalina_log}"
  echo "Starting Tomcat at CATALINA_HOME=${CATALINA_HOME}"
  nohup "${tomcat_root}/bin/catalina.sh" run > "${catalina_log}" 2>&1 &
  echo $! > "$(pwd)/build/catalina.integration.pid"

  if ! wait_for_uaa_http "http://127.0.0.1:${uaa_port}/uaa/login" 300; then
    echo "--- last catalina log ---"
    tail -200 "${catalina_log}" || true
    exit 1
  fi

  ./gradlew \
    -Dspring.profiles.active="${test_profile}" \
    -Djava.security.egd=file:/dev/./urandom \
    -Dorg.gradle.jvmargs="-Dfile.encoding=utf8 -Xms64m -Xmx${gradle_test_heap} -XX:MaxMetaspaceSize=128m -XX:+UseG1GC -XX:MaxGCPauseMillis=100 -XX:ParallelGCThreads=2 -XX:CICompilerCount=2 -Djdk.lang.processReaperUseDefaultStackSize=true" \
    -Dorg.gradle.daemon.idletimeout=300000 \
    -Dorg.gradle.parallel=false \
    -Dorg.gradle.workers.max=2 \
    -PuaaIntegrationServer=external \
    ${UAA_GRADLE_INT_TEST_COMMAND:-integrationTest} \
    --no-watch-fs \
    --no-daemon \
    --no-configuration-cache \
    --max-workers=2 \
    --stacktrace \
    --console=plain

  local test_exit=$?
  { set +x; } 2>/dev/null

  stop_tomcat_for_script "${script_dir}" "${repo_root}" "${tomcat_root}"
  trap - EXIT

  popd >/dev/null
  exit "${test_exit}"
}

main "$@"
