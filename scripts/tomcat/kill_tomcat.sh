#!/usr/bin/env bash
# Stops standalone Tomcat for integration tests: graceful shutdown when CATALINA_HOME is set,
# then kills any process still listening on UAA_PORT/PORT (default 8080). Used to recover
# from a failed prior run that left Tomcat bound to the port.
set -eu

function main() {
  local port="${UAA_PORT:-${PORT:-8080}}"
  local catalina_home="${CATALINA_HOME:-}"

  if [[ -n "${catalina_home}" && -x "${catalina_home}/bin/shutdown.sh" ]]; then
    echo "Attempting graceful Tomcat shutdown via ${catalina_home}/bin/shutdown.sh"
    "${catalina_home}/bin/shutdown.sh" 15 2>/dev/null || true
    sleep 2
  fi

  if command -v lsof >/dev/null 2>&1; then
    echo "Killing any process still listening on port ${port}"
    lsof -ti ":${port}" | xargs kill -9 2>/dev/null || true
  fi
}

main "$@"
