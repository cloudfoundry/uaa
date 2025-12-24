#!/usr/bin/env bash
set -eu -o pipefail
export ORG_GRADLE_PROJECT_port=${PORT:-8080}
echo "PORT: ${ORG_GRADLE_PROJECT_port}"

if [ "${1:-}" == "-h" ]; then
  echo "USAGE: $0 [-h] [-s] [-r] [-PdebugPort=<port>] [args]"
  echo "Run UAA in debug mode"
  echo "  -h: help"
  echo "  -s: suspend startup for debugging"
  echo "  -r: run UAA without debug mode"
  echo "  -PdebugPort=<port>: set debug port, default 5005"
  exit 0
fi

debug_flag="-Pdebug"
if [ "${1:-}" == "-s" ]; then
  debug_flag="-Pdebugs"
  shift
elif [ "${1:-}" == "-r" ]; then
  debug_flag=""
  shift
fi

cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd
./gradlew run ${debug_flag} "${@}"
