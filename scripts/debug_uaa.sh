#!/usr/bin/env bash
set -eu -o pipefail
export ORG_GRADLE_PROJECT_port=${PORT:-8080}
echo "PORT: ${ORG_GRADLE_PROJECT_port}"

if [ "${1:-}" == "-h" ]; then
  echo USAGE: $0 [-h] [-s] [args]
  echo "Run UAA in debug mode"
  echo "  -h: help"
  echo "  -s: suspend startup for debugging"
  echo "  -r: run UAA without debug mode"
  exit 0
fi

DEBUG_FLAG="-Dxdebug=true"
if [ "${1:-}" == "-s" ]; then
  DEBUG_FLAG="-Dxdebugs=true"
  shift
elif [ "${1:-}" == "-r" ]; then
  DEBUG_FLAG=""
  shift
fi

cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd
## scripts/kill_uaa.sh && \
./gradlew run ${DEBUG_FLAG} "${@}"
