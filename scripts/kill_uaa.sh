#!/usr/bin/env bash

# Search for jps command in the following order:
# 1. jenv
# 2. JAVA_HOME
# 3. PATH
find_jps_command() {
  if command -v jenv >/dev/null; then
    echo "$(jenv which jps)"
  elif [ -n "${JAVA_HOME}" ]; then
    echo "$JAVA_HOME/bin/jps"
  elif command -v jps >/dev/null; then
    echo jps
  else
    echo "jps command not found"
    exit 1
  fi
}

function main() {
  local jps_command
  jps_command=$(find_jps_command)

  while $jps_command | grep Bootstrap; do
    $jps_command | grep Bootstrap | cut -f 1 -d' ' | xargs kill -HUP
    echo "Waiting for Bootstrap to finish"
    sleep 1
  done

  $jps_command | grep Bootstrap
  if [ $? -eq 0 ]; then
    echo "Bootstrap is still running"
    exit 1
  else
    echo "Bootstrap has finished"
    exit 0
  fi
}

main "$@"
