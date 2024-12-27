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
  local pid
  local jps_command
  local kill_count=5
  local port=${PORT:-8080}
  jps_command=$(find_jps_command)

  pid=$($jps_command -vlm | grep Bootstrap | grep uaa | grep "${port}" | cut -f 1 -d' ')
  if [ -z "$pid" ]; then
    echo "No UAA process found on port: ${port}"
    exit 0
  fi

  echo Currently running UAA processes:
  $jps_command -vlm | egrep "^${pid} "
  echo
  echo -n "Attempting to kill UAA process with PID=$pid: "

  while [ "$kill_count" -ge "0" ]; do
    if ! $jps_command | egrep "^${pid} " >/dev/null; then
      break
    fi
    echo -n .
    kill -HUP "${pid}" || true
    sleep 1
    kill_count=$((kill_count - 1))
  done

  if $jps_command | egrep "^${pid} " >/dev/null; then
    echo -n " Forcibly killing: "
    kill -9 "${pid}" || true
    sleep 2
  fi

  $jps_command | egrep "^${pid} "
  if [ $? -eq 0 ]; then
    echo " Bootstrap is still running"
    exit 1
  else
    echo " Bootstrap has finished"
    exit 0
  fi
}

main "$@"
