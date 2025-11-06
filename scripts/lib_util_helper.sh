#!/usr/bin/env bash
set -eu

########################################
# Check if Boot has started by checking if the port is responding
##########################################
function is_boot_running() {
  local port=${PORT:-8080}
  local timeout=600 # Timeout in seconds

  local start_time
  start_time=$(date +%s)

  while true; do
    # Use curl to check if the port is responding
    # Any HTTP response (even 4xx/5xx) indicates the server is running
    if curl -ksS --max-time 5 --connect-timeout 2 "http://127.0.0.1:${port}/uaa/info"; then
      echo "Boot is running on port ${port}."
      return 0
    fi

    local current_time elapsed_time
    current_time=$(date +%s)
    elapsed_time=$((current_time - start_time))

    if [[ "$elapsed_time" -ge "$timeout" ]]; then
      echo "Timeout reached. Boot did not start on port ${port}"
      local pid; pid=$(cat boot.pid)
      if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
        echo "Sending SIGQUIT (kill -3) to UAA process (pid=$pid)"
        kill -3 "$pid" || true
      fi
      return 1
    fi

    tail -n 1 boot.log
    sleep 1 # Check every second
  done
}

########################################
# setup_hosts_file
# Appends test-zone and other necessary host entries to /etc/hosts
##########################################
function setup_hosts_file() {

  if [[ -w "/etc/hosts" ]]; then
    cat <<EOF >>/etc/hosts || true
127.0.0.1 testzone1.localhost
127.0.0.1 testzone2.localhost
127.0.0.1 testzone3.localhost
127.0.0.1 testzone4.localhost
127.0.0.1 testzonedoesnotexist.localhost
127.0.0.1 oidcloginit.localhost
127.0.0.1 testzoneinactive.localhost
127.0.0.1 ldap01.example.com
EOF
  fi
}

########################################
# Display memory of container
##########################################
function display_memory() {
  if [[ -f "/proc/meminfo" ]]; then
    grep MemTotal /proc/meminfo || true
  fi
}

