#!/usr/bin/env bash
set -eu

########################################
# Check if Boot has started by looking for a specific line in the log file
##########################################
function is_boot_running() {
  local log_file="boot.log"
  local target_line="Started UaaBootApplication"
  local timeout=300 # Timeout in seconds

  local start_time
  start_time=$(date +%s)

  while true; do
    if grep "$target_line" "$log_file"; then
      echo "Boot Start was found in the log file."
      return 0
    fi

    local current_time elapsed_time
    current_time=$(date +%s)
    elapsed_time=$((current_time - start_time))

    if [[ "$elapsed_time" -ge "$timeout" ]]; then
      echo "Timeout reached. Boot did not start"
      return 1
    fi

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

