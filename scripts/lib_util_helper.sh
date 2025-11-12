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

  echo
  echo "Waiting for the UAA server to start, only partial log messages will be shown as it progresses:"
  while true; do
    # Use curl to check if the port is responding
    # Any HTTP response (even 4xx/5xx) indicates the server is running
    if curl -ks --max-time 5 -o /dev/null --connect-timeout 2 -u "admin:adminsecret" \
            --data "client_id=admin&grant_type=client_credentials" \
            -X POST "http://localhost:${port}/uaa/oauth/token" 2>/dev/null; then
      echo
      echo "Boot is running on port ${port}."
      grep "Started UaaBootApplication" boot.log
      return 0
    fi

    local current_time elapsed_time
    current_time=$(date +%s)
    elapsed_time=$((current_time - start_time))

    if [[ "$elapsed_time" -ge "$timeout" ]]; then
      echo
      echo "Timeout reached. Boot did not start on port ${port}"
      curl -ksS --max-time 5 --connect-timeout 2 -u "admin:adminsecret" \
              --data "client_id=admin&grant_type=client_credentials" \
              -X POST "http://localhost:${port}/uaa/info" || true

      thread_dump_on_boot_pid
      return 1
    fi

    tail -n 1 boot.log
    sleep 1 # Check every second
  done
}

########################################
# thread_dump_on_boot_pid
# Display Memeory info and Request a thread dump on the pid in boot.pid
##########################################
function thread_dump_on_boot_pid() {
  local pid
  pid=$(cat boot.pid)
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    echo "Collecting JVM diagnostics..."
    jstat -gccause "${pid}" 2>/dev/null || true
    jstat -gccapacity "${pid}" 2>/dev/null || true
    jstat -gcmetacapacity "${pid}" 2>/dev/null || true
    echo "Sending SIGQUIT (kill -3) to Thread Dump on UAA process (pid=${pid})"
    kill -3 "$pid" || true
    # Wait a moment for the thread dump to be written
    sleep 2
  fi
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

