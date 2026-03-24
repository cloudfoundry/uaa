#!/usr/bin/env bash
set -eu

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

