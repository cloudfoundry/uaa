#!/usr/bin/env bash
set -eu

#################################
# copy_ldif
# copies ldif files to /tmp/ldap for use by the LDAP server
# Must be in the UAA directory to run this function
#################################
function copy_ldif() {
  mkdir -p /tmp/ldap
  cp ./scripts/ldap/*.ldif /tmp/ldap
}

#################################
# start_ldap_debian
# Starts the slapd service on Debian-based systems
#################################
function start_ldap_debian() {
  # Debian Linux: slapd started via init.d
  echo "Starting slapd service"
  /etc/init.d/slapd start
  sleep 5
  /etc/init.d/slapd status
}

#################################
# start_ldap_oracle
# Starts the slapd service on Oracle Linux-based systems
#################################
function start_ldap_oracle() {
  echo "Starting slapd"
  # Oracle Linux: slapd started with a specific command and TLS enabled
  /usr/local/openldap/libexec/slapd -f /usr/local/openldap/etc/openldap/slapd.conf -h "ldap:/// ldaps:/// ldapi:///" -u ldap -g ldap
  sleep 5
  echo "SLAPD PID: $(cat /usr/local/openldap/var/run/slapd.pid)"
}

#################################
# update_ldif_paths_oracle
# Updates the LDIF schema file paths for Oracle Linux-based systems
#################################
function update_ldif_paths_oracle() {
  # Update the LDIF schema file to use the correct path
  sed -i 's#/var/lib/ldap#/usr/local/openldap/var/openldap-data#g' /tmp/ldap/ldap_slapd_schema.ldif
}

#################################
# start_ldap
# Starts the slapd service based on the detected system
#################################
function start_ldap() {
  copy_ldif
  if [ -f /etc/init.d/slapd ]; then
    start_ldap_debian
  elif [ -f /usr/local/openldap/libexec/slapd ]; then
    start_ldap_oracle
    update_ldif_paths_oracle
  else
    echo "LDAP setup could not be detected"
    exit 1
  fi
  initialize_ldap
}

##################################
# initialize_ldap
# Initializes the LDAP server with schema and data
##################################
function initialize_ldap() {
  echo "Initializing LDAP with schema and data"
  ldapadd \
          -Y EXTERNAL \
          -H 'ldapi:///' \
          -w password \
          -f /tmp/ldap/ldap_slapd_schema.ldif

  ldapadd \
          -x \
          -D 'cn=admin,dc=test,dc=com' \
          -w password \
          -f /tmp/ldap/ldap_slapd_data.ldif
}
