#!/bin/bash

# Used by ../docker-compose.yml
set -e
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

LDAP_TLS_CHK=/tmp/ldap-tls-run-once
LDAP_SCHEMA_CHK=/tmp/ldap-schema-run-once

function restart_ldap() {
  ### service slapd restart|stop doesn't kill the slapd daemon
  pid=$(pgrep slapd || echo "0")
  if [[ "$pid" -gt "0" ]]; then
    echo "Sending QUIT signal to slapd"
    kill -3 $pid
    sleep 1
    pid=$(pgrep slapd || echo "0")
    if [[ "$pid" == "0" ]]; then
      echo "slapd stop [OK]"
    else
      echo "slapd stop [ERROR]"
      kill -9 $pid
    fi
  fi
  service slapd start
}

function generate_certs_if_needed() {
  if
    [ ! -f /uaa/certificates/server.crt ] ||
    [ ! -f /uaa/certificates/server.key ] ||
    [ ! -f /uaa/certificates/CA.crt ] ||
    [ ! -f /uaa/certificates/CA.key ]; then
    /uaa/certificates/generate.sh
  fi
}

function configure_slapd_tls() {
  cp /uaa/certificates/CA.key /etc/ldap/sasl2/
  cp /uaa/certificates/CA.crt /etc/ldap/sasl2/
  cp /uaa/certificates/server.crt /etc/ldap/sasl2/
  cp /uaa/certificates/server.key /etc/ldap/sasl2/
  cp /etc/ssl/certs/ca-certificates.crt /etc/ldap/sasl2/
  cat /etc/ldap/sasl2/CA.crt >> /etc/ldap/sasl2/ca-certificates.crt
  chown -R openldap:openldap /etc/ldap/sasl2

  echo "dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/ldap/sasl2/ca-certificates.crt
-
add: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ldap/sasl2/server.crt
-
add: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ldap/sasl2/server.key" > /etc/ldap/sasl2/uaa-certinfo.ldif
  ## TODO start LDAP server here
  restart_ldap
  echo "Adding LDAP Certs"
  ldapmodify -Y EXTERNAL -H ldapi:/// -f /etc/ldap/sasl2/uaa-certinfo.ldif
  echo "LDAP Certs added"
  sed -i "s/^SLAPD_SERVICES.*/SLAPD_SERVICES=\"ldap\:\/\/\/ ldapi\:\/\/\/ ldaps\:\/\/\/\"/g" /etc/default/slapd
  sed -i "s/^TLS/\#TLS/g" /etc/ldap/ldap.conf
  echo "TLS_CACERT /etc/ldap/sasl2/ca-certificates.crt
TLS_REQCERT allow
" >> /etc/ldap/ldap.conf
  restart_ldap
}

if [ ! -f ${LDAP_SCHEMA_CHK} ]; then
  generate_certs_if_needed
  configure_slapd_tls
  touch ${LDAP_TLS_CHK}
fi

echo "LDAP server Status:"
service slapd status || true

if [ ! -f ${LDAP_SCHEMA_CHK} ]; then
  echo "Starting LDAP server."
  restart_ldap
  echo "Creating LDAP schema."
  ldapadd -Y EXTERNAL -H ldapi:/// -f $SCRIPT_DIR/ldap_slapd_schema.ldif
  echo "Populating LDAP database entries."
  ldapadd -x -D 'cn=admin,dc=test,dc=com' -w password -f $SCRIPT_DIR/ldap_slapd_data.ldif
  touch ${LDAP_SCHEMA_CHK}
else
  echo "Starting LDAP server with existing data."
  restart_ldap
fi

doExit() {
  echo "Caught SIGTERM signal."
  exit 0
}

trap doExit SIGINT SIGQUIT SIGTERM

echo "LDAP server is READY"

# Do not exit the container in docker compose
while true; do
    sleep 1
done
