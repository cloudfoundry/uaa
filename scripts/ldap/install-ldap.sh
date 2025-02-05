#!/bin/bash

## TODO - remove this script. The ../docker-compose.yml has a container with the same setup

set -e

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

cd `dirname $0`/../..

sudo apt-get -qy purge slapd ldap-utils
set -x

sudo apt-get -qy update
sudo DEBIAN_FRONTEND=noninteractive apt-get -qy install slapd ldap-utils

# SSH Installation notes - from https://help.ubuntu.com/14.04/serverguide/openldap-server.html#openldap-tls
if test "$1" == "ssl"
then
    sudo apt-get -qy install gnutls-bin ssl-cert
    sudo sh -c "certtool --generate-privkey > /etc/ssl/private/cakey.pem"
    sudo sh -c 'echo "cn = Pivotal Software Test
    ca
    cert_signing_key" >  /etc/ssl/ca.info'
    sudo certtool --generate-self-signed --load-privkey /etc/ssl/private/cakey.pem --template /etc/ssl/ca.info --outfile /etc/ssl/certs/cacert.pem
    sudo certtool --generate-privkey --bits 1024 --outfile /etc/ssl/private/ldap01_slapd_key.pem
    sudo sh -c 'echo "organization = Pivotal Software Test
    cn = ldap01.example.com
    tls_www_server
    encryption_key
    signing_key
    expiration_days = 3650" >  /etc/ssl/ldap01.info'
    sudo certtool --generate-certificate --load-privkey /etc/ssl/private/ldap01_slapd_key.pem --load-ca-certificate /etc/ssl/certs/cacert.pem --load-ca-privkey /etc/ssl/private/cakey.pem --template /etc/ssl/ldap01.info --outfile /etc/ssl/certs/ldap01_slapd_cert.pem
    sudo adduser openldap ssl-cert
    sudo chgrp ssl-cert /etc/ssl/private/ldap01_slapd_key.pem
    sudo chmod g+r /etc/ssl/private/ldap01_slapd_key.pem
    sudo chmod o-r /etc/ssl/private/ldap01_slapd_key.pem
    sudo sh -c 'echo "dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/ssl/certs/cacert.pem
-
add: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ssl/certs/ldap01_slapd_cert.pem
-
add: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ssl/private/ldap01_slapd_key.pem" > /etc/ssl/certinfo.ldif'
    echo "Adding LDAP Certs"
    sudo ldapmodify -Y EXTERNAL -H ldapi:/// -f /etc/ssl/certinfo.ldif
    echo "LDAP Certs added"
    sudo sed -i "s/^SLAPD_SERVICES.*/SLAPD_SERVICES=\"ldap\:\/\/\/ ldapi\:\/\/\/ ldaps\:\/\/\/\"/g" /etc/default/slapd
    sudo /etc/init.d/slapd restart

fi

sudo ldapadd -Y EXTERNAL -H ldapi:/// -f ${SCRIPT_DIR}/ldap_slapd_schema.ldif
sudo ldapadd -x -D 'cn=admin,dc=test,dc=com' -w password -f ${SCRIPT_DIR}/ldap_slapd_data.ldif