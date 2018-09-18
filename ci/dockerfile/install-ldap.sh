#!/bin/bash

set -e

cd `dirname $0`/../..

apt-get -qy purge slapd ldap-utils
set -x

apt-get -qy update
DEBIAN_FRONTEND=noninteractive apt-get -qy install slapd ldap-utils

# SSH Installation notes - from https://help.ubuntu.com/14.04/serverguide/openldap-server.html#openldap-tls
apt-get -qy install gnutls-bin ssl-cert
sh -c "certtool --generate-privkey > /etc/ssl/private/cakey.pem"
cat <<EOF >/etc/ssl/ca.info
cn = Pivotal Software Test
  ca
  cert_signing_key
EOF

certtool --generate-self-signed --load-privkey /etc/ssl/private/cakey.pem --template /etc/ssl/ca.info --outfile /etc/ssl/certs/cacert.pem
certtool --generate-privkey --bits 1024 --outfile /etc/ssl/private/ldap01_slapd_key.pem
cat <<EOF >  /etc/ssl/ldap01.info
organization = Pivotal Software Test
    cn = ldap01.example.com
    tls_www_server
    encryption_key
    signing_key
    expiration_days = 3650
EOF

certtool --generate-certificate --load-privkey /etc/ssl/private/ldap01_slapd_key.pem --load-ca-certificate /etc/ssl/certs/cacert.pem --load-ca-privkey /etc/ssl/private/cakey.pem --template /etc/ssl/ldap01.info --outfile /etc/ssl/certs/ldap01_slapd_cert.pem
adduser openldap ssl-cert
chgrp ssl-cert /etc/ssl/private/ldap01_slapd_key.pem
chmod g+r /etc/ssl/private/ldap01_slapd_key.pem
chmod o-r /etc/ssl/private/ldap01_slapd_key.pem

cat <<EOF > /etc/ssl/certinfo.ldif
dn: cn=config
changetype: modify
add: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/ssl/certs/cacert.pem
-
add: olcTLSCertificateFile
olcTLSCertificateFile: /etc/ssl/certs/ldap01_slapd_cert.pem
-
add: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/ssl/private/ldap01_slapd_key.pem
EOF

/etc/init.d/slapd start

echo "Adding LDAP Certs"
ldapmodify -Y EXTERNAL -H ldapi:/// -f /etc/ssl/certinfo.ldif
echo "LDAP Certs added"
sed -i "s/^SLAPD_SERVICES.*/SLAPD_SERVICES=\"ldap\:\/\/\/ ldapi\:\/\/\/ ldaps\:\/\/\/\"/g" /etc/default/slapd
