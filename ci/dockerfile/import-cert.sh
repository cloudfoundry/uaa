#!/bin/sh
#
# usage:  import-cert.sh remote.host.name [port]
#
REMHOST=$1
REMPORT=${2:-443}

echo | openssl s_client -connect ${REMHOST}:${REMPORT} 2>&1 |sed -ne '/-BEGIN CERTIFICATE-/,/-END CERTIFICATE-/p' > /tmp/$REMHOST.crt
certutil -d sql:$HOME/.pki/nssdb -A -t "P,," -n "$REMHOST" -i /tmp/$REMHOST.crt