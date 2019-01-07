#!/usr/bin/env bash
set -xeu

function generate_keystore {
    # parameters are:
    # $1 - alias
    # $2 - validity
    # $3 - keystore file
    rm -f $3

    # server private key
    openssl genrsa -out "$3.key" 2048

    # CSR
    openssl req -new -sha256 -key "$3.key" -subj "/C=US/ST=CA/O=Pivotal/CN=localhost" -out "$TMPDIR/tmp-$1.csr"

    # Server public key, signed by CA
    openssl x509 -req -in "$TMPDIR/tmp-$1.csr" -CA $TMPDIR/myCA.pem -CAkey $TMPDIR/myCA.key -CAcreateserial -out "$3.crt" -days $2 -sha256

    # Create PKCS12 keystore from private key and public certificate.
    openssl pkcs12 -export -name $1 -in "$3.crt" -inkey "$3.key" -out $TMPDIR/keystore.p12 # password source

    # Convert PKCS12 keystore into a JKS keystore
    keytool -importkeystore -destkeystore $3 -srckeystore $TMPDIR/keystore.p12 -srcstoretype pkcs12 -alias $1 -srcstorepass password -deststorepass password
}

function setup_ldap_certs_for_tests {
    openssl genrsa -out $TMPDIR/myCA.key 2048
    openssl req -x509 -new -nodes -key $TMPDIR/myCA.key -sha256 -days 365000 -subj "/C=US/ST=CA/O=Pivotal Cert Auth" -out $TMPDIR/myCA.pem
    install_cert $TMPDIR/myCA.pem uaa-ldap-ca

    generate_keystore valid-self-signed-ldap-cert 365000 $OUTPUT_DIR/valid-self-signed-ldap-cert.jks
    generate_keystore expired-self-signed-ldap-cert 1 $OUTPUT_DIR/expired-self-signed-ldap-cert.jks
}

function install_cert {
    #define the certificate to import
    CERT_FILE=$1

    #define the alias
    CERT_ALIAS=$2

    #define the trust store
    TRUST_STORE_FILE=$OUTPUT_DIR/truststore-containing-the-ldap-ca.jks

    if test -r "$CERT_FILE" -a -f "$CERT_FILE"
    then
        echo "Installing $CERT_FILE with alias $CERT_ALIAS"
        keytool -importcert -file $CERT_FILE -keystore $TRUST_STORE_FILE -storepass changeit -noprompt -alias $CERT_ALIAS >/dev/null 2>&1
        if [ $? != 0 ]; then
          # implement import error logic
          echo "Failed to install certificate[1]."
        fi
    else
      echo "Unable to read certificate file: $CERT_FILE or write to trust file:$TRUST_STORE_FILE"
      exit 1
    fi
}

function install_ldap_certs() {
    TMPDIR=${TMPDIR:-/tmp}
    OUTPUT_DIR=/Users/pivotal/workspace/uaa/uaa/src/test/resources/certs
    setup_ldap_certs_for_tests
}

install_ldap_certs
