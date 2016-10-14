#!/bin/bash

function generate_keystore {
    # parameters are:
    # $1 - alias
    # $2 - validity
    # $3 - keystore file
    rm -f $3
    echo "Generating keystore file for server."
    keytool -genkey -noprompt \
        -alias $1 \
        -dname "CN=Pivotal Test Server, OU=UAA, O=Pivotal Software Inc, L=Pivot, S=The, C=US" \
        -keystore $3 \
        -validity $2 \
        -startdate -2d \
        -storepass password \
        -keypass password

    echo "Exporting certificate for client"
    keytool -export \
        -storepass password \
        -keypass password \
        -keystore $3 \
        -alias $1 \
        -file "$3.crt"
}

function setup_ldap_certs_for_tests {
    generate_keystore valid-self-signed-ldap-cert 3650 $DIR/valid-self-signed-ldap-cert.jks
    generate_keystore expired-self-signed-ldap-cert 1 $DIR/expired-self-signed-ldap-cert.jks
}


function install_cert {
    #define the certificate to import
    CERT_FILE=$1

    #define the alias
    CERT_ALIAS=$2

    #define the trust store
    TRUST_STORE_FILE=$JAVA_HOME/jre/lib/security/cacerts

    #check if the cert file exists, readable and that the trust store exists and is writeable
    if test -r "$CERT_FILE" -a -f "$CERT_FILE" -a -f $TRUST_STORE_FILE -a -w $TRUST_STORE_FILE
    then
      #check to see if the alias exists
      $JAVA_HOME/bin/keytool -list -file $CERT_FILE -keystore $TRUST_STORE_FILE -storepass changeit -noprompt -alias $CERT_ALIAS >/dev/null 2>&1
      if [ $? != 0 ]; then
        echo "Installing $CERT_FILE with alias $CERT_ALIAS"
        $JAVA_HOME/bin/keytool -importcert -file $CERT_FILE -keystore $TRUST_STORE_FILE -storepass changeit -noprompt -alias $CERT_ALIAS >/dev/null 2>&1
        if [ $? != 0 ]; then
          # implement import error logic
          echo "Failed to install certificate[1]."
        fi
      else
        echo "Certificate already installed. Replacing it"
        $JAVA_HOME/bin/keytool -delete -file $CERT_FILE -keystore $TRUST_STORE_FILE -storepass changeit -noprompt -alias $CERT_ALIAS >/dev/null 2>&1
        if [ $? != 0 ]; then
          # implement import error logic
          echo "Failed to delete existing alias, will attempt to reinstall it"
        fi
        $JAVA_HOME/bin/keytool -importcert -file $CERT_FILE -keystore $TRUST_STORE_FILE -storepass changeit -noprompt -alias $CERT_ALIAS >/dev/null 2>&1
        if [ $? != 0 ]; then
          # implement import error logic
          echo "Failed to install certificate[2]."
        fi
      fi
    else
      echo "Unable to read certificate file: $CERT_FILE or write to trust file:$TRUST_STORE_FILE"
      exit 1
    fi
    ## END CERTIFICATE INSTALLATION
}

#DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DIR=/tmp
setup_ldap_certs_for_tests
install_cert $DIR/expired-self-signed-ldap-cert.jks.crt expired-self-signed-ldap-cert
install_cert $DIR/valid-self-signed-ldap-cert.jks.crt valid-self-signed-ldap-cert
