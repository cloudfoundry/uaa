#!/bin/bash

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

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

install_cert $DIR/expired-self-signed-ldap-cert.crt expired-self-signed-ldap-cert
install_cert $DIR/valid-self-signed-ldap-cert.crt valid-self-signed-ldap-cert
