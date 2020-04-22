rm foo.truststore

import_cert() {
  "${JAVA_HOME}"/bin/keytool \
    -noprompt \
    -import \
    -file "${1}" \
    -trustcacerts \
    -alias "${2}" \
    -keystore uaa.pkcs12.truststore \
    -storepass changeit
}

import_cert simple.pem simple
#cat cf-router-ssl-for-acceptance.pem | $JAVA_HOME/bin/keytool \
#  -noprompt \
#  -import \
#  -trustcacerts \
#  -alias cf-router-ssl-for-acceptance \
#  -keystore foo.truststore \
#  -storepass changeit


