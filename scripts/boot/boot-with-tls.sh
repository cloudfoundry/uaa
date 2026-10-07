#!/bin/bash

set -e

GREEN='\033[0;32m'
NC='\033[0m' # No Color

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( cd "${SCRIPT_DIR}"/../../ && pwd )"

echo "SCRIPT_DIR = ${SCRIPT_DIR}"
echo "ROOT_DIR = ${ROOT_DIR}"
WAR_FILE=${ROOT_DIR}/uaa/build/libs/cloudfoundry-identity-uaa-0.0.0.war
CERT_FILE=${ROOT_DIR}/scripts/certificates/uaa_keystore.p12

# build the boot war if it isn't there yet
if [[ ! -f ${WAR_FILE} ]]; then
  echo -e "${GREEN}WAR file not found. Building it now:${NC} ${WAR_FILE}"
  (cd "${ROOT_DIR}" && ./gradlew :cloudfoundry-identity-uaa:assemble)
fi

# generate the TLS certificates and keystore if they aren't there yet
if [[ ! -f ${CERT_FILE} ]]; then
  echo -e "${GREEN}Certificate file not found. Generating it now:${NC} ${CERT_FILE}"
  "${ROOT_DIR}/scripts/certificates/generate.sh"
fi

pushd ${SCRIPT_DIR}
  # exec, not a plain invocation: replaces this script's process with java's, so a caller that
  # backgrounds this script (./boot-with-tls.sh &) gets the actual server's PID via $! -- instead
  # of this wrapper's PID, whose only child is the server.
  exec java \
      -Dlogging.level.org.springframework.security=TRACE \
      -Duaa.boot.location.tomcat=${ROOT_DIR}/scripts/boot/tomcat \
      -Duaa.boot.location.certificate=${ROOT_DIR}/scripts/certificates \
      -Dlogging.config=${ROOT_DIR}/scripts/boot/log4j2.properties \
      -DCLOUDFOUNDRY_CONFIG_PATH=${ROOT_DIR}/scripts/boot \
      -DSECRETS_DIR=${ROOT_DIR}/scripts/boot \
      -Dserver.http.port=8080 \
      -Dserver.http.address=0.0.0.0 \
      -Dserver.port=8443 \
      -Dserver.ssl.enabled=true \
      -Dserver.ssl.key-store=${ROOT_DIR}/scripts/certificates/uaa_keystore.p12 \
      -Dserver.ssl.key-store-type=PKCS12 \
      -Dserver.ssl.key-alias=uaa_ssl_cert \
      -Dserver.ssl.key-store-password=k0*l*s3cur1tyr0ck$ \
      -Djava.security.egd=file:/dev/./urandom \
      -Dmetrics.perRequestMetrics=true \
      -Dserver.servlet.context-path=/uaa \
      -Dsmtp.host=localhost \
      -Dsmtp.port=2525 \
      -Dspring.profiles.active=hsqldb \
      -Dstatsd.enabled=true \
      -Duaa.mtls-enabled=true \
      -Dfile.encoding=UTF-8 \
      -Duser.country=US \
      -Duser.language=en \
      -Duser.variant -jar ${WAR_FILE}
# No popd: exec above replaces this process on success, so this line only runs if exec itself
# failed to find/launch java -- the directory stack doesn't matter to a process that's exiting.