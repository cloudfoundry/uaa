#!/bin/bash

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
ROOT_DIR="$( cd "${SCRIPT_DIR}"/../../ && pwd )"

echo "SCRIPT_DIR = ${SCRIPT_DIR}"
echo "ROOT_DIR = ${ROOT_DIR}"
WAR_FILE=${ROOT_DIR}/uaa/build/libs/cloudfoundry-identity-uaa-0.0.0.war
CERT_FILE=${ROOT_DIR}/scripts/certificates/uaa_keystore.p12

# make sure boot war is available
if [[ ! -f ${WAR_FILE} ]]; then
  echo -e "${RED}ERROR${NC} WAR file not found."
  echo -e "${RED}ERROR${NC} ${WAR_FILE}"
  echo -e "${RED}ERROR${NC} Please run:"
  echo -e "${RED} (cd ${ROOT_DIR} && ./gradlew assemble)${NC}"
  exit 1
fi

# make sure that certificates are available
if [[ ! -f ${CERT_FILE} ]]; then
  echo -e "${RED}ERROR${NC} Certificate file not found."
  echo -e "${RED}ERROR${NC} ${CERT_FILE}"
  echo -e "${RED}ERROR${NC} Please run:"
  echo -e "${RED} ${ROOT_DIR}/scripts/certificates/generate.sh${NC}"
  exit 1
fi

pushd ${SCRIPT_DIR}
  java \
      -Dlogging.level.org.springframework.security=TRACE \
      -Duaa.location.tomcat=${ROOT_DIR}/scripts/boot/tomcat \
      -Duaa.location.certificate=${ROOT_DIR}/scripts/certificates \
      -Dlogging.config=${ROOT_DIR}/scripts/boot/log4j2.properties \
      -DCLOUDFOUNDRY_CONFIG_PATH=${ROOT_DIR}/scripts/cargo \
      -DSECRETS_DIR=${ROOT_DIR}/scripts/cargo \
      -Djava.security.egd=file:/dev/./urandom \
      -Dmetrics.perRequestMetrics=true \
      -Dserver.servlet.context-path=/uaa \
      -Dsmtp.host=localhost \
      -Dsmtp.port=2525 \
      -Dspring.profiles.active=hsqldb \
      -Dstatsd.enabled=true \
      -Dfile.encoding=UTF-8 \
      -Duser.country=US \
      -Duser.language=en \
      -Duser.variant -jar ${WAR_FILE}
popd