#!/usr/bin/env bash
set -xeu
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source $DIR/start_db_helper.sh
source $DIR/start_ldap_helper.sh

TESTENV="$1"

pushd $(dirname $DIR)
  bootDB "${DB}"
  install_ldap_certs
  /etc/init.d/slapd start
  ./scripts/ldap/configure-manifest.sh
  ./gradlew "-Dspring.profiles.active=$TESTENV" jacocoRootReportIntegrationTest
popd