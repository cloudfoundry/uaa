#!/usr/bin/env bash
set -xeu
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source $DIR/start_db_helper.sh
source $DIR/start_ldap_helper.sh

TESTENV="$1"

bootDB "${DB}"

pushd $(dirname $DIR)
  install_ldap_certs
  ./gradlew "-Dspring.profiles.active=$TESTENV" jacocoRootReportIntegrationTest
popd