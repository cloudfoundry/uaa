#!/usr/bin/env bash
set -xeu
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source $SCRIPT_DIR/start_db_helper.sh
source $SCRIPT_DIR/start_ldap_helper.sh

TESTENV="$1"

pushd $(dirname $SCRIPT_DIR)
  bootDB "${DB}"
  install_ldap_certs
  ./gradlew "-Dspring.profiles.active=$TESTENV" jacocoRootReportTest --stacktrace
popd