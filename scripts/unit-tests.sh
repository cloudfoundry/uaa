#!/usr/bin/env bash
set -xeu
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source $SCRIPT_DIR/start_db_helper.sh
source $SCRIPT_DIR/start_ldap_helper.sh

TESTENV="$1"

cat <<EOF >>/etc/hosts
127.0.0.1 testzone1.localhost
127.0.0.1 testzone2.localhost
127.0.0.1 testzone3.localhost
127.0.0.1 testzone4.localhost
127.0.0.1 testzonedoesnotexist.localhost
127.0.0.1 oidcloginit.localhost
EOF

bootDB "${DB}"

pushd $(dirname $SCRIPT_DIR)
  install_ldap_certs
  /etc/init.d/slapd start
  ./scripts/ldap/configure-manifest.sh
  ./gradlew "-Dspring.profiles.active=$TESTENV" jacocoRootReportTest --stacktrace
popd