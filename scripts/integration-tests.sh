#!/usr/bin/env bash
set -xeu
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source $DIR/start_db_helper.sh
source $DIR/start_ldap_helper.sh

TESTENV="$1"
UAA_DIR="$2"

cat <<EOF >>/etc/hosts
127.0.0.1 testzone1.localhost
127.0.0.1 testzone2.localhost
127.0.0.1 testzone3.localhost
127.0.0.1 testzone4.localhost
127.0.0.1 testzonedoesnotexist.localhost
127.0.0.1 oidcloginit.localhost
EOF

bootDB "${DB}"

pushd $(dirname $DIR)
  install_ldap_certs
  /etc/init.d/slapd start
  ./scripts/ldap/configure-manifest.sh
  ldapadd -Y EXTERNAL -H ldapi:/// -f ./uaa/src/main/resources/ldap_db_init.ldif
  ldapadd -x -D 'cn=admin,dc=test,dc=com' -w password -f ./uaa/src/main/resources/ldap_init.ldif
  ./gradlew "-Dspring.profiles.active=$TESTENV" jacocoRootReportIntegrationTest --no-daemon --stacktrace --console=plain -x :cloudfoundry-identity-samples:assemble -x javadoc -x javadocJar
popd