#!/usr/bin/env bash
set -xeu
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source $SCRIPT_DIR/start_db_helper.sh

TESTENV="$1"

cat <<EOF >>/etc/hosts
127.0.0.1 testzone1.localhost
127.0.0.1 testzone2.localhost
127.0.0.1 testzone3.localhost
127.0.0.1 testzone4.localhost
127.0.0.1 testzonedoesnotexist.localhost
127.0.0.1 oidcloginit.localhost
127.0.0.1 testzoneinactive.localhost
EOF

bootDB "${DB}" # DB is set in the Dockerfile for each image

pushd $(dirname $SCRIPT_DIR)
  /etc/init.d/slapd start

  ldapadd \
      -Y EXTERNAL \
      -H 'ldapi:///' \
      -f ./uaa/src/test/resources/ldap_db_init.ldif

  ldapadd \
      -x \
      -D 'cn=admin,dc=test,dc=com' \
      -w password \
      -f ./uaa/src/test/resources/ldap_init.ldif

  ./gradlew "-Dspring.profiles.active=${TESTENV}" \
            "-Djava.security.egd=file:/dev/./urandom" \
            assemble \
            --max-workers=4 \
            --no-daemon \
            --stacktrace \
            --console=plain \
            --exclude-task ':cloudfoundry-identity-samples:assemble'

  ./gradlew "-Dspring.profiles.active=${TESTENV}" \
            "-Djava.security.egd=file:/dev/./urandom" \
            test \
            --no-daemon \
            --stacktrace \
            --console=plain \
            --exclude-task ':cloudfoundry-identity-samples:assemble'
popd
