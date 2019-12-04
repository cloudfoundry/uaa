#!/usr/bin/env bash
set -xeu
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

source $DIR/start_db_helper.sh

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

bootDB "${DB}"

pushd $DIR/..
  ./gradlew clean assemble
  java \
    -Dspring.profiles.active=${TESTENV} \
    -DLOGIN_CONFIG_URL=classpath:required_configuration.yml \
    -jar uaa/build/libs/cloudfoundry-identity-uaa-0.0.0.war > /dev/null 2>&1 &
  UAA_PID=$!
popd

set +ex
for count in `seq 1 20`; do
  echo "${count}: trying to curl the UAA"
  curl localhost:8080
  exitcode=$?
  if [[ $exitcode -eq 0 ]]; then
    break
  fi
  sleep 3
done

curl localhost:8080ChangeEmailIT
exitcode=$?
if [[ $exitcode -ne 0 ]]; then
  echo "Cannot connect to the UAA"
  return 1
fi
set -ex

pushd $(dirname $DIR)
  /etc/init.d/slapd start
  ldapadd -Y EXTERNAL -H ldapi:/// -f ./uaa/src/main/resources/ldap_db_init.ldif
  ldapadd -x -D 'cn=admin,dc=test,dc=com' -w password -f ./uaa/src/main/resources/ldap_init.ldif
  ./gradlew "-Dspring.profiles.active=${TESTENV}" integrationTest \
    --continue \
    --no-daemon --stacktrace \
    --console=plain -x :cloudfoundry-identity-samples:assemble
popd

kill $UAA_PID