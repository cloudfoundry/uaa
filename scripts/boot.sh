#!/usr/bin/env bash

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

curl localhost:8080
exitcode=$?
if [[ $exitcode -ne 0 ]]; then
  echo "Cannot connect to the UAA"
  return 1
fi
set -ex
