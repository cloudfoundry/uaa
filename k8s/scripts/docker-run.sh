#!/usr/bin/env bash

JAVA_OPTS=""
SPRING_PROFILES="default,hsqldb"
PUBLISH_FLAGS="--publish 8080:8080"
while getopts "d" arg; do
  case $arg in
    d)
      JAVA_OPTS="-agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=5005 -Djava.security.egd=file:/dev/./urandom"
      SPRING_PROFILES="default,debug,hsqldb"
      PUBLISH_FLAGS="--publish 8080:8080 --publish 5005:5005"
      ;;
  esac
done

docker pull ${1}
docker run --detach ${PUBLISH_FLAGS} --mount type=bind,source=${2},target=/uaa.yml --env CLOUDFOUNDRY_CONFIG_PATH= --env spring_profiles=${SPRING_PROFILES} --env JAVA_OPTS=${JAVA_OPTS} ${1}
