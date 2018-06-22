#!/bin/bash

set -xeu

pushd uaa
    sed -i "s#nexusUsername=#nexusUsername=${NEXUS_USERNAME}#" ./gradle.properties
    sed -i "s#nexusPassword=#nexusPassword=${NEXUS_PASSWORD}#" ./gradle.properties
    ./gradlew publish
popd