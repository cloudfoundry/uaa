#!/bin/bash

set -xeu

pushd uaa
    sed -i "s/nexusUsername=/nexusUsername=${NEXUS_USERNAME}/" ./gradle.properties
    sed -i "s/nexusUsername=/nexusPassword=${NEXUS_PASSWORD}/" ./gradle.properties
    ./gradlew publish
popd