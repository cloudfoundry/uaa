#!/bin/bash

set -eux

echo "Running tests for profile/environment: ${TEST_ENV}"
echo "Running tests with command: ${TEST_COMMAND}"
./gradlew "-Dspring.profiles.active=${TEST_ENV}" "${TEST_COMMAND}"
