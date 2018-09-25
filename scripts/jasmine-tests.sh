#!/usr/bin/env bash
set -xeu
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

pushd $(dirname $SCRIPT_DIR)
  ./gradlew jasmineTests
popd
