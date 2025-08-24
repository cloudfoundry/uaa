#!/usr/bin/env bash
set -xeu

pushd /root/uaa
  ./gradlew generateDocs
popd