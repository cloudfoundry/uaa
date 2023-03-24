#!/usr/bin/env bash
set -xeu

pushd /root/uaa/uaa/slate
  gem install bundler:2.2.22 
popd
pushd /root/uaa
  ./gradlew generateDocs
popd