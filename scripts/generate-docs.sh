#!/usr/bin/env bash

pushd /root/uaa
  ./gradlew generateDocs
  retVal=$?
  if [ $retVal -ne 0 ]; then
      exit 1
  fi
popd