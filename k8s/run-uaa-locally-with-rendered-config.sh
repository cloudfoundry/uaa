#!/usr/bin/env bash

set -eux

CURRENT_DIR=$(basename ~+)

if [[ "${CURRENT_DIR}" != "k8s" ]]; then
  echo "You must be in the k8s directory"
  exit 255
fi

CLOUDFOUNDRY_CONFIG_PATH=$(mktemp -d)

make render | yq r - "data[uaa.yml]" > "${CLOUDFOUNDRY_CONFIG_PATH}/uaa.yml"

pushd ..
  ./gradlew clean run
popd