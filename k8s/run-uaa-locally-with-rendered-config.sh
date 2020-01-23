#!/usr/bin/env bash

set -eux

CURRENT_DIR=$(basename ~+)

if [[ "${CURRENT_DIR}" != "k8s" ]]; then
  echo "You must be in the k8s directory"
  exit 255
fi

TEMP_UAA_YML=$(mktemp)

make render | yq r - "data[uaa.yml]" > "${TEMP_UAA_YML}"

pushd ..
  UAA_CONFIG_FILE="${TEMP_UAA_YML}" ./gradlew clean run
popd