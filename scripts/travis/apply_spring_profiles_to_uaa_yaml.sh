#!/bin/bash

set -e

cd `dirname $0`/../..

set -x

echo "
spring_profiles: ${@}
" >> uaa/src/main/resources/uaa.yml

echo "
database:
  maxactive: 10
  maxidle: 0
" >> uaa/src/main/resources/uaa.yml