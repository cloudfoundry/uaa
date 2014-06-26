#!/bin/bash

set -e

cd `dirname $0`/../..

set -x

echo "
spring_profiles: ${@}
" >> uaa/src/main/resources/uaa.yml
