#!/bin/bash

set -e

cd `dirname $0`/../../

set -x

beg_tag='#BEGIN SAML PROVIDERS'
end_tag='#END SAML PROVIDERS'

(
  sed "/^$beg_tag"'$/,$d' uaa/src/main/resources/login.yml
  echo "$beg_tag"
  cat login/src/test/resources/test.saml.login.yml.txt
  echo "$end_tag"
  sed "1,/^$end_tag/d" uaa/src/main/resources/login.yml
) > login/src/main/resources/test.yml

cat login/src/main/resources/test.yml

cat login/src/main/resources/test.yml > uaa/src/main/resources/login.yml
rm -f login/src/main/resources/test.yml
