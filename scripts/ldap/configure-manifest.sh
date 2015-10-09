#!/bin/bash

set -e

cd `dirname $0`/../..

set -x

echo "
ldap:
  profile:
    file: ldap/ldap-search-and-bind.xml
  base:
    url: 'ldap://localhost:389/'
    userDn: 'cn=admin,dc=test,dc=com'
    password: 'password'
    searchBase: 'dc=test,dc=com'
    searchFilter: 'cn={0}'
">> uaa/src/main/resources/uaa.yml
