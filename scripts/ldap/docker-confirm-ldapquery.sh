#!/usr/bin/env bash

#query to run to confirm docker openldap is up and running with correct configuration

set -e

echo ==================================GET all userApplication attributes using anonymous bind=============================================

LDAPTLS_REQCERT=never ldapsearch -vvv -x -L -H ldaps://localhost -b dc=test,dc=com

echo =====================================Bind with Admin and Seach for user01==========================================

LDAPTLS_REQCERT=never ldapsearch -vvv -x -L -H ldaps://localhost -b dc=test,dc=com -D "cn=admin,dc=test,dc=com" -w password "(cn=user01)"

echo -e "\n*********** SUCCESS"
