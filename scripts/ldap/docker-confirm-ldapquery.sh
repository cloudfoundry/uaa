#query to run to confirm docker openldap is up and running with correct configuration
set +x

#ldapsearch -x -L -H ldap://localhost:389/ -b dc=test,dc=com
ldapsearch -vvv -x -L -H ldap://localhost -b dc=test,dc=com
echo ===============================================================================
#ldapsearch -x -L -H ldap://localhost:389/ -b dc=test,dc=com -D "cn=admin,dc=test,dc=com" -w password
ldapsearch -vvv -x -L -H ldap://localhost -b dc=test,dc=com -D "cn=admin,dc=test,dc=com" -w password
ldapsearch -vvv -x -L -H ldap://localhost -b dc=test,dc=com -D "cn=confadmin,dc=test,dc=com" -w configpassword
#ldapsearch -x -L -H ldap://localhost -b dc=test,dc=com -D "dc=test,dc=com" -w password
#ldapsearch -x -L -H ldap://localhost -b dc=test,dc=com -D "test.com" -w password
