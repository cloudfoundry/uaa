#!/bin/bash

# Starting LDAP server on different ports is done through the command line startup with the -h switch
# -h "ldap://localhost:10389"

# run ldap server with debug output enabled ( -d3 switch )
if test "$1" == "debug"
then
  sudo /usr/libexec/slapd -d3
else
  sudo /usr/libexec/slapd
fi