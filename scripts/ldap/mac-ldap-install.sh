brew install ldap-utils slapd

sudo cp -v ./slapd.conf /etc/openldap

sudo mkdir -vp /var/lib/ldap
sudo cp -v /private/etc/openldap/DB_CONFIG.example /var/lib/ldap

# run ldap server with debug output enabled ( -d3 switch )
if test "$1" == "debug"
then
  sudo /usr/libexec/slapd -d3
else
  sudo /usr/libexec/slapd
fi
