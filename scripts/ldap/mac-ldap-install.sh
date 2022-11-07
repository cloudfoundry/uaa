brew install ldap-utils slapd

sudo cp -v ./slapd.conf /etc/openldap

sudo mkdir -vp /var/lib/ldap
sudo cp -v /private/etc/openldap/DB_CONFIG.example /var/lib/ldap

