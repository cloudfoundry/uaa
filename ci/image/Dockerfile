FROM ubuntu:18.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl jq git lsb-release unzip vim sudo \
    apt-transport-https apt-utils ca-certificates gnupg \
    && apt-get autoremove -yqq && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
    # unzip used once

ENV DEBIAN_FRONTEND=noninteractive
ENV APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=true

# JAVA
ENV JAVA_HOME /usr/lib/jvm/java-bellsoft-amd64
ENV PATH "${JAVA_HOME}/bin:${PATH}"
RUN JAVA_MAJOR_VERSION="11" \
    && JDK_METADATA="jdk-metadata.json" \
    && curl -sLo "${JDK_METADATA}" "https://api.bell-sw.com/v1/liberica/releases?version-modifier=latest&os=linux&release-type=lts&bitness=64&package-type=tar.gz&bundle-type=jdk&arch=x86&version-feature=${JAVA_MAJOR_VERSION}" \
    && JDK_VERSION="$(jq -r ".[] | select(.featureVersion | contains("${JAVA_MAJOR_VERSION}")).version" "${JDK_METADATA}")" \
    && JDK_ARCHIVE_URL="$(jq -r ".[] | select(.featureVersion | contains("${JAVA_MAJOR_VERSION}")).downloadUrl" "${JDK_METADATA}")" \
    && JDK_ARCHIVE="$(basename "${JDK_ARCHIVE_URL}")" \
    && curl -sLo "${JDK_ARCHIVE}" "${JDK_ARCHIVE_URL}" \
    && mkdir -p "${JAVA_HOME}" \
    && tar -xf "${JDK_ARCHIVE}" -C "${JAVA_HOME}" --strip-components=1 \
    && rm -rf "${JDK_ARCHIVE}" "${JDK_METADATA}" \
    && "${JAVA_HOME}"/bin/java -version
#/JAVA

# CHROME; see https://github.com/justinribeiro/dockerfiles/blob/c87217ebfeced3f0088f6559b799ed85f495ddff/chrome-headless/Dockerfile#L31-L51
RUN curl -sSL https://dl.google.com/linux/linux_signing_key.pub | apt-key add - \
	&& echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends \
	google-chrome-stable \
	fontconfig \
	fonts-ipafont-gothic \
	fonts-wqy-zenhei \
	fonts-thai-tlwg \
	fonts-kacst \
	fonts-symbola \
	fonts-noto \
    libgconf-2-4 \
    libxss1 \
    libasound2 \
    libnss3-tools \
    && apt-get install -y --no-install-recommends libosmesa6 \
        && ln -s /usr/lib/x86_64-linux-gnu/libOSMesa.so.8 \
                 /opt/google/chrome/libosmesa.so \
    && apt-get install -y --no-install-recommends libatk-bridge2.0-0 \
        && ln -s /usr/lib/x86_64-linux-gnu/libatk-bridge-2.0.so.0 \
                 /opt/google/chrome/ \
    && apt-get install -y --no-install-recommends libgtk-3-0 \
        && ln -s /usr/lib/x86_64-linux-gnu/libgtk-3.so.0 \
                 /opt/google/chrome/ \
    && apt-get install -y --no-install-recommends libgdk3.0-cil \
        && ln -s /usr/lib/x86_64-linux-gnu/libgdk-3.so.0 \
                 /opt/google/chrome/ \
    && export CHROMEDRIVER_VERSION=$(curl -sS chromedriver.storage.googleapis.com/LATEST_RELEASE_$(google-chrome --version | cut -f 3 -d ' ' | cut -f 1,2,3 -d '.')) \
    && curl -sfLO https://chromedriver.storage.googleapis.com/${CHROMEDRIVER_VERSION}/chromedriver_linux64.zip \
    && unzip chromedriver_linux64.zip -d /usr/bin/ \
    && rm chromedriver_linux64.zip \
    && ln -s /usr/bin/chromedriver /usr/local/bin/ \
    && apt-get autoremove -yqq && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*
    # ^ TODO: WHY IS THE BINARY NEEDED IN TWO PLACES?
#/CHROME

# LDAP; see https://help.ubuntu.com/lts/serverguide/openldap-server.html
RUN apt-get update && apt-get install -y --no-install-recommends \
    gnutls-bin slapd ldap-utils ssl-cert \
    && apt-get autoremove -yqq && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && certtool --generate-privkey > /etc/ssl/private/cakey.pem \
    && echo "cn = Pivotal Software Test"    >> /etc/ssl/ca.info \
    && echo "  ca"                          >> /etc/ssl/ca.info \
    && echo "  cert_signing_key"            >> /etc/ssl/ca.info \
    && certtool --generate-self-signed --load-privkey /etc/ssl/private/cakey.pem --template /etc/ssl/ca.info --outfile /etc/ssl/certs/cacert.pem \
    && certtool --generate-privkey --bits 1024 --outfile /etc/ssl/private/ldap01_slapd_key.pem \
    && echo "organization = Pivotal Software Test"  >> /etc/ssl/ldap01.info \
    && echo "    cn = ldap01.example.com"           >> /etc/ssl/ldap01.info \
    && echo "    tls_www_server"                    >> /etc/ssl/ldap01.info \
    && echo "    encryption_key"                    >> /etc/ssl/ldap01.info \
    && echo "    signing_key"                       >> /etc/ssl/ldap01.info \
    && echo "    expiration_days = 3650"            >> /etc/ssl/ldap01.info \
    && certtool --generate-certificate --load-privkey /etc/ssl/private/ldap01_slapd_key.pem --load-ca-certificate /etc/ssl/certs/cacert.pem --load-ca-privkey /etc/ssl/private/cakey.pem --template /etc/ssl/ldap01.info --outfile /etc/ssl/certs/ldap01_slapd_cert.pem \
    && adduser openldap ssl-cert \
    && chgrp ssl-cert /etc/ssl/private/ldap01_slapd_key.pem \
    && chmod 0640 /etc/ssl/private/ldap01_slapd_key.pem \
    && echo "dn: cn=config"                                                     >> /etc/ssl/certinfo.ldif \
    && echo "changetype: modify"                                                >> /etc/ssl/certinfo.ldif \
    && echo "add: olcTLSCACertificateFile"                                      >> /etc/ssl/certinfo.ldif \
    && echo "olcTLSCACertificateFile: /etc/ssl/certs/cacert.pem"                >> /etc/ssl/certinfo.ldif \
    && echo "-"                                                                 >> /etc/ssl/certinfo.ldif \
    && echo "add: olcTLSCertificateFile"                                        >> /etc/ssl/certinfo.ldif \
    && echo "olcTLSCertificateFile: /etc/ssl/certs/ldap01_slapd_cert.pem"       >> /etc/ssl/certinfo.ldif \
    && echo "-"                                                                 >> /etc/ssl/certinfo.ldif \
    && echo "add: olcTLSCertificateKeyFile"                                     >> /etc/ssl/certinfo.ldif \
    && echo "olcTLSCertificateKeyFile: /etc/ssl/private/ldap01_slapd_key.pem"   >> /etc/ssl/certinfo.ldif \
    && service slapd start \
    && ldapmodify -Y EXTERNAL -H ldapi:/// -f /etc/ssl/certinfo.ldif \
    && sed -i "s/^SLAPD_SERVICES.*/SLAPD_SERVICES=\"ldap\:\/\/\/ ldapi\:\/\/\/ ldaps\:\/\/\/\"/g" /etc/default/slapd \
    && echo "#!/usr/bin/env bash"                                               >> /bin/start-slapd \
    && echo "set -eu -o pipefail"                                               >> /bin/start-slapd \
    && echo "echo '# docker build will not persist /etc/hosts'  >> /etc/hosts"  >> /bin/start-slapd \
    && echo "echo '# ------------- UAA DNS ------------- #'     >> /etc/hosts"  >> /bin/start-slapd \
    && echo "echo '127.0.0.1 oidcloginit.localhost'             >> /etc/hosts"  >> /bin/start-slapd \
    && echo "echo '127.0.0.1 testzone1.localhost'               >> /etc/hosts"  >> /bin/start-slapd \
    && echo "echo '127.0.0.1 testzone2.localhost'               >> /etc/hosts"  >> /bin/start-slapd \
    && echo "echo '127.0.0.1 testzone3.localhost'               >> /etc/hosts"  >> /bin/start-slapd \
    && echo "echo '127.0.0.1 testzone4.localhost'               >> /etc/hosts"  >> /bin/start-slapd \
    && echo "echo '127.0.0.1 testzoneinactive.localhost'        >> /etc/hosts"  >> /bin/start-slapd \
    && echo "echo '127.0.0.1 testzonedoesnotexist.localhost'    >> /etc/hosts"  >> /bin/start-slapd \
    && echo "echo '# ------------- UAA DNS ------------- #'     >> /etc/hosts"  >> /bin/start-slapd \
    && echo "pgrep slapd || service slapd start"                                >> /bin/start-slapd \
    && chmod 0755 /bin/start-slapd
#/LDAP

# DATABASES
# DATABASES-POSTGRESQL
RUN apt-get update && apt-get install -y --no-install-recommends \
    postgresql postgresql-contrib \
    && apt-get autoremove -yqq && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && echo "#!/usr/bin/env bash"                                               >> /bin/start-postgresql \
    && echo "set -eu -o pipefail"                                               >> /bin/start-postgresql \
    && echo "service postgresql start"                                          >> /bin/start-postgresql \
    && echo "while ! sudo -u postgres psql -c 'select 1'; do sleep 1; done;"    >> /bin/start-postgresql \
    && chmod 0755 /bin/start-postgresql
#/DATABASES-POSTGRESQL

# DATABASES-MYSQL-OR-PERCONA
RUN export PERCONA_DEB="percona-release_latest.$(lsb_release -sc)_all.deb" \
    && curl -sLo ${PERCONA_DEB} https://repo.percona.com/apt/${PERCONA_DEB} \
    && dpkg -i ${PERCONA_DEB} && rm ${PERCONA_DEB} \
    && apt-get update && apt-get install -y --no-install-recommends \
# MYSQL - collides with PERCONA
    mysql-server \
# MYSQL - collides with PERCONA
# PERCONA - collides with MYSQL
#    percona-server-server-5.7 mysql-client \
#/PERCONA - collides with MYSQL
    && apt-get autoremove -yqq && apt-get clean && rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/* \
    && sudo mysql_ssl_rsa_setup --uid=mysql \
    && echo "#!/usr/bin/env bash"                                                   >> /bin/start-mysql \
    && echo "set -eu -o pipefail"                                                   >> /bin/start-mysql \
    && echo "find /var/lib/mysql -type f -exec touch {} \; && service mysql start"  >> /bin/start-mysql \
    && echo "while ! mysql -e 'select 1'; do sleep 1; done;"                        >> /bin/start-mysql \
    && chmod 0755 /bin/start-mysql
# DATABASES-MYSQL-OR-PERCONA
#/DATABASES

# PROJECT_SETUP
ENV DB_NAME=uaa
ENV DB_USER=root
ENV DB_PASS=changeme
ENV NUM_DBS=24

RUN /bin/start-mysql \
    && echo "[mysql]"               >> "${HOME}/.my.cnf" \
    && echo "password=${DB_PASS}"   >> "${HOME}/.my.cnf" \
    && mysql -e "ALTER USER '${DB_USER}'@'localhost' IDENTIFIED WITH mysql_native_password BY '${DB_PASS}';" \
    # -----------^ change root from `auth_socket` to `mysql_native_password` so that `-h 127.0.0.1` works
    && mysql -e "CREATE DATABASE ${DB_NAME} DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci;" \
    && for i in $(seq 1 ${NUM_DBS}); do mysql -e "CREATE DATABASE ${DB_NAME}_${i} DEFAULT CHARACTER SET utf8 DEFAULT COLLATE utf8_general_ci;" ; done

RUN /bin/start-postgresql \
    && sudo -u postgres psql -c "CREATE USER ${DB_USER} WITH SUPERUSER PASSWORD '${DB_PASS}';" \
    && sudo -u postgres createdb "${DB_USER}" \
    && sudo -u postgres createdb "${DB_NAME}" \
    && for i in $(seq 1 ${NUM_DBS}); do sudo -u postgres createdb "${DB_NAME}_${i}" ; done

COPY ldap_db_init.ldif copy_of-uaa_src_main_resources_ldap_init.ldif /ldap/
RUN /bin/start-slapd \
    && ldapadd -Y EXTERNAL -H ldapi:/// -f /ldap/ldap_db_init.ldif \
    && ldapadd -x -D 'cn=admin,dc=test,dc=com' -w password -f /ldap/copy_of-uaa_src_main_resources_ldap_init.ldif \
    && rm -rf /ldap/
#/PROJECT_SETUP
