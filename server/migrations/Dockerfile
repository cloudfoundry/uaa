FROM ubuntu:18.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl jq git unzip vim sudo \
    apt-transport-https apt-utils ca-certificates gnupg
    # unzip used once

ENV DEBIAN_FRONTEND=noninteractive
ENV APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=true

# JAVA
ENV JAVA_HOME /usr/lib/jvm/java-bellsoft-amd64
ENV PATH "${JAVA_HOME}/bin:${PATH}"
RUN JAVA_MAJOR_VERSION="11" \
    && JDK_METADATA="jdk-metadata.json" \
    && curl -sLo "${JDK_METADATA}" "https://api.bell-sw.com/v1/liberica/releases?version-modifier=latest&os=linux&release-type=lts&bitness=64&package-type=tar.gz&bundle-type=jdk&arch=x86" \
    && JDK_VERSION="$(jq -r ".[] | select(.featureVersion | contains("${JAVA_MAJOR_VERSION}")).version" "${JDK_METADATA}")" \
    && JDK_ARCHIVE_URL="$(jq -r ".[] | select(.featureVersion | contains("${JAVA_MAJOR_VERSION}")).downloadUrl" "${JDK_METADATA}")" \
    && JDK_ARCHIVE="$(basename "${JDK_ARCHIVE_URL}")" \
    && curl -sLo "${JDK_ARCHIVE}" "${JDK_ARCHIVE_URL}" \
    && mkdir -p "${JAVA_HOME}" \
    && tar -xf "${JDK_ARCHIVE}" -C "${JAVA_HOME}" --strip-components=1 \
    && rm -rf "${JDK_ARCHIVE}" "${JDK_METADATA}" \
    && "${JAVA_HOME}"/bin/java -version
#/JAVA

COPY UAA-FlywayMigrationRunner-0.0.0-all.jar UAA-FlywayMigrationRunner-0.0.0-all.jar
# is this better b/c it doesn't know about concourse? RUN install git fetch repo get gradle and build jar

# MySQL
#ENV DB_SCHEME="mysql"
#ENV DB_USERNAME=""
#ENV DB_PASSWORD=""
#ENV DB_URL="jdbc:${DB_SCHEME}://${DB_HOST}:3306/uaa"

# Postgres
#ENV DB_SCHEME="postgres"
#ENV DB_USERNAME=""
#ENV DB_PASSWORD=""
#ENV DB_URL="jdbc:${DB_SCHEME}://${DB_HOST}:5432/uaa"

ENV DB_SCRIPT="/migrate.sh"
RUN echo "#!/usr/bin/env bash"                             >> "${DB_SCRIPT}" \
    && echo "set -eu -o pipefail"                          >> "${DB_SCRIPT}" \
    && echo "java \\"                                      >> "${DB_SCRIPT}" \
    && echo '-Dspring.profiles.active=${DB_SCHEME} \\'     >> "${DB_SCRIPT}" \
    && echo '-Ddatabase.username=${DB_USERNAME} \\'        >> "${DB_SCRIPT}" \
    && echo '-Ddatabase.password=${DB_PASSWORD} \\'        >> "${DB_SCRIPT}" \
    && echo '-Ddatabase.url='${DB_URL}' \\'                >> "${DB_SCRIPT}" \
    && echo '-jar UAA-FlywayMigrationRunner-0.0.0-all.jar' >> "${DB_SCRIPT}" \
    && chmod 755 "${DB_SCRIPT}"

CMD ${DB_SCRIPT}

