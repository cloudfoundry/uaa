FROM ubuntu:18.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    curl jq git unzip vim sudo \
    apt-transport-https apt-utils ca-certificates gnupg
    # unzip used once

ENV DEBIAN_FRONTEND=noninteractive
ENV APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=true

# JAVA
ENV JAVA_HOME /usr/lib/jvm/java-11-bellsoft-amd64
ENV PATH "${JAVA_HOME}/bin:${PATH}"
RUN export JAVA_MAJOR_VERSION="11" \
  && JDK_METADATA=$(curl "https://api.bell-sw.com/v1/liberica/releases?version-modifier=latest&os=linux&release-type=lts&bitness=64&package-type=tar.gz&bundle-type=jdk&arch=x86") \
  && JDK_VERSION=$(echo $JDK_METADATA | jq -r ".[] | select(.featureVersion | contains($JAVA_MAJOR_VERSION)).version") \
  && DOWNLOAD_URL=$(echo $JDK_METADATA | jq -r ".[] | select(.featureVersion | contains($JAVA_MAJOR_VERSION)).downloadUrl") \
  && FILENAME="bellsoft-${JDK_VERSION}.tar.gz" \
  && curl -L -o "${FILENAME}" "${DOWNLOAD_URL}" \
    && mkdir -p ${JAVA_HOME} \
  && tar -xf ${FILENAME} -C ${JAVA_HOME} --strip-components=1 \
  && "${JAVA_HOME}"/bin/java -version
#/JAVA

COPY UAA-FlywayMigrationRunner-0.0.0-all.jar UAA-FlywayMigrationRunner-0.0.0-all.jar
# is this better b/c it doesn't know about concourse? RUN install git fetch repo get gradle and build jar


#RUN apt-get install mysql-client -y

#ENTRYPOINT java -Dspring.profiles.active=mysql -Ddatabase.username=barnam  -Ddatabase.url='jdbc:mysql://host.docker.internal:3306/uaa?' -jar UAA-FlywayMigrationRunner-0.0.0-all.jar

CMD java -Dspring.profiles.active=mysql -Ddatabase.username=root -Ddatabase.url='jdbc:mysql://host.docker.internal:3306/uaa?' -jar UAA-FlywayMigrationRunner-0.0.0-all.jar