FROM tomcat:9.0.50-jdk11-openjdk-slim

ARG MAINTAINER_EMAIL
ARG VERSION

LABEL maintainer="${MAINTAINER_EMAIL}"

ENV LOGIN_CONFIG_URL WEB-INF/classes/required_configuration.yml
ENV CLOUD_FOUNDRY_CONFIG_PATH /uaa

COPY cloudfoundry-identity-uaa-${VERSION}.war /usr/local/tomcat/webapps/ROOT.war
COPY uaa-docker.yml /uaa/uaa.yml

RUN set -eux; \
    \
    addgroup --gid 1110 docker; \
    adduser --uid 1100 --disabled-password --gecos '' dockeruser; \
    adduser dockeruser docker; \
    \
    echo $LOGIN_CONFIG_URL; \
    chown -R dockeruser:docker /usr/local/tomcat; \
    ls -l /usr/local/tomcat; \
    chown -R dockeruser:docker /uaa; \
    ls -l /uaa

EXPOSE 8080
USER dockeruser:docker
