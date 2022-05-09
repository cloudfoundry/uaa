FROM tomcat:9.0.50-jdk11-openjdk-slim

ARG MAINTAINER_EMAIL
ARG VERSION

LABEL maintainer="${MAINTAINER_EMAIL}"

ENV CLOUDFOUNDRY_CONFIG_PATH /uaa
ENV SECRETS_DIR /uaa/secrets

COPY cloudfoundry-identity-uaa-${VERSION}.war /usr/local/tomcat/webapps/ROOT.war

RUN set -eux; \
    \
    addgroup --gid 1110 docker; \
    adduser --uid 1100 --disabled-password --gecos '' dockeruser; \
    adduser dockeruser docker; \
    \
    chown -R dockeruser:docker /usr/local/tomcat; \
    ls -l /usr/local/tomcat; \
    mkdir -p /uaa/secrets; \
    chown -R dockeruser:docker /uaa; \
    ls -l /uaa

EXPOSE 8080
USER dockeruser:docker
