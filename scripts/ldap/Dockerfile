FROM ubuntu:jammy

STOPSIGNAL SIGQUIT

SHELL ["/bin/bash", "-xo", "pipefail", "-c"]

# Generate locale C.UTF-8
ENV LANG=C.UTF-8
ENV TZ=UTC

RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

RUN DEBIAN_FRONTEND=noninteractive apt-get -qy update
RUN DEBIAN_FRONTEND=noninteractive apt-get -qy install slapd ldap-utils
RUN DEBIAN_FRONTEND=noninteractive apt-get -qy install libssl-dev ca-certificates

RUN mkdir -p /uaa/ldap/
RUN mkdir -p /uaa/certificates/

STOPSIGNAL SIGQUIT
