#!/bin/bash

set -ex

echo "--------------------------"
echo "NOTE: This script should only be run by Bazel"
echo "--------------------------"

APACHE_TOMCAT_VERSION="8.0.53"

# this might need to change for Linux
APACHE_TOMCAT_DIR="$(dirname "$(readlink external/apache_tomcat/apache-tomcat-${APACHE_TOMCAT_VERSION}.tar.gz)")/apache-tomcat-${APACHE_TOMCAT_VERSION}/"
echo "APACHE_TOMCAT_DIR: ${APACHE_TOMCAT_DIR}"

# clear out bootstrapped Tomcat project
rm -rf ${APACHE_TOMCAT_DIR}/webapps/*

echo "Deploying WAR to Tomcat..."
cp -f uaa/uaa.war ${APACHE_TOMCAT_DIR}/webapps/

echo "Starting Tomcat container..."
export CATALINA_OPTS="-Dspring.profiles.active=default -DLOGIN_CONFIG_URL=file://`pwd`/uaa/src/main/resources/required_configuration.yml"
external/apache_tomcat/apache-tomcat-${APACHE_TOMCAT_VERSION}/bin/catalina.sh run
