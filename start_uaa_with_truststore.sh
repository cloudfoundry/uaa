#!/usr/bin/env bash

./kill_uaa.sh

KEYSTORE=~/workspace/uaa/garbo/foo.truststore

./gradlew clean run \
    --stacktrace \
	  -Djavax.net.ssl.trustStore=$KEYSTORE \
	  -Djavax.net.ssl.trustStoreType=PKCS12 \
	  -Djavax.net.ssl.trustStorePassword=changeit
