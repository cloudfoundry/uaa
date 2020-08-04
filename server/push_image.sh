#!/usr/bin/env bash

# assume uaa/server directory for now

../gradlew clean shadowJar

cp build/libs/UAA-FlywayMigrationRunner-0.0.0-all.jar migrations/

pushd migrations/
  docker build -t swaggoner/uaa_flyway_migrations .
  docker push swaggoner/uaa_flyway_migrations
popd
