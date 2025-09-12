#!/bin/bash

set -e -x -v

uaac target ${PROTOCOL}://$PUBLISHED_DOMAIN
uaac token client get admin -s ${ADMIN_CLIENT_SECRET}

#Create test-jwt-zone (JWT) with zone admin
uaac curl -X POST /identity-zones -H 'Content-Type: application/json' -d'{ "id": "test-jwt-zone", "subdomain":"test-jwt-zone", "name":"test-jwt-zone"}'
uaac -t curl -H "X-Identity-Zone-Id:test-jwt-zone" -XPOST -H"Content-Type:application/json" -H"Accept:application/json" --data '{ "client_id" : "admin", "client_secret" : "'"$ZONE_ADMIN_SECRET"'",  "scope" : ["uaa.none"], "resource_ids" : ["none"], "authorities" : ["uaa.admin","clients.read","clients.write","clients.secret","scim.read","scim.write","clients.admin", "sps.write", "sps.read", "zones.test-jwt-zone.admin", "idps.read", "idps.write"], "authorized_grant_types" : ["client_credentials"]}' /oauth/clients

uaac target ${PROTOCOL}://test-jwt-zone.$PUBLISHED_DOMAIN
uaac token client get admin -s ${ZONE_ADMIN_SECRET}

uaac curl /oauth/clients -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{
  "scope" : [ "uaa.none"],
  "client_id" : "c1",
  "authorized_grant_types" : [ "urn:ietf:params:oauth:grant-type:jwt-bearer" ],
  "authorities" : [ "machine.m1.admin" ],
  "allowed_device_id" : "d10"
}'

#Create a client to check token.
uaac curl /oauth/clients -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{
  "scope" : [ "uaa.none"],
  "client_id" : "app",
  "client_secret" : "'"$BASIC_AUTH_CLIENT_SECRET"'",
  "authorized_grant_types" : [ "client_credentials" ],
  "authorities" : [ "uaa.resource" ]
}'
