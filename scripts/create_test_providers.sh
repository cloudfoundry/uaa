#!/bin/bash

if [ "${1}" == "-h" ]; then
  echo "USAGE: $0 [-h] [-d]
  -h  Show this help
  -d  Delete the created identity zones
  No arguments creates identity providers for default zone.
  "
  exit 0
fi

if [ "${1}" == "-d" ]; then
  echo "Deleting identity providers"
  echo

  AT=$(uaac context | grep access_token | sed 's/.*://')
  curl 'http://localhost:8080/uaa/identity-providers/cc2d4b27-f789-4501-9aaa-4bbbec4f0f3d' -i -X DELETE -H "Authorization: Bearer $AT"
  exit 0
fi

uaac target http://localhost:8080/uaa
uaac token client get admin -s adminsecret
AT=$(uaac context | grep access_token | sed 's/.*://')

# Add Redirect Binding IDP to Default Zone
curl 'http://localhost:8080/uaa/identity-providers?rawConfig=true' -i -X POST \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $AT" \
  -d '{
  "type" : "saml",
  "config" : {
    "externalGroupsWhitelist" : [ ],
    "addShadowUserOnLogin" : true,
    "storeCustomAttributes" : true,
    "metaDataLocation" : "http://simplesamlphp.uaa-acceptance.cf-app.com/saml2/idp/metadata.php",
    "assertionConsumerIndex" : 0,
    "metadataTrustCheck" : true,
    "showSamlLink" : true,
    "linkText" : "SAML-PHP redirect-binding",
    "iconUrl" : null,
    "skipSslValidation" : true,
    "authnContext" : null,
    "socketFactoryClassName" : null
  },
  "originKey" : "default-redirect-binding",
  "name" : "default-redirect-binding",
  "active" : true
}'

# Add Post Binding IDP to Default Zone
curl 'http://localhost:8080/uaa/identity-providers?rawConfig=true' -i -X POST \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $AT" \
  -d '{
  "type" : "saml",
  "config" : {
    "externalGroupsWhitelist" : [ ],
    "addShadowUserOnLogin" : true,
    "storeCustomAttributes" : true,
    "metaDataLocation" : "https://dev-73893672.okta.com/app/exk9ojp48mcTeKG9t5d7/sso/saml/metadata",
    "assertionConsumerIndex" : 1,
    "metadataTrustCheck" : true,
    "showSamlLink" : true,
    "linkText" : "Okta post-binding SAML",
    "iconUrl" : null,
    "skipSslValidation" : true,
    "authnContext" : null,
    "socketFactoryClassName" : null
  },
  "originKey" : "default-post-binding",
  "name" : "default-post-binding",
  "active" : true
}'
