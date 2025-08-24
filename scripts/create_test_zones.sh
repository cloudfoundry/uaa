#!/bin/bash

if [ "${1}" == "-h" ]; then
  echo "USAGE: $0 [-h] [-d]
  -h  Show this help
  -d  Delete the created identity zones
  No arguments creates the identity zones and identity providers for testzone1 and testzone2.
  testzone1 has a zone entity id set, testzone2 does not.
  "
  exit 0
fi

port=${PORT:-8080}
uaac target http://localhost:${port}/uaa
uaac token client get admin -s adminsecret
AT=$(uaac context | grep access_token | sed 's/.*://')

if [ "${1}" == "-d" ]; then
  echo "Deleting identity zones"
  echo

  curl http://localhost:${port}/uaa/identity-zones/testzone1 -i -X DELETE -H "Authorization: Bearer $AT"
  curl http://localhost:${port}/uaa/identity-zones/testzone2 -i -X DELETE -H "Authorization: Bearer $AT"

  exit 0
fi

# Create TestZone1
curl http://localhost:${port}/uaa/identity-zones -i -X POST \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $AT" \
  -d '{
    "id" : "testzone1",
    "subdomain" : "testzone1",
    "config" : {
      "clientSecretPolicy" : {
        "minLength" : -1,
        "maxLength" : -1,
        "requireUpperCaseCharacter" : -1,
        "requireLowerCaseCharacter" : -1,
        "requireDigit" : -1,
        "requireSpecialCharacter" : -1
      },
      "samlConfig" : {
          "assertionSigned" : true,
          "requestSigned" : true,
          "wantAssertionSigned" : true,
          "wantAuthnRequestSigned" : false,
          "assertionTimeToLiveSeconds" : 600,
          "entityID" : "testzone1.cloudfoundry-saml-login",
          "disableInResponseToCheck" : false
        },
      "corsPolicy" : {
          "xhrConfiguration" : {
            "allowedOrigins" : [ ".*" ],
            "allowedOriginPatterns" : [ ],
            "allowedUris" : [ ".*" ],
            "allowedUriPatterns" : [ ],
            "allowedHeaders" : [ "Accept", "Authorization", "Content-Type" ],
            "allowedMethods" : [ "GET", "POST"],
            "allowedCredentials" : false,
            "maxAge" : 1728000
          },
          "defaultConfiguration" : {
            "allowedOrigins" : [ ".*" ],
            "allowedOriginPatterns" : [ ],
            "allowedUris" : [ ".*" ],
            "allowedUriPatterns" : [ ],
            "allowedHeaders" : [ "Accept", "Authorization", "Content-Type" ],
            "allowedMethods" : [ "GET", "POST"],
            "allowedCredentials" : false,
            "maxAge" : 1728000
          }
      }
    },
    "name" : "テストゾーン 1"
}'

# Add IDP to TestZone1
curl http://localhost:${port}/uaa/identity-providers?rawConfig=true -i -X POST \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $AT" \
  -H 'X-Identity-Zone-Id: testzone1' \
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
    "linkText" : "テストゾーン 1 SAML",
    "iconUrl" : null,
    "skipSslValidation" : true,
    "authnContext" : null,
    "socketFactoryClassName" : null
  },
  "originKey" : "testzone1-saml",
  "name" : "testzone1 SAML IdP",
  "active" : true
}'

# Create Test Zone 2, has no entity id set in the saml config
curl http://localhost:${port}/uaa/identity-zones -i -X POST \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $AT" \
  -d '{
    "id" : "testzone2",
    "subdomain" : "testzone2",
    "config" : {
      "clientSecretPolicy" : {
        "minLength" : -1,
        "maxLength" : -1,
        "requireUpperCaseCharacter" : -1,
        "requireLowerCaseCharacter" : -1,
        "requireDigit" : -1,
        "requireSpecialCharacter" : -1
      },
      "samlConfig" : {
          "assertionSigned" : false,
          "requestSigned" : false,
          "wantAssertionSigned" : false,
          "wantAuthnRequestSigned" : true,
          "assertionTimeToLiveSeconds" : 1600,
          "disableInResponseToCheck" : true
        },
      "corsPolicy" : {
          "xhrConfiguration" : {
            "allowedOrigins" : [ ".*" ],
            "allowedOriginPatterns" : [ ],
            "allowedUris" : [ ".*" ],
            "allowedUriPatterns" : [ ],
            "allowedHeaders" : [ "Accept", "Authorization", "Content-Type" ],
            "allowedMethods" : [ "GET", "POST"],
            "allowedCredentials" : false,
            "maxAge" : 1728000
          },
          "defaultConfiguration" : {
            "allowedOrigins" : [ ".*" ],
            "allowedOriginPatterns" : [ ],
            "allowedUris" : [ ".*" ],
            "allowedUriPatterns" : [ ],
            "allowedHeaders" : [ "Accept", "Authorization", "Content-Type" ],
            "allowedMethods" : [ "GET", "POST"],
            "allowedCredentials" : false,
            "maxAge" : 1728000
          }
      }
    },
    "name" : "テストゾーン 2"
}'

# Add IDP to TestZone2
curl http://localhost:${port}/uaa/identity-providers?rawConfig=true -i -X POST \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $AT" \
  -H 'X-Identity-Zone-Id: testzone2' \
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
    "linkText" : "テストゾーン 2 SAML",
    "iconUrl" : null,
    "skipSslValidation" : true,
    "authnContext" : null,
    "socketFactoryClassName" : null
  },
  "originKey" : "testzone2-saml",
  "name" : "testzone2 SAML IdP",
  "active" : true
}'

echo
echo Run these commands to get the metadata:
echo http :${port}/uaa/saml/metadata
echo http testzone1.localhost:${port}/uaa/saml/metadata
echo http testzone2.localhost:${port}/uaa/saml/metadata
