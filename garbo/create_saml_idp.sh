#!/usr/bin/env bash

ACCESS_TOKEN=$(uaa context | jq '.Token.access_token' -r)
UAA_IP="$(minikube ip)"

curl "http://$UAA_IP/identity-providers?rawConfig=true" -i \
    -X POST \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer $ACCESS_TOKEN" \
    -vvv \
    -d '{
  "type" : "saml",
  "config" : {
    "emailDomain" : null,
    "providerDescription" : "For development only",
    "externalGroupsWhitelist" : [ ],
    "attributeMappings" : {
      "email_verified" : "emailVerified",
      "external_groups" : [ "roles" ],
      "user.attribute.department" : "department",
      "phone_number" : "telephone",
      "given_name" : "first_name",
      "family_name" : "last_name",
      "email" : "emailAddress"
    },
    "addShadowUserOnLogin" : true,
    "storeCustomAttributes" : true,
    "metaDataLocation" : "https://simplesamlphp.uaa-acceptance.cf-app.com/saml2/idp/metadata.php",
    "nameID" : "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "assertionConsumerIndex" : 0,
    "metadataTrustCheck" : false,
    "showSamlLink" : true,
    "linkText" : "IDPEndpointsMockTests Saml Provider:SAML",
    "iconUrl" : null,
    "groupMappingMode" : "EXPLICITLY_MAPPED",
    "skipSslValidation" : false,
    "authnContext" : null,
    "socketFactoryClassName" : null
  },
  "originKey" : "SAML",
  "name" : "SAML name",
  "active" : true
}'

