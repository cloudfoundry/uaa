
####Set up the degraded tests...
uaac target ${PROTOCOL}://$PUBLISHED_DOMAIN
uaac token client get admin -s ${ADMIN_CLIENT_SECRET}

uaac client get admin
uaac client update admin --authorities "zones.test-app-zone.admin zones.test-platform-zone.admin zones.write zones.read zones.uaa.admin clients.read clients.secret clients.write clients.admin uaa.admin password.write scim.write scim.read idps.read idps.write sps.read sps.write"

#Create a client for implicit flow
uaac curl /oauth/clients -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{
  "scope" : [ "uaa.resource","openid" ],
  "client_id" : "cf",
  "authorized_grant_types" : [ "implicit" ],
  "authorities" : [ "uaa.resource", "openid" ],
  "redirect_uri" : "'"${PROTOCOL}"'://*.dummy.predix.io/**",
  "autoapprove" : [ "uaa.resource","openid" ],
  "allowedproviders" : ["uaa"]
}'

uaac user add marissa -p koala --email marissa@ge.com || true

#Create test-app-zone (Application UAA) with zone admin
uaac curl -X POST /identity-zones -H 'Content-Type: application/json' -d'{ "id": "test-app-zone", "subdomain":"test-app-zone", "name":"test-app-zone"}'
uaac -t curl -H "X-Identity-Zone-Id:test-app-zone" -XPOST -H"Content-Type:application/json" -H"Accept:application/json" --data '{ "client_id" : "admin", "client_secret" : "'"$ZONE_ADMIN_SECRET"'", "scope" : ["uaa.none"], "resource_ids" : ["none"], "authorities" : ["uaa.admin","clients.read","clients.write","clients.secret","scim.read","scim.write","clients.admin", "sps.write", "sps.read", "zones.test-app-zone.admin", "idps.read", "idps.write", "uaa.resource"], "authorized_grant_types" : ["client_credentials"]}' /oauth/clients

#Create test-platform-zone (Platform UAA) with zone admin
uaac curl -X POST /identity-zones -H 'Content-Type: application/json' -d'{ "id": "test-platform-zone", "subdomain":"test-platform-zone", "name":"test-platform-zone", "config": {"idpDiscoveryEnabled" : true, "prompts" : [ {"name" : "username","type" : "text","text" : "username"}, {"name" : "password","type" : "password","text" : "password"}], "links" : {"selfService" : {"selfServiceLinksEnabled" : false}} }}'
uaac -t curl -H "X-Identity-Zone-Id:test-platform-zone" -XPOST -H"Content-Type:application/json" -H"Accept:application/json" --data '{ "client_id" : "admin", "client_secret" : "'"$ZONE_ADMIN_SECRET"'", "scope" : ["uaa.none"], "resource_ids" : ["none"], "authorities" : ["uaa.admin","clients.read","clients.write","clients.secret","scim.read","scim.write","clients.admin", "sps.write", "sps.read", "zones.test-platform-zone.admin", "idps.read", "idps.write"], "authorized_grant_types" : ["client_credentials"]}' /oauth/clients

#Create test-saml-zone (SAML IDP) with zone admin
uaac curl -X POST /identity-zones -H 'Content-Type: application/json' -d'{ "id": "test-saml-zone", "subdomain":"test-saml-zone", "name":"test-saml-zone"}'
uaac -t curl -H "X-Identity-Zone-Id:test-saml-zone" -XPOST -H"Content-Type:application/json" -H"Accept:application/json" --data '{ "client_id" : "admin", "client_secret" : "'"$ZONE_ADMIN_SECRET"'",  "scope" : ["uaa.none"], "resource_ids" : ["none"], "authorities" : ["uaa.admin","clients.read","clients.write","clients.secret","scim.read","scim.write","clients.admin", "sps.write", "sps.read", "zones.test-saml-zone.admin", "idps.read", "idps.write"], "authorized_grant_types" : ["client_credentials"]}' /oauth/clients

#Login to test-saml-zone
uaac target ${PROTOCOL}://test-saml-zone.$PUBLISHED_DOMAIN
uaac token client get admin -s $ZONE_ADMIN_SECRET

#Get SAML IDP metadata
SAML_IDP_RESPONSE=$(uaac curl "/saml/idp/metadata")
SAML_IDP_METADATA_RAW=$(echo $SAML_IDP_RESPONSE | sed s/.*RESPONSE\ BODY://)
SAML_IDP_METADATA=$(echo $SAML_IDP_METADATA_RAW | sed 's/"/\\"/g')

#Create some saml users
uaac user add samluser1 -p samluser1 --email samluser1@ge.com || true

uaac user add samluser2 -p samluser2 --email samluser2@ge.com || true

uaac user add 1234 -p user3 --email user3@ge.com || true

#Login to test-platform-zone
uaac target ${PROTOCOL}://test-platform-zone.$PUBLISHED_DOMAIN
uaac token client get admin -s $ZONE_ADMIN_SECRET

#Create migrated saml users
uaac curl '/Users' -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -d '{
  "externalId" : "1234",
  "meta" : {
    "version" : 0,
    "created" : "2016-09-09T00:34:22.087Z"
  },
  "userName" : "1234",
  "name" : {
    "formatted" : "given name family name",
    "familyName" : "family name",
    "givenName" : "given name"
  },
  "emails" : [ {
    "value" : "user3@ge.com",
    "primary" : true
  } ],
  "active" : true,
  "verified" : true,
  "origin" : "test-saml-zone-idp",
  "schemas" : [ "urn:scim:schemas:core:1.0" ]
}'

#Get SAML SP metadata
SAML_SP_RESPONSE=$(uaac curl "/saml/metadata/alias/test-platform-zone.cloudfoundry-saml-login")
SAML_SP_METADATA_RAW=$(echo $SAML_SP_RESPONSE | sed s/.*RESPONSE\ BODY://)
SAML_SP_METADATA=$(echo $SAML_SP_METADATA_RAW | sed 's/"/\\\\\\"/g')
SAML_SP_CONFIG='{\"metaDataLocation\":\"'$SAML_SP_METADATA'\",\"metadataTrustCheck\":true}'

#Create IDP of test-saml-zone-idp
uaac curl /identity-providers -XPOST -H 'Content-Type: application/json' -d '{
  "type" : "saml",
  "config" : {
    "emailDomain" : ["ge.com"],
    "providerDescription" :"saml provider",
    "externalGroupsWhitelist" : [ ],
    "attributeMappings" : {
      "user_name" : "user_name",
      "email" : "email"
    },
    "addShadowUserOnLogin" : true,
    "storeCustomAttributes" : false,
    "metaDataLocation" : "'"$SAML_IDP_METADATA"'",
    "nameID" : "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "assertionConsumerIndex" : 0,
    "metadataTrustCheck" : false,
    "showSamlLink" : true,
    "linkText" : "saml provider",
    "iconUrl" : null,
    "groupMappingMode" : "EXPLICITLY_MAPPED",
    "skipSslValidation" : false,
    "socketFactoryClassName" : null
  },
  "originKey" : "test-saml-zone-idp",
  "name" : "test-saml-zone-idp SAML zone",
  "active" : true
    }'

#Create a client for openid flow in test-platform-zone
uaac curl /oauth/clients -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{
  "scope" : [ "uaa.resource","openid" ],
  "client_id" : "oidcClient",
  "client_secret" : "oidc",
  "authorized_grant_types" : [ "authorization_code" ],
  "authorities" : [ "uaa.resource", "openid" ],
  "redirect_uri" : "'"${PROTOCOL}"'://test-app-zone.'"${PUBLISHED_DOMAIN}"'/login/callback/*",
  "autoapprove" : [ "uaa.resource","openid" ],
  "allowedproviders" : ["uaa", "test-saml-zone-idp"]
}'

#Login to test-saml-zone
uaac target ${PROTOCOL}://test-saml-zone.$PUBLISHED_DOMAIN
uaac token client get admin -s $ZONE_ADMIN_SECRET

#Create a SP of platform uaa
uaac curl /saml/service-providers -XPOST -H 'Content-Type: application/json' -d '{
  "name" : "test-platform-zone",
  "entityId" : "test-platform-zone.cloudfoundry-saml-login",
  "active" : true,
  "config" : "'"$SAML_SP_CONFIG"'"
}'

#Login to test-app-zone
uaac target ${PROTOCOL}://test-app-zone.$PUBLISHED_DOMAIN
uaac token client get admin -s $ZONE_ADMIN_SECRET

uaac group add zones.test-app-zone.admin || true

uaac group add sps.read || true

uaac group add sps.write || true


#Create Shadow user account in test-app-zone (password value doesn't matter)
uaac curl '/Users' -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -d '{
  "externalId" : "user1@example.com",
  "meta" : {
    "version" : 0,
    "created" : "2016-09-09T00:34:22.087Z"
  },
  "userName" : "user1@example.com",
  "name" : {
    "formatted" : "given name family name",
    "familyName" : "family name",
    "givenName" : "given name"
  },
  "emails" : [ {
    "value" : "user1@example.com",
    "primary" : true
  } ],
  "active" : true,
  "verified" : true,
  "origin" : "PredixIntegrationOIDCProvider",
  "schemas" : [ "urn:scim:schemas:core:1.0" ]
}'

#Create Shadow saml user account in test-app-zone (password value doesn't matter)
uaac curl '/Users' -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -d '{
  "externalId" : "samluser1",
  "meta" : {
    "version" : 0,
    "created" : "2016-09-09T00:34:22.087Z"
  },
  "userName" : "samluser1",
  "name" : {
    "formatted" : "given name family name",
    "familyName" : "family name",
    "givenName" : "given name"
  },
  "emails" : [ {
    "value" : "samluser1@ge.com",
    "primary" : true
  } ],
  "active" : true,
  "verified" : true,
  "origin" : "PredixIntegrationOIDCProvider",
  "schemas" : [ "urn:scim:schemas:core:1.0" ]
}'

#Create Shadow saml user account in test-app-zone (password value doesn't matter)
uaac curl '/Users' -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -d '{
  "externalId" : "1234",
  "meta" : {
    "version" : 0,
    "created" : "2016-09-09T00:34:22.087Z"
  },
  "userName" : "1234",
  "name" : {
    "formatted" : "given name family name",
    "familyName" : "family name",
    "givenName" : "given name"
  },
  "emails" : [ {
    "value" : "user3@ge.com",
    "primary" : true
  } ],
  "active" : true,
  "verified" : true,
  "origin" : "PredixIntegrationOIDCProvider",
  "schemas" : [ "urn:scim:schemas:core:1.0" ]
}'

#Add shadow user to group
uaac member add zones.test-app-zone.admin user1@example.com || true

uaac member add uaa.admin user1@example.com || true

#Add saml shadow users to group
uaac member add zones.test-app-zone.admin samluser1 || true

uaac member add uaa.admin samluser1 || true

uaac member add zones.test-app-zone.admin 1234 || true

uaac member add uaa.admin 1234 || true

#"clients.admin", "sps.read", "sps.write", "idps.read", "idps.write", "clients.write"

#Create a dashboard client in test-app-zone
uaac curl /oauth/clients -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{
  "scope" : [ "zones.test-app-zone.admin", "clients.admin", "sps.read", "sps.write", "idps.read", "idps.write", "scim.read", "scim.write" ],
  "client_id" : "exampleClient",
  "client_secret" : "secret",
  "authorized_grant_types" : [ "authorization_code" ],
  "authorities" : [ "uaa.resource", "openid" ],
  "autoapprove" : [ "zones.test-app-zone.admin", "clients.admin", "sps.read", "sps.write", "idps.read", "idps.write", "scim.read", "scim.write" ],
  "allowedproviders" : [ "PredixIntegrationOIDCProvider" ],
  "redirect_uri" : [ "'"${PROTOCOL}"'://*.dummy.predix.io/**" ]
}'

#Create OP in test-app-zone
uaac curl /identity-providers -XPOST -H 'Content-Type: application/json' -d '{
  "type" : "oidc1.0",
  "config" : {
    "providerDescription" : "OIDC idp",
    "attributeMappings" : {
        "user_name" : "user_name"
    },
    "addShadowUserOnLogin" : false,
    "authUrl" : "'"${PROTOCOL}"'://test-platform-zone.'"${PUBLISHED_DOMAIN}"'/oauth/authorize",
    "tokenUrl" : "'"${PROTOCOL}"'://test-platform-zone.'"${PUBLISHED_DOMAIN}"'/oauth/token",
    "tokenKeyUrl" : "'"${PROTOCOL}"'://test-platform-zone.'"${PUBLISHED_DOMAIN}"'/token_key",
    "linkText" : "PredixIntegrationOIDCProvider",
    "showLinkText" : true,
    "skipSslValidation" : true,
    "relyingPartyId" : "oidcClient",
    "relyingPartySecret" : "oidc",
    "scopes" : ["openid"],
    "issuer" : "'"${PROTOCOL}"'://test-platform-zone.'"${PUBLISHED_DOMAIN}"'/oauth/token"
  },
  "originKey" : "PredixIntegrationOIDCProvider",
  "name" : "PredixIntegrationOIDCProvider",
  "active" : true
}'
