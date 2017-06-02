uaac target http://localhost:8080/uaa
uaac token client get admin -s adminsecret
uaac client get admin
uaac client update admin --authorities "zones.test-app-zone.admin zones.test-platform-zone.admin zones.write zones.read zones.uaa.admin clients.read clients.secret clients.write clients.admin uaa.admin password.write scim.write scim.read idps.read idps.write sps.read sps.write"

#Create test-app-zone (Application UAA) with zone admin
uaac curl -X POST /identity-zones -H 'Content-Type: application/json' -d'{ "id": "test-app-zone", "subdomain":"test-app-zone", "name":"test-app-zone"}'
uaac -t curl -H "X-Identity-Zone-Id:test-app-zone" -XPOST -H"Content-Type:application/json" -H"Accept:application/json" --data '{ "client_id" : "admin", "client_secret" : "adminsecret", "scope" : ["uaa.none"], "resource_ids" : ["none"], "authorities" : ["uaa.admin","clients.read","clients.write","clients.secret","scim.read","scim.write","clients.admin", "sps.write", "sps.read", "zones.test-app-zone.admin", "idps.read", "idps.write", "uaa.resource"], "authorized_grant_types" : ["client_credentials"]}' /oauth/clients

#Create test-platform-zone (Platform UAA) with zone admin
uaac curl -X POST /identity-zones -H 'Content-Type: application/json' -d'{ "id": "test-platform-zone", "subdomain":"test-platform-zone", "name":"test-platform-zone", "config": {"idpDiscoveryEnabled" : true, "prompts" : [ {"name" : "username","type" : "text","text" : "username"}, {"name" : "password","type" : "password","text" : "password"}], "links" : {"selfService" : {"selfServiceLinksEnabled" : false}} }}'
uaac -t curl -H "X-Identity-Zone-Id:test-platform-zone" -XPOST -H"Content-Type:application/json" -H"Accept:application/json" --data '{ "client_id" : "admin", "client_secret" : "adminsecret", "scope" : ["uaa.none"], "resource_ids" : ["none"], "authorities" : ["uaa.admin","clients.read","clients.write","clients.secret","scim.read","scim.write","clients.admin", "sps.write", "sps.read", "zones.test-platform-zone.admin", "idps.read", "idps.write"], "authorized_grant_types" : ["client_credentials"]}' /oauth/clients

#Create test-saml-zone (SAML IDP) with zone admin
uaac curl -X POST /identity-zones -H 'Content-Type: application/json' -d'{ "id": "test-saml-zone", "subdomain":"test-saml-zone", "name":"test-saml-zone"}'
uaac -t curl -H "X-Identity-Zone-Id:test-saml-zone" -XPOST -H"Content-Type:application/json" -H"Accept:application/json" --data '{ "client_id" : "admin", "client_secret" : "adminsecret", "scope" : ["uaa.none"], "resource_ids" : ["none"], "authorities" : ["uaa.admin","clients.read","clients.write","clients.secret","scim.read","scim.write","clients.admin", "sps.write", "sps.read", "zones.test-saml-zone.admin", "idps.read", "idps.write"], "authorized_grant_types" : ["client_credentials"]}' /oauth/clients

#Login to test-saml-zone
uaac target http://test-saml-zone.localhost:8080/uaa
uaac token client get admin -s adminsecret

#Get SAML IDP metadata
SAML_IDP_RESPONSE=$(uaac curl "/saml/idp/metadata")
SAML_IDP_METADATA_RAW=$(echo $SAML_IDP_RESPONSE | sed s/.*RESPONSE\ BODY://)
SAML_IDP_METADATA=$(echo $SAML_IDP_METADATA_RAW | sed 's/"/\\"/g')

#Create some saml users
uaac user add samluser1 -p samluser1 --email samluser1@ge.com
uaac user add samluser2 -p samluser2 --email samluser2@ge.com
uaac user add 1234 -p user3 --email user3@ge.com

#Login to test-platform-zone
uaac target http://test-platform-zone.localhost:8080/uaa
uaac token client get admin -s adminsecret

#Create migrated ge user to a shadow user of GESSO
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
  "origin" : "GESSO",
  "schemas" : [ "urn:scim:schemas:core:1.0" ]
}'

#Get SAML SP metadata
SAML_SP_RESPONSE=$(uaac curl "/saml/metadata/alias/test-platform-zone.cloudfoundry-saml-login")
SAML_SP_METADATA_RAW=$(echo $SAML_SP_RESPONSE | sed s/.*RESPONSE\ BODY://)
SAML_SP_METADATA=$(echo $SAML_SP_METADATA_RAW | sed 's/"/\\\\\\"/g')
SAML_SP_CONFIG='{\"metaDataLocation\":\"'$SAML_SP_METADATA'\",\"metadataTrustCheck\":true}'

#Create IDP of GESSO
uaac curl /identity-providers -XPOST -H 'Content-Type: application/json' -d '{
  "type" : "saml",
  "config" : {
    "emailDomain" : ["ge.com"],
    "providerDescription" :"GE SSO",
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
    "linkText" : "GE SSO",
    "iconUrl" : null,
    "groupMappingMode" : "EXPLICITLY_MAPPED",
    "skipSslValidation" : false,
    "socketFactoryClassName" : null
  },
  "originKey" : "GESSO",
  "name" : "GESSO SAML zone",
  "active" : true
	}'

#Create a client for openid flow in test-platform-zone
uaac curl /oauth/clients -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{
  "scope" : [ "uaa.resource","openid" ],
  "client_id" : "oidcClient",
  "client_secret" : "oidc",
  "authorized_grant_types" : [ "authorization_code" ],
  "authorities" : [ "uaa.resource", "openid" ],
  "redirect_uri" : "http://test-app-zone.localhost:8080/uaa/login/callback/*",
  "autoapprove" : [ "uaa.resource","openid" ],
  "allowedproviders" : ["uaa", "GESSO"]
}'

#Create a client for saml2bearer flow in test-platform-zone
uaac curl /oauth/clients -X POST -H 'Content-Type: application/json' -H 'Accept: application/json' -d '{
  "scope" : [ "uaa.resource","openid" ],
  "client_id" : "saml2Client",
  "client_secret" : "saml2",
  "authorized_grant_types" : [ "urn:ietf:params:oauth:grant-type:saml2-bearer" ],
  "authorities" : [ "uaa.resource", "openid" ],
  "redirect_uri" : "http://*.localhost:8080/uaa/login/callback/*",
  "autoapprove" : [ "uaa.resource","openid" ],
  "allowedproviders" : ["GESSO"]
}'

#Login to test-saml-zone
uaac target http://test-saml-zone.localhost:8080/uaa
uaac token client get admin -s adminsecret

#Create a SP of platform uaa
uaac curl /saml/service-providers -XPOST -H 'Content-Type: application/json' -d '{
  "name" : "test-platform-zone",
  "entityId" : "test-platform-zone.cloudfoundry-saml-login",
  "active" : true,
  "config" : "'"$SAML_SP_CONFIG"'"
}'

#Login to test-app-zone
uaac target http://test-app-zone.localhost:8080/uaa
uaac token client get admin -s adminsecret

#Create group
uaac group add zones.test-app-zone.admin
uaac group add sps.read
uaac group add sps.write

#Create Shadow user account in test-app-zone (password value doesn't matter)
uaac curl 'http://test-app-zone.localhost:8080/uaa/Users' -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -d '{
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
uaac curl 'http://test-app-zone.localhost:8080/uaa/Users' -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -d '{
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
uaac curl 'http://test-app-zone.localhost:8080/uaa/Users' -X POST -H 'Accept: application/json' -H 'Content-Type: application/json' -d '{
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
uaac member add zones.test-app-zone.admin user1@example.com
uaac member add uaa.admin user1@example.com

#Add saml shadow users to group
uaac member add zones.test-app-zone.admin samluser1
uaac member add uaa.admin samluser1
uaac member add zones.test-app-zone.admin 1234
uaac member add uaa.admin 1234

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
  "redirect_uri" : [ "http://localhost:5000/login/authcode" ]
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
    "authUrl" : "http://test-platform-zone.localhost:8080/uaa/oauth/authorize",
    "tokenUrl" : "http://test-platform-zone.localhost:8080/uaa/oauth/token",
    "tokenKeyUrl" : "http://test-platform-zone.localhost:8080/uaa/token_key",
    "linkText" : "PredixIntegrationOIDCProvider",
    "showLinkText" : true,
    "skipSslValidation" : true,
    "relyingPartyId" : "oidcClient",
    "relyingPartySecret" : "oidc",
    "scopes" : ["openid"],
    "issuer" : "http://test-platform-zone.localhost:8080/uaa/oauth/token"
  },
  "originKey" : "PredixIntegrationOIDCProvider",
  "name" : "PredixIntegrationOIDCProvider",
  "active" : true
}'

#Get token
#uaac token client get dashboardClient -s dashboard
#export TOKEN=$(uaac context | grep access_token | cut -d":" -f 2 | cut -d" " -f 2)

#Get id token and auth code from test-app-zone
#curl -v "http://test-app-zone.localhost:8080/uaa/oauth/authorize?client_id=dashboardClient&client_secret=dashboard&response_type=code&grant_type=authorization_code"
