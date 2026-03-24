# UAA Configuration Reference

The Cloud Foundry UAA (User Account and Authentication) server is a Spring Boot application.
Configuration is loaded from the embedded `uaa/src/main/resources/uaa.yml` and can be overridden
by an external YAML file located at `$UAA_CONFIG_URL`, `$UAA_CONFIG_PATH/uaa.yml`,
or `$CLOUDFOUNDRY_CONFIG_PATH/uaa.yml`.

---

## Table of Contents

- [Property Quick-Reference Table](#property-quick-reference-table)
  - [Core / General](#core--general)
  - [Database](#database)
  - [Servlet & Session](#servlet--session)
  - [JWT Token Policy](#jwt-token-policy)
  - [OAuth Clients & Users](#oauth-clients--users)
  - [Password Policy](#password-policy)
  - [Client Secret Policy](#client-secret-policy)
  - [Authentication / Lockout Policy](#authentication--lockout-policy)
  - [SCIM (User Provisioning)](#scim-user-provisioning)
  - [Login & Branding](#login--branding)
  - [SAML Service Provider](#saml-service-provider)
  - [Logout](#logout)
  - [Links](#links)
  - [CORS](#cors)
  - [SMTP / Notifications](#smtp--notifications)
  - [LDAP](#ldap)
  - [Encryption](#encryption)
  - [Rate Limiting](#rate-limiting)
  - [REST Template (HTTP Client)](#rest-template-http-client)
  - [Tracing (Brave/Zipkin)](#tracing-bravezipkin)
  - [Health & Shutdown](#health--shutdown)
  - [Limited Mode](#limited-mode)
  - [Metrics](#metrics)
  - [Zone Paths](#zone-paths)
  - [CSP (Content Security Policy)](#csp-content-security-policy)
  - [Miscellaneous](#miscellaneous)

---

## Property Quick-Reference Table

### Core / General

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#issueruri"><img src="images/click-me.png" width="14" height="14"/></a> `issuer.uri` | — (required)| Token issuer URI|
| <a href="#uaaurl"><img src="images/click-me.png" width="14" height="14"/></a> `uaa.url` | `http://localhost:8080/uaa`| Public URL of the UAA|
| <a href="#loginurl"><img src="images/click-me.png" width="14" height="14"/></a> `login.url` | `http://localhost:8080/uaa`| URL of the login server|
| <a href="#spring_profiles"><img src="images/click-me.png" width="14" height="14"/></a> `spring_profiles` | —| Active Spring profiles|
| <a href="#require_https"><img src="images/click-me.png" width="14" height="14"/></a> `require_https` | `false`| Require HTTPS for cookies|
| <a href="#https_port"><img src="images/click-me.png" width="14" height="14"/></a> `https_port` | `443`| HTTPS port|
| <a href="#login_secret"><img src="images/click-me.png" width="14" height="14"/></a> `LOGIN_SECRET` | `loginsecret`| Shared secret for login server auth|
| <a href="#dump_requests"><img src="images/click-me.png" width="14" height="14"/></a> `dump_requests` | `false`| Dump HTTP requests for debugging|
| <a href="#environmentyamlkey"><img src="images/click-me.png" width="14" height="14"/></a> `environmentYamlKey` | —| YAML config string for validation|
| <a href="#disableinternalauth"><img src="images/click-me.png" width="14" height="14"/></a> `disableInternalAuth` | `false`| Disable internal IDP authentication|
| <a href="#disableinternalusermanagement"><img src="images/click-me.png" width="14" height="14"/></a> `disableInternalUserManagement` | `false`| Disable internal user management endpoints|
| <a href="#allowunverifiedusers"><img src="images/click-me.png" width="14" height="14"/></a> `allowUnverifiedUsers` | `true`| Allow login for unverified users|

### Database

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#databasedriverclassname"><img src="images/click-me.png" width="14" height="14"/></a> `database.driverClassName` | (per profile)| JDBC driver class|
| <a href="#databaseurl"><img src="images/click-me.png" width="14" height="14"/></a> `database.url` | (per profile)| JDBC connection URL|
| <a href="#databaseusername"><img src="images/click-me.png" width="14" height="14"/></a> `database.username` | —| Database user|
| <a href="#databasepassword"><img src="images/click-me.png" width="14" height="14"/></a> `database.password` | —| Database password|
| <a href="#databasemaxactive"><img src="images/click-me.png" width="14" height="14"/></a> `database.maxactive` | `100`| Max active connections|
| <a href="#databasemaxidle"><img src="images/click-me.png" width="14" height="14"/></a> `database.maxidle` | `10`| Max idle connections|
| <a href="#databaseminidle"><img src="images/click-me.png" width="14" height="14"/></a> `database.minidle` | `0`| Min idle connections|
| <a href="#databasemaxwait"><img src="images/click-me.png" width="14" height="14"/></a> `database.maxwait` | `30000`| Max wait for connection (ms)|
| <a href="#databaseinitialsize"><img src="images/click-me.png" width="14" height="14"/></a> `database.initialsize` | `10`| Initial pool size|
| <a href="#databasevalidationquerytimeout"><img src="images/click-me.png" width="14" height="14"/></a> `database.validationquerytimeout` | `10`| Validation query timeout (s)|
| <a href="#databasevalidationinterval"><img src="images/click-me.png" width="14" height="14"/></a> `database.validationinterval` | `5000`| Validation interval (ms)|
| <a href="#databaseconnecttimeout"><img src="images/click-me.png" width="14" height="14"/></a> `database.connecttimeout` | `10`| Connection timeout (s)|
| <a href="#databasetestwhileidle"><img src="images/click-me.png" width="14" height="14"/></a> `database.testwhileidle` | `false`| Test connections while idle|
| <a href="#databaseremovedabandoned"><img src="images/click-me.png" width="14" height="14"/></a> `database.removedAbandoned` | `false`| Remove abandoned connections|
| <a href="#databaselogabandoned"><img src="images/click-me.png" width="14" height="14"/></a> `database.logabandoned` | `true`| Log abandoned connections|
| <a href="#databaseabandonedtimeout"><img src="images/click-me.png" width="14" height="14"/></a> `database.abandonedtimeout` | `300`| Abandoned timeout (s)|
| <a href="#databaseevictionintervalms"><img src="images/click-me.png" width="14" height="14"/></a> `database.evictionintervalms` | `15000`| Eviction interval (ms)|
| <a href="#databaseminevictionidlems"><img src="images/click-me.png" width="14" height="14"/></a> `database.minevictionidlems` | `60000`| Min eviction idle time (ms)|
| <a href="#databasecaseinsensitive"><img src="images/click-me.png" width="14" height="14"/></a> `database.caseinsensitive` | `false`| Case-insensitive queries|
| <a href="#databaseuseskiplocked"><img src="images/click-me.png" width="14" height="14"/></a> `database.useSkipLocked` | `false`| Use SKIP LOCKED in queries|
| <a href="#databasemaxparameters"><img src="images/click-me.png" width="14" height="14"/></a> `database.maxParameters` | `-1`| Max SQL parameters (-1 = unlimited)|

### Servlet & Session

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#servletsession-store"><img src="images/click-me.png" width="14" height="14"/></a> `servlet.session-store` | `memory`| Session store type|
| <a href="#servletsession-cookieencode-base64"><img src="images/click-me.png" width="14" height="14"/></a> `servlet.session-cookie.encode-base64` | `true`| Base64-encode session cookie|
| <a href="#servletsession-cookiemax-age"><img src="images/click-me.png" width="14" height="14"/></a> `servlet.session-cookie.max-age` | — (null)| Session cookie max age|
| <a href="#servletidle-timeout"><img src="images/click-me.png" width="14" height="14"/></a> `servlet.idle-timeout` | `1800`| Session idle timeout (s)|
| <a href="#servletfiltered-headers"><img src="images/click-me.png" width="14" height="14"/></a> `servlet.filtered-headers` | `X-Forwarded-For, X-Forwarded-Host, X-Forwarded-Proto, X-Forwarded-Prefix, Forwarded`| Headers to filter|

### JWT Token Policy

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#jwttokensigning-key"><img src="images/click-me.png" width="14" height="14"/></a> `jwt.token.signing-key` | — (null)| Legacy token signing key|
| <a href="#jwttokensigning-alg"><img src="images/click-me.png" width="14" height="14"/></a> `jwt.token.signing-alg` | — (null)| Legacy signing algorithm|
| <a href="#jwttokensigning-cert"><img src="images/click-me.png" width="14" height="14"/></a> `jwt.token.signing-cert` | — (null)| Legacy signing certificate|
| <a href="#jwttokenrevocable"><img src="images/click-me.png" width="14" height="14"/></a> `jwt.token.revocable` | `false`| Make JWT tokens revocable|
| <a href="#jwttokenquerystringenabled"><img src="images/click-me.png" width="14" height="14"/></a> `jwt.token.queryString.enabled` | `true`| Allow tokens via query string|
| <a href="#jwttokenpolicyactivekeyid"><img src="images/click-me.png" width="14" height="14"/></a> `jwt.token.policy.activeKeyId` | — (null)| Active signing key ID|
| <a href="#jwttokenpolicykeys"><img src="images/click-me.png" width="14" height="14"/></a> `jwt.token.policy.keys` | `{}`| Map of signing keys|
| <a href="#jwttokenpolicyaccesstokenvalidityseconds"><img src="images/click-me.png" width="14" height="14"/></a> `jwt.token.policy.accessTokenValiditySeconds` | falls back to global| Access token validity (s)|
| <a href="#jwttokenpolicyrefreshtokenvalidityseconds"><img src="images/click-me.png" width="14" height="14"/></a> `jwt.token.policy.refreshTokenValiditySeconds` | falls back to global| Refresh token validity (s)|
| <a href="#jwttokenpolicyglobalaccesstokenvalidityseconds"><img src="images/click-me.png" width="14" height="14"/></a> `jwt.token.policy.global.accessTokenValiditySeconds` | `43200`| Global access token validity (s)|
| <a href="#jwttokenpolicyglobalrefreshtokenvalidityseconds"><img src="images/click-me.png" width="14" height="14"/></a> `jwt.token.policy.global.refreshTokenValiditySeconds` | `2592000`| Global refresh token validity (s)|
| <a href="#jwttokenrefreshformat"><img src="images/click-me.png" width="14" height="14"/></a> `jwt.token.refresh.format` | `opaque`| Refresh token format|
| <a href="#jwttokenrefreshunique"><img src="images/click-me.png" width="14" height="14"/></a> `jwt.token.refresh.unique` | `false`| Unique refresh tokens|
| <a href="#jwttokenrefreshrotate"><img src="images/click-me.png" width="14" height="14"/></a> `jwt.token.refresh.rotate` | `false`| Rotate refresh tokens|
| <a href="#jwttokenrefreshrestrict_grant"><img src="images/click-me.png" width="14" height="14"/></a> `jwt.token.refresh.restrict_grant` | —| Restrict refresh token grant|
| <a href="#jwttokenclaimsexclude"><img src="images/click-me.png" width="14" height="14"/></a> `jwt.token.claims.exclude` | `[]`| Claims excluded from tokens|

### OAuth Clients & Users

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#oauthclients"><img src="images/click-me.png" width="14" height="14"/></a> `oauth.clients` | `{}`| Bootstrap OAuth client definitions|
| <a href="#oauthclientoverride"><img src="images/click-me.png" width="14" height="14"/></a> `oauth.client.override` | —| Override existing client on bootstrap|
| <a href="#oauthclientautoapprove"><img src="images/click-me.png" width="14" height="14"/></a> `oauth.client.autoapprove` | `[]`| Clients auto-approved for all scopes|
| <a href="#oauthuserauthorities"><img src="images/click-me.png" width="14" height="14"/></a> `oauth.user.authorities` | (see details)| Default authorities for new users|
| <a href="#clientmaxcount"><img src="images/click-me.png" width="14" height="14"/></a> `clientMaxCount` | `500`| Max clients returned by list endpoint|

### Password Policy

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#passwordpolicyglobalminlength"><img src="images/click-me.png" width="14" height="14"/></a> `password.policy.global.minLength` | `0`| Global min password length|
| <a href="#passwordpolicyglobalmaxlength"><img src="images/click-me.png" width="14" height="14"/></a> `password.policy.global.maxLength` | `255`| Global max password length|
| <a href="#passwordpolicyglobalrequireuppercasecharacter"><img src="images/click-me.png" width="14" height="14"/></a> `password.policy.global.requireUpperCaseCharacter` | `0`| Global required uppercase chars|
| <a href="#passwordpolicyglobalrequirelowercasecharacter"><img src="images/click-me.png" width="14" height="14"/></a> `password.policy.global.requireLowerCaseCharacter` | `0`| Global required lowercase chars|
| <a href="#passwordpolicyglobalrequiredigit"><img src="images/click-me.png" width="14" height="14"/></a> `password.policy.global.requireDigit` | `0`| Global required digits|
| <a href="#passwordpolicyglobalrequirespecialcharacter"><img src="images/click-me.png" width="14" height="14"/></a> `password.policy.global.requireSpecialCharacter` | `0`| Global required special chars|
| <a href="#passwordpolicyglobalexpirepasswordinmonths"><img src="images/click-me.png" width="14" height="14"/></a> `password.policy.global.expirePasswordInMonths` | `0`| Global password expiry (months)|
| <a href="#passwordpolicyminlength"><img src="images/click-me.png" width="14" height="14"/></a> `password.policy.minLength` | (falls back to global)| Default zone min password length|
| <a href="#passwordpolicymaxlength"><img src="images/click-me.png" width="14" height="14"/></a> `password.policy.maxLength` | (falls back to global)| Default zone max password length|
| <a href="#passwordpolicyrequireuppercasecharacter"><img src="images/click-me.png" width="14" height="14"/></a> `password.policy.requireUpperCaseCharacter` | (falls back to global)| Default zone required uppercase|
| <a href="#passwordpolicyrequirelowercasecharacter"><img src="images/click-me.png" width="14" height="14"/></a> `password.policy.requireLowerCaseCharacter` | (falls back to global)| Default zone required lowercase|
| <a href="#passwordpolicyrequiredigit"><img src="images/click-me.png" width="14" height="14"/></a> `password.policy.requireDigit` | (falls back to global)| Default zone required digits|
| <a href="#passwordpolicyrequirespecialcharacter"><img src="images/click-me.png" width="14" height="14"/></a> `password.policy.requireSpecialCharacter` | (falls back to global)| Default zone required special chars|
| <a href="#passwordpolicyexpirepasswordinmonths"><img src="images/click-me.png" width="14" height="14"/></a> `password.policy.expirePasswordInMonths` | (falls back to global)| Default zone password expiry|

### Client Secret Policy

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#oauthclientsecretpolicyglobalminlength"><img src="images/click-me.png" width="14" height="14"/></a> `oauth.client.secret.policy.global.minLength` | `0`| Global min secret length|
| <a href="#oauthclientsecretpolicyglobalmaxlength"><img src="images/click-me.png" width="14" height="14"/></a> `oauth.client.secret.policy.global.maxLength` | `255`| Global max secret length|
| <a href="#oauthclientsecretpolicyglobalrequireuppercasecharacter"><img src="images/click-me.png" width="14" height="14"/></a> `oauth.client.secret.policy.global.requireUpperCaseCharacter` | `0`| Global required uppercase|
| <a href="#oauthclientsecretpolicyglobalrequirelowercasecharacter"><img src="images/click-me.png" width="14" height="14"/></a> `oauth.client.secret.policy.global.requireLowerCaseCharacter` | `0`| Global required lowercase|
| <a href="#oauthclientsecretpolicyglobalrequiredigit"><img src="images/click-me.png" width="14" height="14"/></a> `oauth.client.secret.policy.global.requireDigit` | `0`| Global required digits|
| <a href="#oauthclientsecretpolicyglobalrequirespecialcharacter"><img src="images/click-me.png" width="14" height="14"/></a> `oauth.client.secret.policy.global.requireSpecialCharacter` | `0`| Global required special chars|
| <a href="#oauthclientsecretpolicyglobalexpiresecretinmonths"><img src="images/click-me.png" width="14" height="14"/></a> `oauth.client.secret.policy.global.expireSecretInMonths` | `0`| Global secret expiry (months)|
| <a href="#oauthclientsecretpolicyminlength"><img src="images/click-me.png" width="14" height="14"/></a> `oauth.client.secret.policy.minLength` | (falls back to global)| Default zone min secret length|
| <a href="#oauthclientsecretpolicymaxlength"><img src="images/click-me.png" width="14" height="14"/></a> `oauth.client.secret.policy.maxLength` | (falls back to global)| Default zone max secret length|

### Authentication / Lockout Policy

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#authenticationpolicygloballockoutafterfailures"><img src="images/click-me.png" width="14" height="14"/></a> `authentication.policy.global.lockoutAfterFailures` | `5`| Global lockout threshold|
| <a href="#authenticationpolicyglobalcountfailureswithinseconds"><img src="images/click-me.png" width="14" height="14"/></a> `authentication.policy.global.countFailuresWithinSeconds` | `1200`| Global failure counting window (s)|
| <a href="#authenticationpolicygloballockoutperiodseconds"><img src="images/click-me.png" width="14" height="14"/></a> `authentication.policy.global.lockoutPeriodSeconds` | `300`| Global lockout duration (s)|
| <a href="#authenticationpolicylockoutafterfailures"><img src="images/click-me.png" width="14" height="14"/></a> `authentication.policy.lockoutAfterFailures` | (falls back to global)| Default zone lockout threshold|
| <a href="#authenticationpolicycountfailureswithinseconds"><img src="images/click-me.png" width="14" height="14"/></a> `authentication.policy.countFailuresWithinSeconds` | (falls back to global)| Default zone failure window (s)|
| <a href="#authenticationpolicylockoutperiodseconds"><img src="images/click-me.png" width="14" height="14"/></a> `authentication.policy.lockoutPeriodSeconds` | (falls back to global)| Default zone lockout duration (s)|
| <a href="#authenticationenableuriencodingcompatibilitymode"><img src="images/click-me.png" width="14" height="14"/></a> `authentication.enableUriEncodingCompatibilityMode` | `false`| URI encoding compat mode|

### SCIM (User Provisioning)

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#scimusers"><img src="images/click-me.png" width="14" height="14"/></a> `scim.users` | `[]`| Bootstrap users|
| <a href="#scimgroups"><img src="images/click-me.png" width="14" height="14"/></a> `scim.groups` | `{}`| Bootstrap groups and descriptions|
| <a href="#scimexternal_groups"><img src="images/click-me.png" width="14" height="14"/></a> `scim.external_groups` | `[]`| External group mappings|
| <a href="#scimuserids_enabled"><img src="images/click-me.png" width="14" height="14"/></a> `scim.userids_enabled` | `true`| Enable /ids/Users endpoint|
| <a href="#scimuseroverride"><img src="images/click-me.png" width="14" height="14"/></a> `scim.user.override` | `false`| Override existing bootstrap users|
| <a href="#scimdeletedeactivate"><img src="images/click-me.png" width="14" height="14"/></a> `scim.delete.deactivate` | `false`| Deactivate instead of delete|
| <a href="#usermaxcount"><img src="images/click-me.png" width="14" height="14"/></a> `userMaxCount` | `500`| Max users returned by list endpoint|
| <a href="#groupmaxcount"><img src="images/click-me.png" width="14" height="14"/></a> `groupMaxCount` | `500`| Max groups returned by list endpoint|
| <a href="#deleteusers"><img src="images/click-me.png" width="14" height="14"/></a> `delete.users` | — (null)| Users to delete on bootstrap|

### Login & Branding

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#loginselfservicelinksenabled"><img src="images/click-me.png" width="14" height="14"/></a> `login.selfServiceLinksEnabled` | `true`| Show self-service links|
| <a href="#loginhomeredirect"><img src="images/click-me.png" width="14" height="14"/></a> `login.homeRedirect` | — (null)| Home page redirect URL|
| <a href="#loginidpdiscoveryenabled"><img src="images/click-me.png" width="14" height="14"/></a> `login.idpDiscoveryEnabled` | `false`| Enable IDP discovery|
| <a href="#loginaccountchooserenabled"><img src="images/click-me.png" width="14" height="14"/></a> `login.accountChooserEnabled` | `false`| Enable account chooser|
| <a href="#loginentitybaseurl"><img src="images/click-me.png" width="14" height="14"/></a> `login.entityBaseURL` | `http://localhost:8080/uaa`| SAML SP entity base URL|
| <a href="#loginentityid"><img src="images/click-me.png" width="14" height="14"/></a> `login.entityID` | `unit-test-sp`| SAML SP entity ID|
| <a href="#loginpromptusernameteext"><img src="images/click-me.png" width="14" height="14"/></a> `login.prompt.username.text` | `Email`| Username field label|
| <a href="#loginpromptpasswordtext"><img src="images/click-me.png" width="14" height="14"/></a> `login.prompt.password.text` | `Password`| Password field label|
| <a href="#loginbranding"><img src="images/click-me.png" width="14" height="14"/></a> `login.branding` | —| UI branding configuration|
| <a href="#logindefaultidentityprovider"><img src="images/click-me.png" width="14" height="14"/></a> `login.defaultIdentityProvider` | — (null)| Default IDP origin key|
| <a href="#loginallowedgroups"><img src="images/click-me.png" width="14" height="14"/></a> `login.allowedGroups` | — (null)| Restrict login to group members|
| <a href="#logincheckoriginenabled"><img src="images/click-me.png" width="14" height="14"/></a> `login.checkOriginEnabled` | `false`| Check user origin on auth|
| <a href="#loginmaxusers"><img src="images/click-me.png" width="14" height="14"/></a> `login.maxUsers` | `-1`| Max users (-1 = unlimited)|
| <a href="#loginalloworiginloop"><img src="images/click-me.png" width="14" height="14"/></a> `login.allowOriginLoop` | `true`| Allow origin loop|
| <a href="#loginaliasEntitiesenabled"><img src="images/click-me.png" width="14" height="14"/></a> `login.aliasEntitiesEnabled` | `false`| Enable alias entities|
| <a href="#loginoauthproviders"><img src="images/click-me.png" width="14" height="14"/></a> `login.oauth.providers` | —| External OAuth/OIDC providers|

### SAML Service Provider

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#loginsamlactivekeyid"><img src="images/click-me.png" width="14" height="14"/></a> `login.saml.activeKeyId` | —| Active SAML signing key ID|
| <a href="#loginsamlkeys"><img src="images/click-me.png" width="14" height="14"/></a> `login.saml.keys` | `{}`| Map of SAML keys|
| <a href="#loginsamlentityidalias"><img src="images/click-me.png" width="14" height="14"/></a> `login.saml.entityIDAlias` | — (null)| SAML entity ID alias|
| <a href="#loginsamlnameid"><img src="images/click-me.png" width="14" height="14"/></a> `login.saml.nameID` | `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`| Default SAML NameID format|
| <a href="#loginsamlassertionconsumerindex"><img src="images/click-me.png" width="14" height="14"/></a> `login.saml.assertionConsumerIndex` | `0`| Assertion consumer index|
| <a href="#loginsamlsignmetadata"><img src="images/click-me.png" width="14" height="14"/></a> `login.saml.signMetaData` | `true`| Sign SAML SP metadata|
| <a href="#loginsamlsignrequest"><img src="images/click-me.png" width="14" height="14"/></a> `login.saml.signRequest` | `true`| Sign SAML auth requests|
| <a href="#loginsamlwantassertionsigned"><img src="images/click-me.png" width="14" height="14"/></a> `login.saml.wantAssertionSigned` | `true`| Require signed assertions|
| <a href="#loginsamlsignaturealgorithm"><img src="images/click-me.png" width="14" height="14"/></a> `login.saml.signatureAlgorithm` | `SHA256`| SAML signature algorithm|
| <a href="#loginsamldisableinresponsetocheck"><img src="images/click-me.png" width="14" height="14"/></a> `login.saml.disableInResponseToCheck` | `false`| Disable InResponseTo validation|
| <a href="#loginsamlproviders"><img src="images/click-me.png" width="14" height="14"/></a> `login.saml.providers` | —| SAML IDP definitions|
| <a href="#loginserviceproviderkey"><img src="images/click-me.png" width="14" height="14"/></a> `login.serviceProviderKey` | —| Legacy SP private key|
| <a href="#loginserviceproviderkey"><img src="images/click-me.png" width="14" height="14"/></a> `login.serviceProviderKeyPassword` | —| Legacy SP key password|
| <a href="#loginserviceproviderkey"><img src="images/click-me.png" width="14" height="14"/></a> `login.serviceProviderCertificate` | —| Legacy SP certificate|

### Logout

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#logoutredirecturl"><img src="images/click-me.png" width="14" height="14"/></a> `logout.redirect.url` | `/login`| Post-logout redirect URL|
| <a href="#logoutredirectparameterdisable"><img src="images/click-me.png" width="14" height="14"/></a> `logout.redirect.parameter.disable` | `false`| Disable redirect parameter|
| <a href="#logoutredirectparameterwhitelist"><img src="images/click-me.png" width="14" height="14"/></a> `logout.redirect.parameter.whitelist` | `[]`| Allowed redirect URLs|

### Links

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#linksglobalpasswd"><img src="images/click-me.png" width="14" height="14"/></a> `links.global.passwd` | — (null)| Custom forgot-password link|
| <a href="#linksglobalsignup"><img src="images/click-me.png" width="14" height="14"/></a> `links.global.signup` | — (null)| Custom signup link|
| <a href="#linksglobalhomeredirect"><img src="images/click-me.png" width="14" height="14"/></a> `links.global.homeRedirect` | — (null)| Home redirect URL|

### CORS

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#corsenforcessystemzonepolicyinallzones"><img src="images/click-me.png" width="14" height="14"/></a> `cors.enforceSystemZonePolicyInAllZones` | `false`| Enforce system CORS in all zones|
| <a href="#corsdefaultmax_age"><img src="images/click-me.png" width="14" height="14"/></a> `cors.default.max_age` | `1728000`| Default CORS max age (s)|
| <a href="#corsdefaultalloweduris"><img src="images/click-me.png" width="14" height="14"/></a> `cors.default.allowed.uris` | `[".*"]`| Default allowed URI patterns|
| <a href="#corsdefaultallowedorigins"><img src="images/click-me.png" width="14" height="14"/></a> `cors.default.allowed.origins` | `[".*"]`| Default allowed origins|
| <a href="#corsdefaultallowedheaders"><img src="images/click-me.png" width="14" height="14"/></a> `cors.default.allowed.headers` | `[Accept, Authorization, Content-Type, Accept-Language, Content-Language]`| Default allowed headers|
| <a href="#corsdefaultallowedmethods"><img src="images/click-me.png" width="14" height="14"/></a> `cors.default.allowed.methods` | `[GET, POST, PUT, OPTIONS, DELETE, PATCH]`| Default allowed methods|
| <a href="#corsdefaultallowedcredentials"><img src="images/click-me.png" width="14" height="14"/></a> `cors.default.allowed.credentials` | `false`| Default allow credentials|
| <a href="#corsxhrmax_age"><img src="images/click-me.png" width="14" height="14"/></a> `cors.xhr.max_age` | `1728000`| XHR CORS max age (s)|
| <a href="#corsxhralloweduris"><img src="images/click-me.png" width="14" height="14"/></a> `cors.xhr.allowed.uris` | `[".*"]`| XHR allowed URI patterns|
| <a href="#corsxhrallowedorigins"><img src="images/click-me.png" width="14" height="14"/></a> `cors.xhr.allowed.origins` | `[".*"]`| XHR allowed origins|
| <a href="#corsxhrallowedheaders"><img src="images/click-me.png" width="14" height="14"/></a> `cors.xhr.allowed.headers` | `[Accept, Authorization, Content-Type, Accept-Language, Content-Language, X-Requested-With]`| XHR allowed headers|
| <a href="#corsxhrallowedmethods"><img src="images/click-me.png" width="14" height="14"/></a> `cors.xhr.allowed.methods` | `[GET, OPTIONS]`| XHR allowed methods|
| <a href="#corsxhrallowedcredentials"><img src="images/click-me.png" width="14" height="14"/></a> `cors.xhr.allowed.credentials` | `true`| XHR allow credentials|

### SMTP / Notifications

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#smtphost"><img src="images/click-me.png" width="14" height="14"/></a> `smtp.host` | `localhost`| SMTP server hostname|
| <a href="#smtpport"><img src="images/click-me.png" width="14" height="14"/></a> `smtp.port` | `25`| SMTP server port|
| <a href="#smtpuser"><img src="images/click-me.png" width="14" height="14"/></a> `smtp.user` | `""`| SMTP username|
| <a href="#smtppassword"><img src="images/click-me.png" width="14" height="14"/></a> `smtp.password` | `""`| SMTP password|
| <a href="#smtpauth"><img src="images/click-me.png" width="14" height="14"/></a> `smtp.auth` | `false`| Enable SMTP auth|
| <a href="#smtpstarttls"><img src="images/click-me.png" width="14" height="14"/></a> `smtp.starttls` | `false`| Enable STARTTLS|
| <a href="#smtpsslprotocols"><img src="images/click-me.png" width="14" height="14"/></a> `smtp.sslprotocols` | `TLSv1.2`| SSL/TLS protocol versions|
| <a href="#smtpfromaddress"><img src="images/click-me.png" width="14" height="14"/></a> `smtp.fromAddress` | `""`| From address for emails|
| <a href="#notificationsurl"><img src="images/click-me.png" width="14" height="14"/></a> `notifications.url` | — (null)| Notification service URL|
| <a href="#notificationssendindefaultzone"><img src="images/click-me.png" width="14" height="14"/></a> `notifications.sendInDefaultZone` | `true`| Send in default zone|
| <a href="#notificationsverify_ssl"><img src="images/click-me.png" width="14" height="14"/></a> `notifications.verify_ssl` | `false`| Verify SSL for notifications|

### LDAP

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#ldapprofilefile"><img src="images/click-me.png" width="14" height="14"/></a> `ldap.profile.file` | —| LDAP profile configuration file|
| <a href="#ldapbaseurl"><img src="images/click-me.png" width="14" height="14"/></a> `ldap.base.url` | —| LDAP server URL|
| <a href="#ldapbaseuserdn"><img src="images/click-me.png" width="14" height="14"/></a> `ldap.base.userDn` | —| LDAP bind DN|
| <a href="#ldapbasepassword"><img src="images/click-me.png" width="14" height="14"/></a> `ldap.base.password` | —| LDAP bind password|
| <a href="#ldapbasesearchbase"><img src="images/click-me.png" width="14" height="14"/></a> `ldap.base.searchBase` | —| LDAP search base DN|
| <a href="#ldapbasesearchfilter"><img src="images/click-me.png" width="14" height="14"/></a> `ldap.base.searchFilter` | —| LDAP user search filter|
| <a href="#ldapbaseuserdnpattern"><img src="images/click-me.png" width="14" height="14"/></a> `ldap.base.userDnPattern` | —| DN pattern for simple bind|
| <a href="#ldapbasereferral"><img src="images/click-me.png" width="14" height="14"/></a> `ldap.base.referral` | —| LDAP referral handling|
| <a href="#ldapsslskipverification"><img src="images/click-me.png" width="14" height="14"/></a> `ldap.ssl.skipverification` | `false`| Skip LDAP SSL verification|
| <a href="#ldapgroupsfile"><img src="images/click-me.png" width="14" height="14"/></a> `ldap.groups.file` | —| LDAP groups configuration file|
| <a href="#ldapgroupssearchbase"><img src="images/click-me.png" width="14" height="14"/></a> `ldap.groups.searchBase` | —| LDAP group search base|
| <a href="#ldapgroupsgroupsearchfilter"><img src="images/click-me.png" width="14" height="14"/></a> `ldap.groups.groupSearchFilter` | —| Group membership filter|
| <a href="#ldapgroupsmaxsearchdepth"><img src="images/click-me.png" width="14" height="14"/></a> `ldap.groups.maxSearchDepth` | `10`| Max nested group depth|
| <a href="#ldapgroupsautoadd"><img src="images/click-me.png" width="14" height="14"/></a> `ldap.groups.autoAdd` | —| Auto-add LDAP groups|

### Encryption

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#encryptionactive_key_label"><img src="images/click-me.png" width="14" height="14"/></a> `encryption.active_key_label` | — (required)| Active encryption key label|
| <a href="#encryptionencryption_keys"><img src="images/click-me.png" width="14" height="14"/></a> `encryption.encryption_keys` | — (required)| List of encryption keys|

### Rate Limiting

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#ratelimitloggingoption"><img src="images/click-me.png" width="14" height="14"/></a> `ratelimit.loggingOption` | `OnlyLimited`| Rate-limit logging mode|
| <a href="#ratelimitcredentialid"><img src="images/click-me.png" width="14" height="14"/></a> `ratelimit.credentialID` | —| Regex for credential extraction|
| <a href="#ratelimitlimitermappings"><img src="images/click-me.png" width="14" height="14"/></a> `ratelimit.limiterMappings` | `[]`| Rate-limit rules|

### REST Template (HTTP Client)

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#resttemplatetimeout"><img src="images/click-me.png" width="14" height="14"/></a> `rest.template.timeout` | `10000`| HTTP client timeout (ms)|
| <a href="#resttemplatemaxtotal"><img src="images/click-me.png" width="14" height="14"/></a> `rest.template.maxTotal` | `10`| Max total connections|
| <a href="#resttemplatemaxperroute"><img src="images/click-me.png" width="14" height="14"/></a> `rest.template.maxPerRoute` | `5`| Max connections per route|
| <a href="#resttemplatemaxkeepalive"><img src="images/click-me.png" width="14" height="14"/></a> `rest.template.maxKeepAlive` | `0`| Max keep-alive (ms)|
| <a href="#resttemplatevalidateafterinactivity"><img src="images/click-me.png" width="14" height="14"/></a> `rest.template.validateAfterInactivity` | `2000`| Validate after inactivity (ms)|
| <a href="#resttemplateretrycount"><img src="images/click-me.png" width="14" height="14"/></a> `rest.template.retryCount` | `0`| HTTP retry count|

### Tracing (Brave/Zipkin)

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#bravelocalservicename"><img src="images/click-me.png" width="14" height="14"/></a> `brave.localServiceName` | `uaa`| Service name in traces|
| <a href="#bravesupportsjoin"><img src="images/click-me.png" width="14" height="14"/></a> `brave.supportsJoin` | `true`| Support span joining|
| <a href="#bravetraceid128bit"><img src="images/click-me.png" width="14" height="14"/></a> `brave.traceId128Bit` | `false`| Use 128-bit trace IDs|

### Health & Shutdown

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#uaashutdownsleep"><img src="images/click-me.png" width="14" height="14"/></a> `uaa.shutdown.sleep` | `10000`| Shutdown sleep time (ms)|
| <a href="#uaahealthdbrate"><img src="images/click-me.png" width="14" height="14"/></a> `uaa.health.db.rate` | `10000`| DB health check interval (ms)|
| <a href="#deleteexpirationruntime"><img src="images/click-me.png" width="14" height="14"/></a> `delete.expirationRunTime` | `2500`| Token expiration cleanup timeout (ms)|

### Limited Mode

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#uaalimitedfunctionalitystatusfile"><img src="images/click-me.png" width="14" height="14"/></a> `uaa.limitedFunctionality.statusFile` | — (null)| Limited mode status file|
| <a href="#uaalimitedfunctionalitywhitelistendpoints"><img src="images/click-me.png" width="14" height="14"/></a> `uaa.limitedFunctionality.whitelist.endpoints` | `{}`| Whitelisted endpoints|
| <a href="#uaalimitedfunctionalitywhitelistmethods"><img src="images/click-me.png" width="14" height="14"/></a> `uaa.limitedFunctionality.whitelist.methods` | `{}`| Whitelisted HTTP methods|

### Metrics

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#metricsenabled"><img src="images/click-me.png" width="14" height="14"/></a> `metrics.enabled` | `true`| Enable metrics collection|
| <a href="#metricsperrequestmetrics"><img src="images/click-me.png" width="14" height="14"/></a> `metrics.perRequestMetrics` | `false`| Per-request metrics|

### Zone Paths

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#zonespathsenabled"><img src="images/click-me.png" width="14" height="14"/></a> `zones.paths.enabled` | `false`| Enable zone path routing|
| <a href="#zonesinternalhostnames"><img src="images/click-me.png" width="14" height="14"/></a> `zones.internal.hostnames` | `[]`| Hostnames for default zone|

### CSP (Content Security Policy)

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#cspscript-src"><img src="images/click-me.png" width="14" height="14"/></a> `csp.script-src` | `['self']`| CSP script-src directive|

### Miscellaneous

| Property | Default | Description |
|----------|---------|-------------|
| <a href="#loggingfilenamepath"><img src="images/click-me.png" width="14" height="14"/></a> `logging.file.name.path` | —| Log file directory|

---

## Detailed Property Descriptions

---

### `issuer.uri`

**Default:** — (required, no default)
**Source:** `@Value("${issuer.uri}")` in [`TokenEndpointBuilder`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/TokenEndpointBuilder.java), [`OpenIdConnectEndpoints`](../server/src/main/java/org/cloudfoundry/identity/uaa/account/OpenIdConnectEndpoints.java)
**Type:** `String`

The URI that identifies this UAA instance as an OAuth 2.0 / OIDC token issuer. This value appears
in the `iss` claim of all tokens issued by the UAA and in the OpenID Connect discovery document.
It must be a fully-qualified URL (e.g. `http://localhost:8080/uaa`).

[Back to table](#core--general)

---

### `uaa.url`

**Default:** `http://localhost:8080/uaa`
**Source:** `@ConfigurationProperties(prefix = "uaa")` in [`UaaProperties.Uaa`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java), `@Value("${uaa.url}")` in multiple beans
**Type:** `String`

The externally-reachable URL of the UAA. Used for constructing token endpoint URLs, JWKS URIs,
and other self-referencing links in API responses.

[Back to table](#core--general)

---

### `login.url`

**Default:** `http://localhost:8080/uaa`
**Source:** `@Value("${login.url:http://localhost:8080/uaa}")` in [`MessagingConfig`](../server/src/main/java/org/cloudfoundry/identity/uaa/login/MessagingConfig.java), [`SpringServletXmlBeansConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/SpringServletXmlBeansConfiguration.java)
**Type:** `String`

The base URL of the login server. Used in email templates (e.g. password reset links) and
other contexts where the login page URL is needed. Typically the same as `uaa.url`.

[Back to table](#core--general)

---

### `spring_profiles`

**Default:** — (none)
**Source:** Mapped to Spring active profiles
**Type:** `String` (comma-separated)

Controls which Spring profiles are active. Common values:
- `hsqldb` — in-memory HSQLDB (default for testing)
- `postgresql` — PostgreSQL database
- `mysql` — MySQL/MariaDB database
- `ldap` — Enable LDAP authentication
- `saml` — Enable SAML support

Multiple profiles can be combined, e.g. `postgresql,ldap`.

[Back to table](#core--general)

---

### `require_https`

**Default:** `false`
**Source:** `@ConfigurationProperties` in [`UaaProperties.RootLevel`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `boolean`

When `true`, various UAA cookies will have the `Secure` attribute set. Should be `true` in
production when the UAA is served over HTTPS.

[Back to table](#core--general)

---

### `https_port`

**Default:** `443`
**Source:** `@ConfigurationProperties` in [`UaaProperties.RootLevel`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `int`

The HTTPS port for the UAA server. Used in redirect calculations when HTTPS is required.

[Back to table](#core--general)

---

### `LOGIN_SECRET`

**Default:** `loginsecret`
**Source:** `@ConfigurationProperties` in [`UaaProperties.RootLevel`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `String`

The shared secret that an external login server uses to authenticate to the UAA via the `login`
client. Each deployment should set a unique value.

[Back to table](#core--general)

---

### `dump_requests`

**Default:** `false`
**Source:** `@ConfigurationProperties` in [`UaaProperties.RootLevel`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `boolean`

When `true`, logs full HTTP request details for debugging. Should never be `true` in production.

[Back to table](#core--general)

---

### `environmentYamlKey`

**Default:** — (injected internally)
**Source:** `@Value("${environmentYamlKey}")` in [`SpringServletXmlBeansConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/SpringServletXmlBeansConfiguration.java)
**Type:** `String`

An internal property holding the full YAML configuration string. Used by the
`YamlConfigurationValidator` to validate configuration structure at startup.

[Back to table](#core--general)

---

### `disableInternalAuth`

**Default:** `false`
**Source:** Referenced in [`uaa.yml`](../uaa/src/main/resources/uaa.yml) comments, checked via `@config['disableInternalAuth']`
**Type:** `boolean`

When `true`, authentication via the UAA's internal identity provider (IDP) is disabled.
Users must then authenticate via external IDPs (LDAP, SAML, OAuth/OIDC).

[Back to table](#core--general)

---

### `disableInternalUserManagement`

**Default:** `false`
**Source:** `@config['disableInternalUserManagement']` in [`SpringServletXmlBeansConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/SpringServletXmlBeansConfiguration.java)
**Type:** `boolean`

When `true`, disables user management endpoints and controllers for the internal IDP.
Operations like creating internal users, changing passwords, etc. will be blocked.

[Back to table](#core--general)

---

### `allowUnverifiedUsers`

**Default:** `true`
**Source:** `@Value("${allowUnverifiedUsers:true}")` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `boolean`

When `true`, users who have not verified their email can still log in.
Set to `false` to require email verification before allowing authentication.

[Back to table](#core--general)

---

### `database.driverClassName`

**Default:** Determined by active profile (`hsqldb`, `postgresql`, or `mysql`)
**Source:** `@ConfigurationProperties(prefix = "database")` in [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `String`

The fully-qualified JDBC driver class name. Typically auto-resolved from the active profile:
- HSQLDB: `org.hsqldb.jdbc.JDBCDriver`
- PostgreSQL: `org.postgresql.Driver`
- MySQL: `org.mariadb.jdbc.Driver`

[Back to table](#database)

---

### `database.url`

**Default:** Determined by active profile
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `String`

JDBC connection URL for the UAA database (e.g. `jdbc:postgresql://localhost/uaa`).

[Back to table](#database)

---

### `database.username`

**Default:** — (none)
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `String`

Database connection username.

[Back to table](#database)

---

### `database.password`

**Default:** — (none)
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `String`

Database connection password.

[Back to table](#database)

---

### `database.maxactive`

**Default:** `100`
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `int`

Maximum number of active connections in the connection pool.

[Back to table](#database)

---

### `database.maxidle`

**Default:** `10`
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `int`

Maximum number of idle connections in the pool.

[Back to table](#database)

---

### `database.minidle`

**Default:** `0`
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `int`

Minimum number of idle connections maintained in the pool.

[Back to table](#database)

---

### `database.maxwait`

**Default:** `30000`
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `int`

Maximum time (in milliseconds) to wait for a connection from the pool before throwing an exception.

[Back to table](#database)

---

### `database.initialsize`

**Default:** `10`
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `int`

Initial number of connections created when the pool starts.

[Back to table](#database)

---

### `database.validationquerytimeout`

**Default:** `10`
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `int`

Timeout (in seconds) for the validation query.

[Back to table](#database)

---

### `database.validationinterval`

**Default:** `5000`
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `long`

Interval (in milliseconds) between connection validation checks.

[Back to table](#database)

---

### `database.connecttimeout`

**Default:** `10`
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `Integer`

Connection timeout (in seconds) for establishing a new database connection.

[Back to table](#database)

---

### `database.testwhileidle`

**Default:** `false`
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `boolean`

When `true`, idle connections are validated periodically.

[Back to table](#database)

---

### `database.removedAbandoned`

**Default:** `false`
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `boolean`

When `true`, connections that have been abandoned (not returned to the pool) are reclaimed.

[Back to table](#database)

---

### `database.logabandoned`

**Default:** `true`
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `boolean`

When `true`, logs a stack trace for abandoned connections to help identify leaks.

[Back to table](#database)

---

### `database.abandonedtimeout`

**Default:** `300`
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `int`

Time (in seconds) after which a connection is considered abandoned.

[Back to table](#database)

---

### `database.evictionintervalms`

**Default:** `15000`
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `int`

Interval (in milliseconds) between eviction runs that remove idle connections.

[Back to table](#database)

---

### `database.minevictionidlems`

**Default:** `60000`
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `int`

Minimum time (in milliseconds) a connection can sit idle before being eligible for eviction.

[Back to table](#database)

---

### `database.caseinsensitive`

**Default:** `false`
**Source:** [`DatabaseProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/db/beans/DatabaseProperties.java)
**Type:** `boolean`

When `true`, enables case-insensitive queries for username lookups. This affects how
users are searched and matched in the database.

[Back to table](#database)

---

### `database.useSkipLocked`

**Default:** `false`
**Source:** `@Value("${database.useSkipLocked:false}")` in [`JdbcUaaUserDatabase`](../server/src/main/java/org/cloudfoundry/identity/uaa/user/JdbcUaaUserDatabase.java)
**Type:** `boolean`

When `true`, uses the `SKIP LOCKED` clause in SQL queries to avoid lock contention.
Supported by PostgreSQL and MySQL 8+.

[Back to table](#database)

---

### `database.maxParameters`

**Default:** `-1` (unlimited)
**Source:** `@Value("${database.maxParameters:-1}")` in [`JdbcUaaUserDatabase`](../server/src/main/java/org/cloudfoundry/identity/uaa/user/JdbcUaaUserDatabase.java), [`JdbcScimGroupMembershipManager`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/jdbc/JdbcScimGroupMembershipManager.java)
**Type:** `int`

Maximum number of SQL parameters allowed in IN clauses. `-1` means no limit.
Use this to work around database driver parameter limits.

[Back to table](#database)

---

### `servlet.session-store`

**Default:** `memory`
**Source:** [`UaaSessionConfig`](../server/src/main/java/org/cloudfoundry/identity/uaa/web/beans/UaaSessionConfig.java) (reads `servlet.session-store` from environment)
**Type:** `String`

The session storage mechanism. Accepted values:
- `memory` — In-memory sessions (default, suitable for multi-instance deployments that support sticky sessions)
- `database` — Database-backed sessions via Spring Session JDBC

[Back to table](#servlet--session)

---

### `servlet.session-cookie.encode-base64`

**Default:** `true`
**Source:** `@ConfigurationProperties(prefix = "servlet")` in [`UaaProperties.Servlet`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `boolean`

When `true`, the session cookie value is Base64-encoded. Helps with cookie compatibility
across different web servers and proxies.

[Back to table](#servlet--session)

---

### `servlet.session-cookie.max-age`

**Default:** — (null, session cookie)
**Source:** [`UaaProperties.SessionCookie`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `Integer` (nullable)

Maximum age of the session cookie in seconds. When null, the cookie is a session cookie
(expires when the browser closes).

[Back to table](#servlet--session)

---

### `servlet.idle-timeout`

**Default:** `1800`
**Source:** `@ConfigurationProperties(prefix = "servlet")` in [`UaaProperties.Servlet`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `int`

Session idle timeout in seconds. After this period of inactivity, the session expires.

[Back to table](#servlet--session)

---

### `servlet.filtered-headers`

**Default:** `[X-Forwarded-For, X-Forwarded-Host, X-Forwarded-Proto, X-Forwarded-Prefix, Forwarded]`
**Source:** `@ConfigurationProperties(prefix = "servlet")` in [`UaaProperties.Servlet`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `List<String>`

HTTP headers that the UAA's request filter will process. These are typically proxy headers
used to determine the original client request details.

[Back to table](#servlet--session)

---

### `jwt.token.signing-key`

**Default:** — (null)
**Source:** `@Value("${jwt.token.signing-key:#{null}}")` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `String`

Legacy property for specifying a single token signing key (RSA private key in PEM format or
symmetric key). Prefer using `jwt.token.policy.keys` instead for key rotation support.

[Back to table](#jwt-token-policy)

---

### `jwt.token.signing-alg`

**Default:** — (null)
**Source:** `@Value("${jwt.token.signing-alg:#{null}}")` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `String`

Legacy signing algorithm override (e.g. `RS256`, `HS256`). Prefer using
`jwt.token.policy.keys[].signingAlg` instead.

[Back to table](#jwt-token-policy)

---

### `jwt.token.signing-cert`

**Default:** — (null)
**Source:** `@Value("${jwt.token.signing-cert:#{null}}")` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `String`

Legacy signing certificate (X.509 in PEM format) for the signing key. Used as the
verification certificate for RS256 tokens when provided.

[Back to table](#jwt-token-policy)

---

### `jwt.token.revocable`

**Default:** `false`
**Source:** `@Value("${jwt.token.revocable:false}")` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `boolean`

When `true`, all JWT access tokens issued by the default zone are stored in the revocable
token store, allowing them to be revoked before expiration.

[Back to table](#jwt-token-policy)

---

### `jwt.token.queryString.enabled`

**Default:** `true`
**Source:** `@Value("${jwt.token.queryString.enabled:true}")` in [`SpringServletXmlBeansConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/SpringServletXmlBeansConfiguration.java)
**Type:** `boolean`

When `true`, allows access tokens to be passed via query string parameters.
Disable for increased security (tokens in query strings may be logged).

[Back to table](#jwt-token-policy)

---

### `jwt.token.policy.activeKeyId`

**Default:** — (null)
**Source:** `@Value("${jwt.token.policy.activeKeyId:#{null}}")` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `String`

The key ID of the currently active signing key from the `jwt.token.policy.keys` map.
Tokens are signed with this key. Other keys in the map remain valid for verification,
enabling key rotation.

[Back to table](#jwt-token-policy)

---

### `jwt.token.policy.keys`

**Default:** `{}` (empty map)
**Source:** `@config['jwt.token.policy.keys']` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `Map<String, Map<String, String>>`

A map of key IDs to signing key configurations. Each entry has:
- `signingKey` — RSA private key in PEM format
- `signingAlg` — Algorithm (e.g. `RS256`)

```yaml
jwt:
  token:
    policy:
      activeKeyId: key-id-1
      keys:
        key-id-1:
          signingAlg: RS256
          signingKey: |
            -----BEGIN PRIVATE KEY-----
            ...
            -----END PRIVATE KEY-----
```

[Back to table](#jwt-token-policy)

---

### `jwt.token.policy.accessTokenValiditySeconds`

**Default:** Falls back to `jwt.token.policy.global.accessTokenValiditySeconds`
**Source:** `@Value` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `int`

Access token lifetime in seconds for the default identity zone. Overrides the global value.

[Back to table](#jwt-token-policy)

---

### `jwt.token.policy.refreshTokenValiditySeconds`

**Default:** Falls back to `jwt.token.policy.global.refreshTokenValiditySeconds`
**Source:** `@Value` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `int`

Refresh token lifetime in seconds for the default identity zone. Overrides the global value.

[Back to table](#jwt-token-policy)

---

### `jwt.token.policy.global.accessTokenValiditySeconds`

**Default:** `43200` (12 hours)
**Source:** `@Value("${jwt.token.policy.global.accessTokenValiditySeconds:43200}")` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `int`

Global default for access token lifetime in seconds. Applies to all zones unless overridden.

[Back to table](#jwt-token-policy)

---

### `jwt.token.policy.global.refreshTokenValiditySeconds`

**Default:** `2592000` (30 days)
**Source:** `@Value("${jwt.token.policy.global.refreshTokenValiditySeconds:2592000}")` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `int`

Global default for refresh token lifetime in seconds. Applies to all zones unless overridden.

[Back to table](#jwt-token-policy)

---

### `jwt.token.refresh.format`

**Default:** `opaque`
**Source:** `@Value` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `String`

Format of issued refresh tokens. Accepted values:
- `opaque` — Opaque, randomly generated token stored in the database
- `jwt` — Self-contained JWT refresh token

[Back to table](#jwt-token-policy)

---

### `jwt.token.refresh.unique`

**Default:** `false`
**Source:** `@Value("${jwt.token.refresh.unique:false}")` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `boolean`

When `true`, only one refresh token can exist per user/client combination. Issuing a new
refresh token invalidates the previous one.

[Back to table](#jwt-token-policy)

---

### `jwt.token.refresh.rotate`

**Default:** `false`
**Source:** `@Value("${jwt.token.refresh.rotate:false}")` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `boolean`

When `true`, a new refresh token is issued each time the current refresh token is used
to obtain a new access token (refresh token rotation).

[Back to table](#jwt-token-policy)

---

### `jwt.token.refresh.restrict_grant`

**Default:** — (not set)
**Source:** Referenced in [`uaa.yml`](../uaa/src/main/resources/uaa.yml) comments
**Type:** `boolean`

When `true`, refresh tokens are only granted to clients that have `refresh_token`
in their scopes for offline access.

[Back to table](#jwt-token-policy)

---

### `jwt.token.claims.exclude`

**Default:** `[]` (empty set)
**Source:** `@config['jwt.token.claims.exclude']` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `List<String>`

A list of claim names to exclude from issued JWT tokens. For example, to omit
the `authorities` claim: `exclude: [authorities]`.

[Back to table](#jwt-token-policy)

---

### `oauth.clients`

**Default:** `{}` (empty)
**Source:** Loaded via `@config['oauth']['clients']`
**Type:** `Map<String, OAuthClientConfig>`

Bootstrap client definitions loaded at startup. Each entry is keyed by client ID and contains:
- `id` — Client ID
- `secret` — Client secret
- `authorized-grant-types` — Comma-separated grant types
- `scope` — Comma-separated scopes
- `authorities` — Comma-separated authorities
- `redirect-uri` — Comma-separated redirect URIs
- `autoapprove` — Auto-approved scopes
- `allowpublic` — Allow public (no secret) auth
- `jwks` — Inline JWKS for private_key_jwt auth
- `jwks_uri` — URI to fetch JWKS
- `name` — Display name

[Back to table](#oauth-clients--users)

---

### `oauth.client.override`

**Default:** — (not set)
**Source:** [`UaaConfiguration.OAuth.Client`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/UaaConfiguration.java)
**Type:** `String` (boolean-like)

When `true`, existing OAuth clients are overwritten on bootstrap with the values
defined in the configuration file.

[Back to table](#oauth-clients--users)

---

### `oauth.client.autoapprove`

**Default:** `[]`
**Source:** [`UaaConfiguration.OAuth.Client`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/UaaConfiguration.java)
**Type:** `List<String>`

List of client IDs that are auto-approved for all scopes (user consent is not requested).

[Back to table](#oauth-clients--users)

---

### `oauth.user.authorities`

**Default:** `[openid, scim.me, cloud_controller.read, cloud_controller.write, cloud_controller_service_permissions.read, password.write, scim.userids, uaa.user, approvals.me, oauth.approvals, profile, roles, user_attributes, uaa.offline_token]`
**Source:** `@config['oauth']['user']['authorities']` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `List<String>`

Default authorities (group memberships) automatically assigned to every new user.

[Back to table](#oauth-clients--users)

---

### `clientMaxCount`

**Default:** `500`
**Source:** `@Value("${clientMaxCount:500}")` in [`ClientAdminEndpoints`](../server/src/main/java/org/cloudfoundry/identity/uaa/client/ClientAdminEndpoints.java)
**Type:** `int`

Maximum number of clients returned in a single list/search response from the
client admin API (`/oauth/clients`).

[Back to table](#oauth-clients--users)

---

### `password.policy.global.minLength`

**Default:** `0`
**Source:** `@Value("${password.policy.global.minLength:0}")` in [`ScimBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/beans/ScimBeanConfiguration.java)
**Type:** `int`

Global minimum password length. Applies across all zones unless overridden.
Set to `0` to impose no minimum.

[Back to table](#password-policy)

---

### `password.policy.global.maxLength`

**Default:** `255`
**Source:** `@Value("${password.policy.global.maxLength:255}")` in [`ScimBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/beans/ScimBeanConfiguration.java)
**Type:** `int`

Global maximum password length.

[Back to table](#password-policy)

---

### `password.policy.global.requireUpperCaseCharacter`

**Default:** `0`
**Source:** `@Value` in [`ScimBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/beans/ScimBeanConfiguration.java)
**Type:** `int`

Global minimum number of uppercase characters required. `0` means not enforced.

[Back to table](#password-policy)

---

### `password.policy.global.requireLowerCaseCharacter`

**Default:** `0`
**Source:** `@Value` in [`ScimBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/beans/ScimBeanConfiguration.java)
**Type:** `int`

Global minimum number of lowercase characters required.

[Back to table](#password-policy)

---

### `password.policy.global.requireDigit`

**Default:** `0`
**Source:** `@Value` in [`ScimBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/beans/ScimBeanConfiguration.java)
**Type:** `int`

Global minimum number of digit characters required.

[Back to table](#password-policy)

---

### `password.policy.global.requireSpecialCharacter`

**Default:** `0`
**Source:** `@Value` in [`ScimBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/beans/ScimBeanConfiguration.java)
**Type:** `int`

Global minimum number of special characters required.

[Back to table](#password-policy)

---

### `password.policy.global.expirePasswordInMonths`

**Default:** `0` (no expiry)
**Source:** `@Value` in [`ScimBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/beans/ScimBeanConfiguration.java)
**Type:** `int`

Number of months before a password expires globally. `0` means passwords never expire.

[Back to table](#password-policy)

---

### `password.policy.minLength`

**Default:** Falls back to `password.policy.global.minLength`
**Source:** `@Value("${password.policy.minLength:#{globalPasswordPolicy.getMinLength()}}")` in [`ScimBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/beans/ScimBeanConfiguration.java)
**Type:** `int`

Minimum password length for the default identity zone. Falls back to the global value if not set.

[Back to table](#password-policy)

---

### `password.policy.maxLength`

**Default:** Falls back to global
**Source:** `@Value` in [`ScimBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/beans/ScimBeanConfiguration.java)
**Type:** `int`

Maximum password length for the default identity zone.

[Back to table](#password-policy)

---

### `password.policy.requireUpperCaseCharacter`

**Default:** Falls back to global
**Source:** `@Value` in [`ScimBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/beans/ScimBeanConfiguration.java)
**Type:** `int`

Required uppercase characters for the default zone.

[Back to table](#password-policy)

---

### `password.policy.requireLowerCaseCharacter`

**Default:** Falls back to global
**Source:** `@Value` in [`ScimBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/beans/ScimBeanConfiguration.java)
**Type:** `int`

Required lowercase characters for the default zone.

[Back to table](#password-policy)

---

### `password.policy.requireDigit`

**Default:** Falls back to global
**Source:** `@Value` in [`ScimBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/beans/ScimBeanConfiguration.java)
**Type:** `int`

Required digits for the default zone.

[Back to table](#password-policy)

---

### `password.policy.requireSpecialCharacter`

**Default:** Falls back to global
**Source:** `@Value` in [`ScimBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/beans/ScimBeanConfiguration.java)
**Type:** `int`

Required special characters for the default zone.

[Back to table](#password-policy)

---

### `password.policy.expirePasswordInMonths`

**Default:** Falls back to global
**Source:** `@Value` in [`ScimBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/beans/ScimBeanConfiguration.java)
**Type:** `int`

Password expiry in months for the default zone.

[Back to table](#password-policy)

---

### `oauth.client.secret.policy.global.minLength`

**Default:** `0`
**Source:** `@ConfigurationProperties(prefix = "oauth.client.secret.policy.global")` in [`UaaProperties.GlobalClientSecretPolicy`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `int`

Global minimum length for client secrets. Applies across all zones unless overridden.

[Back to table](#client-secret-policy)

---

### `oauth.client.secret.policy.global.maxLength`

**Default:** `255`
**Source:** [`UaaProperties.GlobalClientSecretPolicy`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `int`

Global maximum length for client secrets.

[Back to table](#client-secret-policy)

---

### `oauth.client.secret.policy.global.requireUpperCaseCharacter`

**Default:** `0`
**Source:** [`UaaProperties.GlobalClientSecretPolicy`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `int`

Global minimum uppercase chars for client secrets.

[Back to table](#client-secret-policy)

---

### `oauth.client.secret.policy.global.requireLowerCaseCharacter`

**Default:** `0`
**Source:** [`UaaProperties.GlobalClientSecretPolicy`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `int`

Global minimum lowercase chars for client secrets.

[Back to table](#client-secret-policy)

---

### `oauth.client.secret.policy.global.requireDigit`

**Default:** `0`
**Source:** [`UaaProperties.GlobalClientSecretPolicy`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `int`

Global minimum digits for client secrets.

[Back to table](#client-secret-policy)

---

### `oauth.client.secret.policy.global.requireSpecialCharacter`

**Default:** `0`
**Source:** [`UaaProperties.GlobalClientSecretPolicy`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `int`

Global minimum special characters for client secrets.

[Back to table](#client-secret-policy)

---

### `oauth.client.secret.policy.global.expireSecretInMonths`

**Default:** `0` (no expiry)
**Source:** [`UaaProperties.GlobalClientSecretPolicy`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `int`

Number of months before a client secret expires.

[Back to table](#client-secret-policy)

---

### `oauth.client.secret.policy.minLength`

**Default:** Falls back to global
**Source:** [`UaaProperties.DefaultClientSecretPolicy`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `int`

Default zone min client secret length. If set to `-1` (or not set), the global value is used.

[Back to table](#client-secret-policy)

---

### `oauth.client.secret.policy.maxLength`

**Default:** Falls back to global
**Source:** [`UaaProperties.DefaultClientSecretPolicy`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `int`

Default zone max client secret length. If `-1`, uses global.

[Back to table](#client-secret-policy)

---

### `authentication.policy.global.lockoutAfterFailures`

**Default:** `5`
**Source:** `@Value("${authentication.policy.global.lockoutAfterFailures:5}")` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `int`

Global number of consecutive failed login attempts before locking the account.

[Back to table](#authentication--lockout-policy)

---

### `authentication.policy.global.countFailuresWithinSeconds`

**Default:** `1200` (20 minutes)
**Source:** `@Value("${authentication.policy.global.countFailuresWithinSeconds:1200}")` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `int`

Global time window (in seconds) during which failed attempts are counted toward lockout.

[Back to table](#authentication--lockout-policy)

---

### `authentication.policy.global.lockoutPeriodSeconds`

**Default:** `300` (5 minutes)
**Source:** `@Value("${authentication.policy.global.lockoutPeriodSeconds:300}")` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `int`

Global duration (in seconds) for which an account remains locked after exceeding the failure threshold.

[Back to table](#authentication--lockout-policy)

---

### `authentication.policy.lockoutAfterFailures`

**Default:** Falls back to global
**Source:** `@Value` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `int`

Default zone lockout failure threshold. Falls back to global if not specified.

[Back to table](#authentication--lockout-policy)

---

### `authentication.policy.countFailuresWithinSeconds`

**Default:** Falls back to global
**Source:** `@Value` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `int`

Default zone failure counting window.

[Back to table](#authentication--lockout-policy)

---

### `authentication.policy.lockoutPeriodSeconds`

**Default:** Falls back to global
**Source:** `@Value` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `int`

Default zone lockout duration.

[Back to table](#authentication--lockout-policy)

---

### `authentication.enableUriEncodingCompatibilityMode`

**Default:** `false`
**Source:** `@Value("${authentication.enableUriEncodingCompatibilityMode:false}")` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `boolean`

Enables a backward-compatible URI encoding mode for client authentication. When `true`,
client credentials are decoded using a legacy algorithm for compatibility with older clients.

[Back to table](#authentication--lockout-policy)

---

### `scim.users`

**Default:** `[]` (empty)
**Source:** `@config['scim']['users']` in [`ScimBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/beans/ScimBeanConfiguration.java)
**Type:** `List<String>`

Bootstrap users created at startup. Each entry is a pipe-delimited string:
`username|password|email|firstName|lastName|groups[|origin]`

Example:
```yaml
scim:
  users:
    - admin|admin|admin@example.com|Admin|User|uaa.admin
    - marissa|koala|marissa@test.org|Marissa|Bloggs|uaa.user
```

[Back to table](#scim-user-provisioning)

---

### `scim.groups`

**Default:** `{}`
**Source:** Loaded via `@config['scim']['groups']`
**Type:** `Map<String, String>`

Bootstrap groups created at startup. Keys are group names, values are human-readable descriptions.
These groups are created in the default identity zone.

```yaml
scim:
  groups:
    scim.read: Read all SCIM entities
    scim.write: Create, modify and delete SCIM entities
```

[Back to table](#scim-user-provisioning)

---

### `scim.external_groups`

**Default:** `[]`
**Source:** Loaded via config map
**Type:** `List<String>`

Mappings from external (LDAP) groups to internal UAA groups. Each entry is pipe-delimited:
`internal_group|external_group_dn`

```yaml
scim:
  external_groups:
    - internal.read|cn=developers,ou=scopes,dc=test,dc=com
```

[Back to table](#scim-user-provisioning)

---

### `scim.userids_enabled`

**Default:** `true`
**Source:** `@Value("${scim.userids_enabled:true}")` in [`UserIdConversionEndpoints`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/endpoints/UserIdConversionEndpoints.java)
**Type:** `boolean`

Enables the `/ids/Users` endpoint for converting usernames to user IDs.

[Back to table](#scim-user-provisioning)

---

### `scim.user.override`

**Default:** `false`
**Source:** `@Value("${scim.user.override:false}")` in [`ScimBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/beans/ScimBeanConfiguration.java)
**Type:** `boolean`

When `true`, bootstrap users defined in `scim.users` overwrite existing users with the same
username on every startup.

[Back to table](#scim-user-provisioning)

---

### `scim.delete.deactivate`

**Default:** `false`
**Source:** `@Value("${scim.delete.deactivate:false}")` in [`JdbcScimUserProvisioning`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/jdbc/JdbcScimUserProvisioning.java)
**Type:** `boolean`

When `true`, SCIM user DELETE operations deactivate the user (set `active=false`) instead
of permanently deleting the record.

[Back to table](#scim-user-provisioning)

---

### `userMaxCount`

**Default:** `500`
**Source:** `@Value("${userMaxCount:500}")` in [`ScimUserEndpoints`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/endpoints/ScimUserEndpoints.java)
**Type:** `int`

Maximum number of users returned in a single list/search response from the SCIM Users API.

[Back to table](#scim-user-provisioning)

---

### `groupMaxCount`

**Default:** `500`
**Source:** `@Value("${groupMaxCount:500}")` in [`ScimGroupEndpoints`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/endpoints/ScimGroupEndpoints.java)
**Type:** `int`

Maximum number of groups returned in a single list/search response from the SCIM Groups API.

[Back to table](#scim-user-provisioning)

---

### `delete.users`

**Default:** — (null)
**Source:** `@Value("${delete.users:#{null}}")` in [`ScimBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/scim/beans/ScimBeanConfiguration.java)
**Type:** `List<String>`

List of usernames to delete on bootstrap. Used to remove specific users during startup.

[Back to table](#scim-user-provisioning)

---

### `login.selfServiceLinksEnabled`

**Default:** `true`
**Source:** `@ConfigurationProperties(prefix = "login")` in [`UaaProperties.Login`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `boolean`

When `true`, "Create Account" and "Forgot Password" links are displayed on the login page.

[Back to table](#login--branding)

---

### `login.homeRedirect`

**Default:** — (null)
**Source:** [`UaaProperties.Login`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `String`

URL to redirect to after successful login if no redirect was requested.

[Back to table](#login--branding)

---

### `login.idpDiscoveryEnabled`

**Default:** `false`
**Source:** [`UaaProperties.Login`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `boolean`

When `true`, the login page first asks for the user's email to discover which
identity provider (IDP) should be used for authentication.

[Back to table](#login--branding)

---

### `login.accountChooserEnabled`

**Default:** `false`
**Source:** [`UaaProperties.Login`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `boolean`

When `true`, users see an account chooser UI that lets them pick from previously used accounts.

[Back to table](#login--branding)

---

### `login.entityBaseURL`

**Default:** `http://localhost:8080/uaa`
**Source:** `@Value("${login.entityBaseURL:http://localhost:8080/uaa}")` in [`SpringServletXmlBeansConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/SpringServletXmlBeansConfiguration.java), [`SamlRelyingPartyRegistrationRepositoryConfig`](../server/src/main/java/org/cloudfoundry/identity/uaa/provider/saml/SamlRelyingPartyRegistrationRepositoryConfig.java)
**Type:** `String`

The base URL of this UAA instance for SAML SP metadata generation. This URL appears in the
SAML metadata as the service provider's base location. When `null`, UAA uses the request URL,
which enables automatic zone subdomain resolution.

[Back to table](#login--branding)

---

### `login.entityID`

**Default:** `unit-test-sp` (production deployments should override)
**Source:** `@Value("${login.entityID:unit-test-sp}")` in [`SamlConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/provider/saml/SamlConfiguration.java)
**Type:** `String`

The SAML entity ID (issuer name) for this UAA instance as a SAML Service Provider.
This value is declared in SAML SP metadata as the `entityID` attribute.

[Back to table](#login--branding)

---

### `login.prompt.username.text`

**Default:** `Email`
**Source:** `@Value("${login.prompt.username.text:Email}")` in [`SpringServletXmlBeansConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/SpringServletXmlBeansConfiguration.java)
**Type:** `String`

The label text displayed for the username input field on the login page.

[Back to table](#login--branding)

---

### `login.prompt.password.text`

**Default:** `Password`
**Source:** `@Value("${login.prompt.password.text:Password}")` in [`SpringServletXmlBeansConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/SpringServletXmlBeansConfiguration.java)
**Type:** `String`

The label text displayed for the password input field on the login page.

[Back to table](#login--branding)

---

### `login.branding`

**Default:** — (null)
**Source:** [`UaaProperties.Login`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `Map<String, Object>`

Customizes the visual branding of the login UI. Supports the following sub-keys:
- `companyName` — Company name displayed in the UI
- `productLogo` — Base64-encoded product logo image
- `squareLogo` — Base64-encoded square logo
- `footerLegalText` — Legal text in the footer
- `footerLinks` — Map of link names to URLs
- `banner.logo` — Base64-encoded banner logo
- `banner.text` — Banner text
- `banner.textColor` — Banner text color (hex)
- `banner.backgroundColor` — Banner background color (hex)
- `banner.link` — Banner link URL

[Back to table](#login--branding)

---

### `login.defaultIdentityProvider`

**Default:** — (null)
**Source:** [`UaaProperties.Login`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `String`

When set, automatically routes users to the specified IDP origin key, skipping the login page.

[Back to table](#login--branding)

---

### `login.allowedGroups`

**Default:** — (null, no restriction)
**Source:** `@Value("${login.allowedGroups:#{null}}")` in [`SpringServletXmlBeansConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/SpringServletXmlBeansConfiguration.java)
**Type:** `List<String>`

When set, only users who are members of at least one of these groups can log in.
Null means no restriction.

[Back to table](#login--branding)

---

### `login.checkOriginEnabled`

**Default:** `false`
**Source:** `@Value("${login.checkOriginEnabled:false}")` in [`SpringServletXmlBeansConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/SpringServletXmlBeansConfiguration.java)
**Type:** `boolean`

When `true`, the UAA checks the user's origin during authentication to ensure it matches
the expected IDP.

[Back to table](#login--branding)

---

### `login.maxUsers`

**Default:** `-1` (unlimited)
**Source:** `@Value("${login.maxUsers:-1}")` in [`SpringServletXmlBeansConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/SpringServletXmlBeansConfiguration.java)
**Type:** `int`

Maximum number of users allowed in the system. `-1` means unlimited.

[Back to table](#login--branding)

---

### `login.allowOriginLoop`

**Default:** `true`
**Source:** `@Value("${login.allowOriginLoop:true}")` in [`SpringServletXmlBeansConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/SpringServletXmlBeansConfiguration.java)
**Type:** `boolean`

When `true`, allows redirect loops between origins during authentication flows.

[Back to table](#login--branding)

---

### `login.aliasEntitiesEnabled`

**Default:** `false`
**Source:** `@Value("${login.aliasEntitiesEnabled:false}")` in [`AliasEntitiesConfig`](../server/src/main/java/org/cloudfoundry/identity/uaa/alias/AliasEntitiesConfig.java)
**Type:** `boolean`

When `true`, enables identity provider and client alias entities across identity zones.

[Back to table](#login--branding)

---

### `login.oauth.providers`

**Default:** — (not set)
**Source:** `@config['login']['oauth']['providers']` in [`SpringServletXmlBeansConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/SpringServletXmlBeansConfiguration.java)
**Type:** `Map<String, Map>`

External OAuth 2.0 and OIDC provider definitions. Each provider entry includes:
- `type` — `oauth2.0` or `oidc1.0`
- `authUrl` / `discoveryUrl` — Authorization or discovery URL
- `tokenUrl` — Token endpoint
- `tokenKey` / `tokenKeyUrl` — Key for token verification
- `issuer` — Expected token issuer
- `scopes` — List of scopes to request
- `linkText` — Text for the login link
- `relyingPartyId` / `relyingPartySecret` — Client credentials
- `attributeMappings` — Attribute mapping configuration

[Back to table](#login--branding)

---

### `login.saml.activeKeyId`

**Default:** — (none)
**Source:** [`SamlConfigProps`](../server/src/main/java/org/cloudfoundry/identity/uaa/provider/saml/SamlConfigProps.java)
**Type:** `String`

The ID of the active key from the `login.saml.keys` map. SAML requests and metadata are
signed with this key.

[Back to table](#saml-service-provider)

---

### `login.saml.keys`

**Default:** `{}` (empty)
**Source:** [`SamlConfigProps`](../server/src/main/java/org/cloudfoundry/identity/uaa/provider/saml/SamlConfigProps.java)
**Type:** `Map<String, SamlKey>`

Map of key IDs to SAML key configurations. Each key has:
- `key` — RSA private key in PEM format
- `certificate` — X.509 certificate in PEM format
- `passphrase` — Optional key passphrase

[Back to table](#saml-service-provider)

---

### `login.saml.entityIDAlias`

**Default:** — (null, falls back to `login.entityID`)
**Source:** [`SamlConfigProps`](../server/src/main/java/org/cloudfoundry/identity/uaa/provider/saml/SamlConfigProps.java)
**Type:** `String`

Alias for the SAML SP entity ID. Used in SSO URLs like `/saml/SSO/alias/{entityIDAlias}`.
If not set, falls back to the host portion of `login.entityID`.

[Back to table](#saml-service-provider)

---

### `login.saml.nameID`

**Default:** `urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified`
**Source:** [`SamlConfigProps`](../server/src/main/java/org/cloudfoundry/identity/uaa/provider/saml/SamlConfigProps.java), `@Value("${login.saml.nameID:...}")` in [`SamlRelyingPartyRegistrationRepositoryConfig`](../server/src/main/java/org/cloudfoundry/identity/uaa/provider/saml/SamlRelyingPartyRegistrationRepositoryConfig.java)
**Type:** `String`

Default SAML NameID format requested in authentication requests.

[Back to table](#saml-service-provider)

---

### `login.saml.assertionConsumerIndex`

**Default:** `0`
**Source:** [`SamlConfigProps`](../server/src/main/java/org/cloudfoundry/identity/uaa/provider/saml/SamlConfigProps.java)
**Type:** `int`

The index of the Assertion Consumer Service (ACS) endpoint to use.

[Back to table](#saml-service-provider)

---

### `login.saml.signMetaData`

**Default:** `true`
**Source:** [`SamlConfigProps`](../server/src/main/java/org/cloudfoundry/identity/uaa/provider/saml/SamlConfigProps.java)
**Type:** `Boolean`

When `true`, the generated SAML SP metadata includes a signature. When `false`,
no signature is included in the metadata XML.

[Back to table](#saml-service-provider)

---

### `login.saml.signRequest`

**Default:** `true`
**Source:** [`SamlConfigProps`](../server/src/main/java/org/cloudfoundry/identity/uaa/provider/saml/SamlConfigProps.java)
**Type:** `Boolean`

When `true`, SAML authentication requests (AuthnRequest) sent to IDPs are signed.

[Back to table](#saml-service-provider)

---

### `login.saml.wantAssertionSigned`

**Default:** `true`
**Source:** [`SamlConfigProps`](../server/src/main/java/org/cloudfoundry/identity/uaa/provider/saml/SamlConfigProps.java)
**Type:** `Boolean`

When `true`, the SP metadata declares that it wants incoming SAML assertions to be signed.

[Back to table](#saml-service-provider)

---

### `login.saml.signatureAlgorithm`

**Default:** `SHA256`
**Source:** [`SamlConfigProps`](../server/src/main/java/org/cloudfoundry/identity/uaa/provider/saml/SamlConfigProps.java)
**Type:** `String`

Algorithm used for SAML signatures. Accepted values: `SHA1`, `SHA256`, `SHA512`.

[Back to table](#saml-service-provider)

---

### `login.saml.disableInResponseToCheck`

**Default:** `false`
**Source:** [`SamlConfigProps`](../server/src/main/java/org/cloudfoundry/identity/uaa/provider/saml/SamlConfigProps.java)
**Type:** `Boolean`

When `true`, the `InResponseTo` field in incoming SAML assertions is not validated.
Useful for IDP-initiated SSO flows.

[Back to table](#saml-service-provider)

---

### `login.saml.providers`

**Default:** — (not configured)
**Source:** [`SamlConfigProps`](../server/src/main/java/org/cloudfoundry/identity/uaa/provider/saml/SamlConfigProps.java) (via `EnvironmentAware`)
**Type:** `Map<String, Map<String, Object>>`

SAML Identity Provider definitions. Each entry is keyed by a provider alias and includes:
- `idpMetadata` — Inline metadata XML or URL to metadata
- `nameID` — NameID format for this IDP
- `assertionConsumerIndex` — ACS index for this IDP
- `metadataTrustCheck` — Validate metadata signature
- `showSamlLoginLink` — Show login link on login page
- `linkText` — Text for the login link
- `iconUrl` — Icon URL for the login link
- `addShadowUserOnLogin` — Create local user on first login
- `emailDomain` — Email domains for IDP discovery
- `externalGroupsWhitelist` — Allowed external groups
- `attributeMappings` — Attribute mapping configuration

[Back to table](#saml-service-provider)

---

### `login.serviceProviderKey`

**Default:** — (none)
**Source:** [`UaaProperties.Login`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java), [`SamlConfigProps`](../server/src/main/java/org/cloudfoundry/identity/uaa/provider/saml/SamlConfigProps.java) (deprecated since 77.20.0)
**Type:** `String`

Legacy property for the SAML SP private key. Use `login.saml.keys` instead.
The key, password, and certificate are grouped together:
- `login.serviceProviderKey` — RSA private key in PEM
- `login.serviceProviderKeyPassword` — Key passphrase
- `login.serviceProviderCertificate` — X.509 certificate in PEM

[Back to table](#saml-service-provider)

---

### `logout.redirect.url`

**Default:** `/login`
**Source:** `@ConfigurationProperties(prefix = "logout")` in [`UaaProperties.Logout`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `String`

URL to redirect to after logout. Relative URLs are resolved against the UAA base URL.

[Back to table](#logout)

---

### `logout.redirect.parameter.disable`

**Default:** `false`
**Source:** [`UaaProperties.LogoutRedirectParameter`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `boolean`

When `true`, the `redirect` query parameter on the logout endpoint is ignored.

[Back to table](#logout)

---

### `logout.redirect.parameter.whitelist`

**Default:** `[]` (empty, no restriction)
**Source:** [`UaaProperties.LogoutRedirectParameter`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `List<String>`

Allowed redirect URLs for the logout endpoint. If empty, all redirects are allowed.

```yaml
logout:
  redirect:
    parameter:
      whitelist:
        - https://app1.example.com/logout-success
        - https://app2.example.com/logout-success
```

[Back to table](#logout)

---

### `links.global.passwd`

**Default:** — (null, uses internal `/forgot_password`)
**Source:** `@Value("${links.global.passwd:#{null}}")` in [`SpringServletXmlBeansConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/SpringServletXmlBeansConfiguration.java)
**Type:** `String`

Custom URL for the "Forgot Password" link on the login page. When null, the UAA's internal
forgot-password flow is used.

[Back to table](#links)

---

### `links.global.signup`

**Default:** — (null, uses internal `/create_account`)
**Source:** `@Value("${links.global.signup:#{null}}")` in [`SpringServletXmlBeansConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/SpringServletXmlBeansConfiguration.java)
**Type:** `String`

Custom URL for the "Create Account" link on the login page. When null, the UAA's internal
account creation flow is used.

[Back to table](#links)

---

### `links.global.homeRedirect`

**Default:** — (null)
**Source:** `@Value("${links.global.homeRedirect:#{null}}")` in [`SpringServletXmlBeansConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/SpringServletXmlBeansConfiguration.java)
**Type:** `String`

URL to redirect to after login when no target redirect was specified.

[Back to table](#links)

---

### `cors.enforceSystemZonePolicyInAllZones`

**Default:** `false`
**Source:** `@Value("${cors.enforceSystemZonePolicyInAllZones:false}")` in [`CorsProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/CorsProperties.java)
**Type:** `boolean`

When `true`, the system (default) zone's CORS policy is enforced in all identity zones,
overriding per-zone CORS configurations.

[Back to table](#cors)

---

### `cors.default.max_age`

**Default:** `1728000` (20 days)
**Source:** `@Value("${cors.default.max_age:1728000}")` in [`CorsProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/CorsProperties.java)
**Type:** `int`

Maximum time (in seconds) a preflight response can be cached for default CORS requests.

[Back to table](#cors)

---

### `cors.default.allowed.uris`

**Default:** `[".*"]` (all URIs)
**Source:** [`CorsProperties.DefaultAllowed`](../server/src/main/java/org/cloudfoundry/identity/uaa/CorsProperties.java)
**Type:** `List<String>`

Regex patterns for URIs that allow CORS requests (non-XHR). Default permits all.

[Back to table](#cors)

---

### `cors.default.allowed.origins`

**Default:** `[".*"]` (all origins)
**Source:** [`CorsProperties.DefaultAllowed`](../server/src/main/java/org/cloudfoundry/identity/uaa/CorsProperties.java)
**Type:** `List<String>`

Regex patterns for allowed CORS origins (non-XHR).

[Back to table](#cors)

---

### `cors.default.allowed.headers`

**Default:** `[Accept, Authorization, Content-Type, Accept-Language, Content-Language]`
**Source:** [`CorsProperties.DefaultAllowed`](../server/src/main/java/org/cloudfoundry/identity/uaa/CorsProperties.java)
**Type:** `List<String>`

Allowed request headers for default CORS.

[Back to table](#cors)

---

### `cors.default.allowed.methods`

**Default:** `[GET, POST, PUT, OPTIONS, DELETE, PATCH]`
**Source:** [`CorsProperties.DefaultAllowed`](../server/src/main/java/org/cloudfoundry/identity/uaa/CorsProperties.java)
**Type:** `List<String>`

Allowed HTTP methods for default CORS.

[Back to table](#cors)

---

### `cors.default.allowed.credentials`

**Default:** `false`
**Source:** [`CorsProperties.DefaultAllowed`](../server/src/main/java/org/cloudfoundry/identity/uaa/CorsProperties.java)
**Type:** `boolean`

Whether default CORS responses include `Access-Control-Allow-Credentials: true`.

[Back to table](#cors)

---

### `cors.xhr.max_age`

**Default:** `1728000` (20 days)
**Source:** `@Value("${cors.xhr.max_age:1728000}")` in [`CorsProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/CorsProperties.java)
**Type:** `int`

Maximum preflight cache time for XHR CORS requests.

[Back to table](#cors)

---

### `cors.xhr.allowed.uris`

**Default:** `[".*"]`
**Source:** [`CorsProperties.XhrAllowed`](../server/src/main/java/org/cloudfoundry/identity/uaa/CorsProperties.java)
**Type:** `List<String>`

Regex patterns for URIs that allow XHR CORS requests.

[Back to table](#cors)

---

### `cors.xhr.allowed.origins`

**Default:** `[".*"]`
**Source:** [`CorsProperties.XhrAllowed`](../server/src/main/java/org/cloudfoundry/identity/uaa/CorsProperties.java)
**Type:** `List<String>`

Regex patterns for allowed XHR CORS origins.

[Back to table](#cors)

---

### `cors.xhr.allowed.headers`

**Default:** `[Accept, Authorization, Content-Type, Accept-Language, Content-Language, X-Requested-With]`
**Source:** [`CorsProperties.XhrAllowed`](../server/src/main/java/org/cloudfoundry/identity/uaa/CorsProperties.java)
**Type:** `List<String>`

Allowed request headers for XHR CORS. Includes `X-Requested-With` by default.

[Back to table](#cors)

---

### `cors.xhr.allowed.methods`

**Default:** `[GET, OPTIONS]`
**Source:** [`CorsProperties.XhrAllowed`](../server/src/main/java/org/cloudfoundry/identity/uaa/CorsProperties.java)
**Type:** `List<String>`

Allowed HTTP methods for XHR CORS. More restrictive than the default CORS policy.

[Back to table](#cors)

---

### `cors.xhr.allowed.credentials`

**Default:** `true`
**Source:** [`CorsProperties.XhrAllowed`](../server/src/main/java/org/cloudfoundry/identity/uaa/CorsProperties.java)
**Type:** `boolean`

Whether XHR CORS responses include `Access-Control-Allow-Credentials: true`.
Default is `true` for XHR.

[Back to table](#cors)

---

### `smtp.host`

**Default:** `localhost`
**Source:** `@ConfigurationProperties(prefix = "smtp")` in [`SmtpProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/SmtpProperties.java)
**Type:** `String`

SMTP server hostname for sending emails (account verification, password reset, etc.).

[Back to table](#smtp--notifications)

---

### `smtp.port`

**Default:** `25`
**Source:** [`SmtpProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/SmtpProperties.java)
**Type:** `int`

SMTP server port.

[Back to table](#smtp--notifications)

---

### `smtp.user`

**Default:** `""` (empty)
**Source:** [`SmtpProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/SmtpProperties.java)
**Type:** `String`

Username for SMTP authentication.

[Back to table](#smtp--notifications)

---

### `smtp.password`

**Default:** `""` (empty)
**Source:** [`SmtpProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/SmtpProperties.java)
**Type:** `String`

Password for SMTP authentication.

[Back to table](#smtp--notifications)

---

### `smtp.auth`

**Default:** `false`
**Source:** [`SmtpProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/SmtpProperties.java)
**Type:** `boolean`

When `true`, enables SMTP authentication using `smtp.user` and `smtp.password`.

[Back to table](#smtp--notifications)

---

### `smtp.starttls`

**Default:** `false`
**Source:** [`SmtpProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/SmtpProperties.java)
**Type:** `boolean`

When `true`, enables STARTTLS encryption for SMTP connections.

[Back to table](#smtp--notifications)

---

### `smtp.sslprotocols`

**Default:** `TLSv1.2`
**Source:** [`SmtpProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/SmtpProperties.java)
**Type:** `String`

SSL/TLS protocol versions to use for SMTP connections.

[Back to table](#smtp--notifications)

---

### `smtp.fromAddress`

**Default:** `""` (empty)
**Source:** [`SmtpProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/SmtpProperties.java)
**Type:** `String`

The "From" address for emails sent by the UAA.

[Back to table](#smtp--notifications)

---

### `notifications.url`

**Default:** — (null)
**Source:** `@ConditionalOnProperty(value = "notifications.url")` in [`MessagingConfig`](../server/src/main/java/org/cloudfoundry/identity/uaa/login/MessagingConfig.java)
**Type:** `String`

URL of an external notification service. When set, HTTP-based notifications are used instead
of SMTP emails. When not set, falls back to email-based messaging.

[Back to table](#smtp--notifications)

---

### `notifications.sendInDefaultZone`

**Default:** `true`
**Source:** [`NotificationsProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/login/NotificationsProperties.java)
**Type:** `boolean`

When `true`, notifications are sent for events occurring in the default identity zone.

[Back to table](#smtp--notifications)

---

### `notifications.verify_ssl`

**Default:** `false`
**Source:** [`NotificationsProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/login/NotificationsProperties.java)
**Type:** `boolean`

When `true`, verifies SSL certificates when connecting to the notification service.

[Back to table](#smtp--notifications)

---

### `ldap.profile.file`

**Default:** — (not set)
**Source:** YAML config, injected via `@config['ldap']`
**Type:** `String`

Path to the LDAP profile configuration file. Determines the bind mode:
- `ldap/ldap-simple-bind.xml` — Simple bind (user DN pattern)
- `ldap/ldap-search-and-bind.xml` — Search then bind
- `ldap/ldap-search-and-compare.xml` — Search then compare

[Back to table](#ldap)

---

### `ldap.base.url`

**Default:** — (not set)
**Source:** YAML config
**Type:** `String`

LDAP server URL (e.g. `ldap://localhost:389/` or `ldaps://ldap.example.com:636/`).

[Back to table](#ldap)

---

### `ldap.base.userDn`

**Default:** — (not set)
**Source:** YAML config
**Type:** `String`

The DN used to bind to the LDAP server for user searches (search-and-bind mode).

[Back to table](#ldap)

---

### `ldap.base.password`

**Default:** — (not set)
**Source:** YAML config
**Type:** `String`

Password for the bind DN.

[Back to table](#ldap)

---

### `ldap.base.searchBase`

**Default:** — (not set)
**Source:** YAML config
**Type:** `String`

Base DN for LDAP user searches (e.g. `dc=test,dc=com`).

[Back to table](#ldap)

---

### `ldap.base.searchFilter`

**Default:** — (not set)
**Source:** YAML config
**Type:** `String`

LDAP search filter for finding users. `{0}` is replaced with the username
(e.g. `cn={0}` or `(uid={0})`).

[Back to table](#ldap)

---

### `ldap.base.userDnPattern`

**Default:** — (not set)
**Source:** YAML config
**Type:** `String`

DN pattern for simple-bind mode. `{0}` is replaced with the username.
Multiple patterns can be separated by semicolons.

Example: `cn={0},ou=Users,dc=test,dc=com;cn={0},ou=OtherUsers,dc=example,dc=com`

[Back to table](#ldap)

---

### `ldap.base.referral`

**Default:** — (not set)
**Source:** YAML config
**Type:** `String`

How LDAP referrals are handled. Common values: `follow`, `ignore`.

[Back to table](#ldap)

---

### `ldap.ssl.skipverification`

**Default:** `false`
**Source:** YAML config
**Type:** `boolean`

When `true`, skips SSL certificate verification for LDAPS connections.
Should only be used in development/testing.

[Back to table](#ldap)

---

### `ldap.groups.file`

**Default:** — (not set)
**Source:** YAML config
**Type:** `String`

Path to the LDAP groups configuration file (e.g. `ldap/ldap-groups-map-to-scopes.xml`).

[Back to table](#ldap)

---

### `ldap.groups.searchBase`

**Default:** — (not set)
**Source:** YAML config
**Type:** `String`

Base DN for LDAP group searches.

[Back to table](#ldap)

---

### `ldap.groups.groupSearchFilter`

**Default:** — (not set)
**Source:** YAML config
**Type:** `String`

Filter for finding group membership (e.g. `member={0}`).

[Back to table](#ldap)

---

### `ldap.groups.maxSearchDepth`

**Default:** `10`
**Source:** YAML config
**Type:** `int`

Maximum depth for nested group lookups.

[Back to table](#ldap)

---

### `ldap.groups.autoAdd`

**Default:** — (not set)
**Source:** YAML config
**Type:** `boolean`

When `true`, LDAP groups are automatically created as UAA groups if they don't exist.

[Back to table](#ldap)

---

### `encryption.active_key_label`

**Default:** — (required)
**Source:** [`UaaConfiguration.Encryption`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/UaaConfiguration.java)
**Type:** `String`

Label identifying the active encryption key from the `encryption_keys` list.
Used for encrypting new data. All listed keys can be used for decryption.

[Back to table](#encryption)

---

### `encryption.encryption_keys`

**Default:** — (required)
**Source:** [`UaaConfiguration.Encryption`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/UaaConfiguration.java)
**Type:** `List<EncryptionKey>`

List of encryption keys. Each key has:
- `label` — Unique identifier
- `passphrase` — Encryption passphrase

```yaml
encryption:
  active_key_label: key-1
  encryption_keys:
    - label: key-1
      passphrase: MY-PASSPHRASE
    - label: key-2
      passphrase: MY-OLD-PASSPHRASE
```

Multiple keys allow for key rotation: new data is encrypted with the active key;
old data encrypted with any listed key can still be decrypted.

[Back to table](#encryption)

---

### `ratelimit.loggingOption`

**Default:** `OnlyLimited` (only log rate-limited requests)
**Source:** [`UaaConfiguration.RateLimit`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/UaaConfiguration.java)
**Type:** `String`

Controls rate limiting log verbosity. Accepted values:
- `OnlyLimited` — Only log when a request is rate-limited
- `AllCalls` — Log all calls with rate-limit info
- `AllCallsWithDetails` — Log all calls with full details

[Back to table](#rate-limiting)

---

### `ratelimit.credentialID`

**Default:** — (not set)
**Source:** [`UaaConfiguration.RateLimit`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/UaaConfiguration.java)
**Type:** `String`

Regex pattern to extract a credential identifier from JWT claims for per-credential
rate limiting. Example: `'JWT:Claims+"sub"\s*:\s*"(.*?)"'`

[Back to table](#rate-limiting)

---

### `ratelimit.limiterMappings`

**Default:** `[]`
**Source:** [`UaaConfiguration.RateLimit`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/UaaConfiguration.java)
**Type:** `List<LimiterMapping>`

List of rate limiting rules. Each mapping has:
- `name` — Rule name
- `withCallerRemoteAddressID` — Per-IP rate limit (e.g. `50r/s`)
- `withCallerCredentialsID` — Per-credential rate limit
- `global` — Global rate limit
- `pathSelectors` — List of path matching rules:
  - `equals:/path` — Exact match
  - `startsWith:/prefix` — Prefix match
  - `other` — Catch-all for unmatched paths

```yaml
ratelimit:
  limiterMappings:
    - name: LoginPage
      withCallerRemoteAddressID: 50r/1s
      pathSelectors:
        - "equals:/login"
    - name: EverythingElse
      global: 1000r/s
      pathSelectors:
        - "other"
```

[Back to table](#rate-limiting)

---

### `rest.template.timeout`

**Default:** `10000` (10 seconds)
**Source:** `@Value("${rest.template.timeout:10000}")` in [`RestTemplateConfig`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/RestTemplateConfig.java)
**Type:** `int`

Connection and read timeout (in milliseconds) for outbound HTTP requests made by the UAA
(e.g. OIDC metadata fetch, notification service calls).

[Back to table](#rest-template-http-client)

---

### `rest.template.maxTotal`

**Default:** `10`
**Source:** `@Value("${rest.template.maxTotal:10}")` in [`RestTemplateConfig`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/RestTemplateConfig.java)
**Type:** `int`

Maximum total number of outbound HTTP connections in the connection pool.

[Back to table](#rest-template-http-client)

---

### `rest.template.maxPerRoute`

**Default:** `5`
**Source:** `@Value("${rest.template.maxPerRoute:5}")` in [`RestTemplateConfig`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/RestTemplateConfig.java)
**Type:** `int`

Maximum number of connections per route (per target host).

[Back to table](#rest-template-http-client)

---

### `rest.template.maxKeepAlive`

**Default:** `0` (no keep-alive limit)
**Source:** `@Value("${rest.template.maxKeepAlive:0}")` in [`RestTemplateConfig`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/RestTemplateConfig.java)
**Type:** `int`

Maximum keep-alive time (in milliseconds) for persistent HTTP connections. `0` means no limit.

[Back to table](#rest-template-http-client)

---

### `rest.template.validateAfterInactivity`

**Default:** `2000`
**Source:** `@Value("${rest.template.validateAfterInactivity:2000}")` in [`RestTemplateConfig`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/RestTemplateConfig.java)
**Type:** `int`

Time (in milliseconds) after which an idle connection is validated before reuse.

[Back to table](#rest-template-http-client)

---

### `rest.template.retryCount`

**Default:** `0`
**Source:** `@Value("${rest.template.retryCount:0}")` in [`RestTemplateConfig`](../server/src/main/java/org/cloudfoundry/identity/uaa/impl/config/RestTemplateConfig.java)
**Type:** `int`

Number of times to retry failed outbound HTTP requests. `0` means no retries.

[Back to table](#rest-template-http-client)

---

### `brave.localServiceName`

**Default:** `uaa`
**Source:** `@Value("${brave.localServiceName:uaa}")` in [`TracingAutoConfiguration`](../uaa/src/main/java/org/cloudfoundry/identity/uaa/TracingAutoConfiguration.java)
**Type:** `String`

The service name reported in distributed traces (Brave/Zipkin).

[Back to table](#tracing-bravezipkin)

---

### `brave.supportsJoin`

**Default:** `true`
**Source:** `@Value("${brave.supportsJoin:true}")` in [`TracingAutoConfiguration`](../uaa/src/main/java/org/cloudfoundry/identity/uaa/TracingAutoConfiguration.java)
**Type:** `boolean`

When `true`, incoming spans can be joined (shared) rather than always creating child spans.

[Back to table](#tracing-bravezipkin)

---

### `brave.traceId128Bit`

**Default:** `false`
**Source:** `@Value("${brave.traceId128Bit:false}")` in [`TracingAutoConfiguration`](../uaa/src/main/java/org/cloudfoundry/identity/uaa/TracingAutoConfiguration.java)
**Type:** `boolean`

When `true`, trace IDs are 128 bits instead of 64 bits. Recommended for compatibility
with systems like AWS X-Ray.

[Back to table](#tracing-bravezipkin)

---

### `uaa.shutdown.sleep`

**Default:** `10000` (10 seconds)
**Source:** `@Value("${uaa.shutdown.sleep:10000}")` in [`HealthzEndpoint`](../server/src/main/java/org/cloudfoundry/identity/uaa/health/HealthzEndpoint.java)
**Type:** `long`

Time (in milliseconds) the `/healthz` endpoint waits during shutdown before the process exits.
During this period, the endpoint returns HTTP 503, allowing load balancers to drain connections.

[Back to table](#health--shutdown)

---

### `uaa.health.db.rate`

**Default:** `10000` (10 seconds)
**Source:** `@Scheduled(fixedRateString = "${uaa.health.db.rate:10000}")` in [`HealthzEndpoint`](../server/src/main/java/org/cloudfoundry/identity/uaa/health/HealthzEndpoint.java)
**Type:** `long`

Interval (in milliseconds) between database connectivity health checks.

[Back to table](#health--shutdown)

---

### `delete.expirationRunTime`

**Default:** `2500`
**Source:** `@Value("${delete.expirationRunTime:2500}")` in [`OauthEndpointBeanConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/oauth/beans/OauthEndpointBeanConfiguration.java)
**Type:** `int`

Maximum runtime (in milliseconds) for a single expired-token cleanup run in the
revocable token store.

[Back to table](#health--shutdown)

---

### `uaa.limitedFunctionality.statusFile`

**Default:** — (null, limited mode disabled)
**Source:** `@Value("${uaa.limitedFunctionality.statusFile:#{null}}")` in [`LimitedModeProperties`](../server/src/main/java/org/cloudfoundry/identity/uaa/LimitedModeProperties.java)
**Type:** `File`

Path to a file that, when present, puts the UAA into limited-functionality mode.
In this mode, only whitelisted endpoints and HTTP methods are allowed.

[Back to table](#limited-mode)

---

### `uaa.limitedFunctionality.whitelist.endpoints`

**Default:** `{}` (empty set)
**Source:** [`LimitedModeProperties.Permitted`](../server/src/main/java/org/cloudfoundry/identity/uaa/LimitedModeProperties.java)
**Type:** `Set<String>`

Set of endpoint patterns that remain accessible when the UAA is in limited-functionality mode.

[Back to table](#limited-mode)

---

### `uaa.limitedFunctionality.whitelist.methods`

**Default:** `{}` (empty set)
**Source:** [`LimitedModeProperties.Permitted`](../server/src/main/java/org/cloudfoundry/identity/uaa/LimitedModeProperties.java)
**Type:** `Set<String>`

Set of HTTP methods allowed when the UAA is in limited-functionality mode.

[Back to table](#limited-mode)

---

### `metrics.enabled`

**Default:** `true`
**Source:** `@ConfigurationProperties(prefix = "metrics")` in [`UaaProperties.Metrics`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `boolean`

Enables or disables metrics collection.

[Back to table](#metrics)

---

### `metrics.perRequestMetrics`

**Default:** `false`
**Source:** [`UaaProperties.Metrics`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `boolean`

When `true`, collects metrics for each individual request (higher overhead).
When `false`, only aggregate metrics are collected.

[Back to table](#metrics)

---

### `zones.paths.enabled`

**Default:** `false`
**Source:** `@Value("${zones.paths.enabled:false}")` in [`ZonePathContextRewritingFilterConfiguration`](../server/src/main/java/org/cloudfoundry/identity/uaa/zone/ZonePathContextRewritingFilterConfiguration.java)
**Type:** `boolean`

When `true`, enables path-based identity zone routing via `/z/{subdomain}/` URL prefixes.
This allows multiple zones to be accessed through the same hostname using different
URL paths instead of different subdomains.

[Back to table](#zone-paths)

---

### `zones.internal.hostnames`

**Default:** `[]` (empty, defaults to `localhost`)
**Source:** `@ConfigurationProperties(prefix = "zones")` in [`UaaProperties.Zones`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `Set<String>`

A comprehensive list of hostnames that route to the UAA default zone. The UAA uses these
to distinguish zone subdomains. If a request's hostname is not in this list and has extra
subdomain levels, it is treated as a zone subdomain.

```yaml
zones:
  internal:
    hostnames:
      - uaa.example.com
      - login.example.com
```

[Back to table](#zone-paths)

---

### `csp.script-src`

**Default:** `['self']`
**Source:** `@ConfigurationProperties(prefix = "csp")` in [`UaaProperties.Csp`](../server/src/main/java/org/cloudfoundry/identity/uaa/UaaProperties.java)
**Type:** `List<String>`

Content Security Policy `script-src` directive values. Controls which sources are allowed
to execute JavaScript on UAA pages.

[Back to table](#csp-content-security-policy)

---

### `logging.file.name.path`

**Default:** — (not set)
**Source:** YAML config
**Type:** `String`

Directory path for UAA log files (e.g. `/tmp/uaa/logs`).

[Back to table](#miscellaneous)

---

## Configuration Precedence

Configuration values are resolved in the following order (later sources override earlier ones):

1. **`uaa/src/main/resources/uaa.yml`** — Embedded defaults in the application JAR
2. **`$CLOUDFOUNDRY_CONFIG_PATH/uaa.yml`** — External config file via Cloud Foundry config path
3. **`$UAA_CONFIG_PATH/uaa.yml`** — External config file via UAA-specific config path
4. **`$UAA_CONFIG_URL`** — Remote configuration URL
5. **System properties and environment variables** — Standard Spring Boot property resolution

## Active Profiles

The `spring_profiles` property activates Spring profiles that control database selection and
optional features:

| Profile | Purpose |
|---------|---------|
| `hsqldb` | In-memory HSQLDB database (default for development) |
| `postgresql` | PostgreSQL database |
| `mysql` | MySQL/MariaDB database |
| `ldap` | Enable LDAP authentication |
| `saml` | Enable SAML support |

Multiple profiles can be combined: `spring_profiles: postgresql,ldap`
