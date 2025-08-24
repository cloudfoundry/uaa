
# User Account and Authentication LDAP Integration

# Overview
UAA integrates with the Lightweight Directory Access Protocol in two major areas. 
Authentication, the first integration point, can be done using three different 
authentication methods.
Once authenticated, a user's LDAP groups can be retrieved and mapped to scopes, 
the second integration point.

In this document we use the term 'bind' a lot, and it refers to the LDAP
[bind operation](http://tools.ietf.org/html/rfc4511#section-4.2).
In short, it is the LDAP way of performing an authentication on a given connection 
to the LDAP server.

At this time, integration with LDAP, both for authentication, is limited to users and the groups they belong to.
We do foresee that we will also be able to authenticate clients and propagate client authorities in the future.

# Authentication

## Chained Authentication
When integrating with an external identity provider, such as LDAP,
authentication within the UAA becomes chained. An
authentication attempt with a user's credentials is initially 
attempted against the UAA user store before the external provider, LDAP.

Chained authentication allows a certain number of bootstrap users to 
exist within the UAA itself without the need to configure them in a potential
 read-only external store. 

Usernames are not unique within the UAA. The combination of a username and 
its origin, 'ldap', for example, is unique.

A potential collision does exist in a chained authentication. 
If the exact same set of credentials, username/password combination, exist in both the UAA and the LDAP 
server, a user would always be authenticated against the UAA and an LDAP authentication would not be attempted.
To avoid such a collision and effectively disable chained authentication, 
do not bootstrap or create users in the UAA directly. 

## UAA Authentication
Authentication against the UAA database is the first step in the chained authentication.
Authentication is done using three variables

 * username — case-insensitive username search, often email address
 * origin — matched against ['uaa'](https://github.com/cloudfoundry/uaa/blob/develop/common/src/main/java/org/cloudfoundry/identity/uaa/authentication/Origin.java#L16-16)
 * password — an encoded password, the input is encoded and then matched against the DB value
 
This is how the UAA performs user authentication out of the box with no external
identity provider configured. When enabling LDAP, this method of authentication is always 
tried before attempting to authenticate against the external provider.

## LDAP Authentication
LDAP authentication within the UAA is done leveraging the 
[Spring Security LDAP module](https://github.com/spring-projects/spring-security/tree/master/ldap)
thus the authentication methods and configuration options you will find available within the UAA
are directly correlated to those found in Spring Security LDAP.
There are three different authentication methods supported against an LDAP compatible server

* Search and Bind — find the user's DN, authenticate as the user
* Simple Bind — construct the user's DN, authenticate as the user
* Search and Compare — find the user's DN, perform a comparison against the user's password attribute

The UAA will attempt to retrieve the user's email address and update the UAA user's record with it.
This is done so that there is a current email address on file as external systems may rely on the UAA SCIM record of the user for notifications.

### LDAP Search and Bind
The most common LDAP authentication method is the 'search and bind'.
During a search and bind

1. the user inputs a username
2. the UAA server performs a search using an LDAP filter and a set of known search credentials
3. If there is exactly one match, the user's DN will be retrieved. Zero or more than one matches are automatically rejected.
4. The user's DN and supplied password is then used to attempt a bind against the LDAP server
5. The LDAP server performs the authentication

This method allows the most flexibility, as username to DN match is done using an LDAP search filter (query), 
and the user's credentials are not exposed. 

The security consideration with this authentication method is that a set of, preferably read-only,
credentials has to be made available to the UAA to perform a search for a subset of the 
LDAP tree where the user resides. Should the UAA's configuration be compromised,
so becomes the LDAP read-only data that the UAA can query.

### Ldap Bind
An LDAP bind authentication never exposes any of the LDAP directory contents to the UAA. This is the benefit for a less flexible authentication method.
In this method, the user supplies a username, and with that username, the UAA statically constructs a DN.
For example 

1. user supplies user, for example, filip — we construct DN, dn=uid=filip,ou=users,dc=test,dc=com
2. The UAA uses the statically constructed DN, and supplied password and attempts a bind to the LDAP server

In the simple bind method, the administrator of the UAA can configure one or more DN patterns
to be tried for a single username input. A pattern can also be the input itself, such as '{0}'
as the pattern means the user would have to type in his or her DN as the username.

While this method provides the most secure installation as no LDAP credentials or data
is exposed through configuration. It is not very common as the flexibility is reduced by not being able
to customize the username through a search query.

### LDAP Search and Compare
Similar to the search and bind, the search and compare will perform a search using a filter, retrieve the user's LDAP record, 
including the password field. It will then perform a password comparison against the password field in a similar way
that the UAA does against its user store.

This method is rarely used, it requires additional privileges to retrieve the password field.

## Ldap Authentication Configuration

### Overview
Configuration of the UAA is done through the [uaa.yml](https://github.com/cloudfoundry/uaa/blob/master/uaa/src/main/resources/uaa.yml)
This allows easy configuration for consumers like Cloud Foundry to generate a configuration file and deploy the UAA as a job.

The UAA is a Spring-based application and reads the values from the uaa.yml and performs a variable substitution in the 
[XML configuration files](https://github.com/cloudfoundry/uaa/tree/master/uaa/src/main/resources/ldap)

Enabling any level of LDAP authentication requires the 
[`spring_profiles: ldap`](https://github.com/cloudfoundry/uaa/blob/master/uaa/src/main/resources/uaa.yml#L7-7) configuration
to be enabled. This `ldap` profile triggers the chained authentication to be enabled and the 
[ldap configuration files](https://github.com/cloudfoundry/uaa/blob/develop/uaa/src/main/webapp/WEB-INF/spring-servlet.xml#L174)
to be loaded. 

<code>
spring_profiles: ldap
</code>

All further configurations will be placed under the `ldap: ` configuration element

#### Selecting an authentication method
Selecting an authentication method, `simple bind`, `search and bind` or `search and compare` is done using the 
`ldap.profiles.file` configuration attribute. There are three different values for this attribute, each mapped to the 
different authentication methods

* [`ldap/ldap-simple-bind.xml`](https://github.com/cloudfoundry/uaa/blob/develop/uaa/src/main/resources/ldap/ldap-simple-bind.xml) — simple bind
* [`ldap/ldap-search-and-bind.xml`](https://github.com/cloudfoundry/uaa/blob/develop/uaa/src/main/resources/ldap/ldap-search-and-bind.xml) — search and bind
* [`ldap/ldap-search-and-compare.xml`](https://github.com/cloudfoundry/uaa/blob/develop/uaa/src/resources/ldap/ldap-search-and-compare.xml) — search and compare

As noticed, the attribute is an actual reference to a configuration file. The configuration, 
at a minimum, should provide a bean named `ldapAuthProvider` that will be used
to configure the 
[LDAP authentication manager](https://github.com/cloudfoundry/uaa/blob/develop/uaa/src/main/resources/ldap-integration.xml#L44).

This allows a user/administrator of the UAA to configure a Spring XML file for a custom LDAP48374 authentication method.

<pre>
spring_profiles: ldap
ldap:
  profile:
    file: ldap/ldap-search-and-bind.xml
</pre>

##### Configuring Simple Bind
The following attributes are available for the default bind configuration

* `ldap.base.url` — A URL pointing to the LDAP server must start with `ldap://` or `ldaps://`
* `ldap.base.userDnPattern` — one or more patterns used to construct DN.
* `ldap.base.userDnPatternDelimiter` — the delimiter character to break up multiple patterns. 
  Default is semi colon `;`
* `ldap.base.mailAttributeName` — the name of the attribute that contains the user's email address, default value is `mail`

<pre>
spring_profiles: ldap
ldap:
  profile:
    file: ldap/ldap-simple-bind.xml
  base:
    url: 'ldap://localhost:10389/'
    mailAttributeName: mail
    userDnPattern: 'cn={0},ou=Users,dc=test,dc=com;cn={0},ou=OtherUsers,dc=example,dc=com'
</pre>


##### Configuring Search and Bind
The following attributes are available for the default search and bind configuration

* `ldap.base.url` — A URL pointing to the LDAP server must start with `ldap://` or `ldaps://`
  In the case of SSL (ldaps), the server must hold a trusted certificate or the certificate must be
  imported into the JVM's truststore. 
* `ldap.base.mailAttributeName` — the name of the attribute that contains the user's email address, default value is `mail`
* `ldap.base.userDn` — The DN for the LDAP credentials used to search the directory
* `ldap.base.password` — Password credentials for the above DN to search the directory
* `ldap.base.searchBase` — Specify only if a part of the directory should be searched, for example
  `dc=test,dc=com`
* `ldap.base.searchFilter` — the search filter used for the query. `{0}` is used to annotate 
  where the username will be inserted. For example `cn={0}` will search the LDAP directory records
  where the attribute `cn` matches the user's input.

<pre>
spring_profiles: ldap
ldap:
  profile:
    file: ldap/ldap-search-and-bind.xml
  base:
    url: 'ldap://localhost:10389/'
    mailAttributeName: mail
    userDn: 'cn=admin,ou=Users,dc=test,dc=com'
    password: 'password'
    searchBase: ''
    searchFilter: 'cn={0}'
</pre>

##### Configuring Search and Compare
The following attributes are available for the default search and bind configuration

* `ldap.base.url` — A URL pointing to the LDAP server must start with `ldap://` or `ldaps://`
  In the case of SSL (ldaps), the server must hold a trusted certificate or the certificate must be
  imported into the JVM's truststore. 
* `ldap.base.mailAttributeName` — the name of the attribute that contains the user's email address, default value is `mail`
* `ldap.base.userDn` — The DN for the LDAP credentials used to search the directory
* `ldap.base.password` — Password credentials for the above DN to search the directory
* `ldap.base.searchBase` — Specify only if a part of the directory should be searched, for example
  `dc=test,dc=com`
* `ldap.base.searchFilter` — the search filter used for the query. `{0}` is used to annotate 
  where the username will be inserted. For example `cn={0}` will search the LDAP directory records
  where the attribute `cn` matches the user's input.
* `ldap.base.passwordAttributeName` — the name of the LDAP attribute that holds the password
* `ldap.base.localPasswordCompare` — set to true if the comparison should be done locally
  Setting this value to false, implies that rather than retrieving the password, the UAA
  will run a query to match the password. In order for this query to work, you must know what 
  type of hash/encoding/salt is used for the LDAP password.
* `ldap.base.passwordEncoder` — A fully qualified Java classname to a password encoder.
  The [default](https://github.com/cloudfoundry/uaa/blob/master/model/org/cloudfoundry/identity/uaa/provider/ldap/DynamicPasswordComparator.java#L20-20)
  uses the Apache Directory Server password utilities to support several different encodings.

<pre>
spring_profiles: ldap
ldap:
  profile:
    file: ldap/ldap-search-and-compare.xml
  base:
    url: 'ldap://localhost:10389/'
    mailAttributeName: mail
    userDn: 'cn=admin,ou=Users,dc=test,dc=com'
    password: 'password'
    searchBase: ''
    searchFilter: 'cn={0}'
    passwordAttributeName: userPassword
    passwordEncoder: org.cloudfoundry.identity.uaa.provider.ldap.DynamicPasswordComparator
    localPasswordCompare: true
</pre>

# LDAP Group Mapping

As of now, the primary purpose of the UAA is to issue [Oauth 2](http://tools.ietf.org/html/rfc6749) 
tokens to the client on behalf of the user. 

The UAA integrates with LDAP groups during the user authentication process. Each time a user is authenticated,
group memberships, if configured, are retrieved and refreshed.

These groups are then mapped to UAA scopes. When LDAP group integration is enabled, groups are translated to scopes and stored 
in the UAA database as SCIM groups. Upon each authentication, a user's group membership is reset. Thus, a change in group 
membership for a user in LDAP does not manifest itself until the next successful authentication of the user against 
the LDAP server.

Support for nested groups has been implemented. Either through the search filter, Active Directory style, 
or for static nested groups by using the search filter, most commonly using the `memberOf` attribute. 

In the UAA, we refer to a scope as a group, or a SCIM group. Groups in the UAA are mapped one-to-one
with a scope. The group name, in fact, is the scope name. Groups can be nested. 

## Scopes

A token contains a list of scopes and authorities. The scopes in the token represent the permissions of the user
while the authorities represent the permissions of the client itself. Thus, a resource server receiving a request
containing a token can decide to authorize the client on behalf of the user, or just the client itself.

## Selecting a Group Mapping

The UAA integrates with LDAP groups in such a way that groups can translate into scopes. 
There are three different ways we incorporate LDAP groups

* No group integration — this is the default setting when you enable LDAP. Groups will be ignored.
* A group is a scope or scopes — With this configuration, UAA will read a designated attribute of a group, 
  and the value of the record attribute is either one scope or a list of comma-delimited scope names.
  These scopes, if configured, will be automatically added to the UAA database as groups.
* Mapping of LDAP groups to scopes — With this configuration you can map a group DN
  to a group/scope UUID using the UAA `external_group_mapping` table. 

We foresee that the strategy of mapping groups to scopes using the mapping table will become the 
most common one, along with no group integration at all. Mapping groups to scopes by putting 
a group name in the LDAP record will require modification to the group record itself. Adding an attribute or modifying an existing attribute requires changes to the LDAP directory 
that most organizations may not wish to perform. It will couple the LDAP tree with the Cloud Foundry, CF, installation,
and thus, in multi CF installations, become troublesome.

### No Group Integration
Choose this strategy if you wish to not retrieve LDAP groups during authentication. All group memberships are managed by the UAA.
May be suitable when all users receive the same groups, either through the manifest or 
through the [Spring configuration files](https://github.com/cloudfoundry/uaa/blob/develop/uaa/src/main/webapp/WEB-INF/spring/oauth-endpoints.xml#L203-203)

### LDAP Groups as Scopes
When you wish to control scopes directly in your LDAP directory, my modifying your LDAP group entries to contain one or more
scope names. In this setup, you'd define an attribute or reuse an existing attribute and store the names of the scopes 
that you wish the group to represent. 

<pre>
dn: cn=developers,ou=scopes,dc=test,dc=com
changetype: add
objectClass: groupOfNames
objectClass: top
cn: developers
description: blog.read,blog.write,blog.delete
member: cn=operators,ou=scopes,dc=test,dc=com
member: cn=marissa6,ou=Users,dc=test,dc=com
</pre>

For the above example, the user marissa6, would inherit the scopes `blog.read`,`blog.write` and `blog.delete` upon authentication.
If the scopes are not present in the UAA schema, they will get created and assigned a UUID. 
Users that are members of the `cn=operators,ou=scopes,dc=test,dc=com` group, would also inherit the above-mentioned scopes if nested 
group searches are [enabled](https://github.com/cloudfoundry/uaa/blob/develop/uaa/src/main/webapp/WEB-INF/spring/ldap/ldap-groups-populator.xml#L34-34).

A major benefit to this integration method is that scopes/groups don't have to preexist in the UAA. They can be 
automatically created upon user authentication. Together with clients having wildcard support for authorities, for example,
`blog.*`, making meaningful LDAP groups to client authority mappings becomes straightforward.

### LDAP Groups to Scopes 
Probably the most flexible integration with LDAP groups is when they are mapped to a UAA group. This allows the administrator of CF
to create the scopes (aka groups in the UAA schema) and then map these to LDAP groups. 
The mapping is many-to-many, so any LDAP group can be mapped to one or more UAA scopes, and likewise, any UAA scope can be mapped to 
one or more. Mappings are not created automatically, and both groups(scopes) and mappings to LDAP groups must exist when the user 
authenticates in order for the user/scope relationship to be created. 

## Group Mapping Configuration 

The property [`ldap.groups.file`](https://github.com/cloudfoundry/uaa/blob/master/uaa/src/main/webapp/WEB-INF/spring/ldap-integration.xml) 
controls what group mapping is used, and is also a reference to a Spring XML configuration file.
The different values are

* `ldap/ldap-groups-null.xml` — no groups will be retrieved
* `ldap/ldap-groups-as-scopes.xml` — group names will be derived from an attribute, like CN, in the group record
* `ldap/ldap-groups-map-to-scopes.xml` — groups will be mapped to UAA groups using the `external_group_mapping` table

The file exports a bean named [`ldapAuthoritiesPopulator`](https://github.com/cloudfoundry/uaa/blob/develop/uaa/src/main/webapp/WEB-INF/spring/ldap/ldap-search-and-bind.xml#L42-42) 
to be used in the LDAP configuration files.

### No Group Integration Configuration

* `ldap.groups.file` — set to `ldap/ldap-groups-null.xml` to never retrieve group information

This is the default.

The configuration looks like

<pre>
spring_profiles: ldap
ldap:
  profile:
    file: ldap/ldap-search-and-bind.xml
  groups:
    file: ldap/ldap-groups-null.xml
  base:
    url: 'ldap://localhost:10389/'
    userDn: 'cn=admin,ou=Users,dc=test,dc=com'
    password: 'password'
    searchBase: ''
    searchFilter: 'cn={0}'
</pre>

Which is the same as omitting the value all together

<pre>
spring_profiles: ldap
ldap:
  profile:
    file: ldap/ldap-search-and-bind.xml
  base:
    url: 'ldap://localhost:10389/'
    userDn: 'cn=admin,ou=Users,dc=test,dc=com'
    password: 'password'
    searchBase: ''
    searchFilter: 'cn={0}'
</pre>


### LDAP Groups as Scopes Configuration

* `ldap.groups.file` — set to `ldap/ldap-groups-as-scopes.xml` to create scopes out of LDAP groups
* `ldap.groups.searchBase` — the search base for the group search
* `ldap.groups.groupRoleAttribute` — the name of the attribute in the LDAP record
  that contains the scope name(s)
* `ldap.groups.searchSubtree` — boolean value, true indicates that we search the subtree of the LDAP base
* `ldap.groups.groupSearchFilter` — similar to a user filter, most common is `member={0}`
* `ldap.groups.maxSearchDepth` — how many levels deep do we search for nested groups
  Set this value to 1 to disable nested groups. The default is 10
* `ldap.groups.autoAdd` — boolean value, true indicates that groups(scopes) will be added automatically if 
  they don't exist

<pre>
spring_profiles: ldap
ldap:
  profile:
    file: ldap/ldap-search-and-bind.xml
  base:
    url: 'ldap://localhost:10389/'
    userDn: 'cn=admin,ou=Users,dc=test,dc=com'
    password: 'password'
    searchBase: ''
    searchFilter: 'cn={0}'
  groups:
    file: ldap/ldap-groups-as-scopes.xml    
    searchBase: ou=scopes,dc=test,dc=com
    groupRoleAttribute: scopenames
    searchSubtree: true
    groupSearchFilter: member={0}
    maxSearchDepth: 10
    autoAdd: true
</pre>

### Ldap Groups to Scopes Configuration 
* `ldap.groups.file` — set to `ldap/ldap-groups-map-to-scopes.xml` to map scopes to LDAP groups
* `ldap.groups.searchBase` — the search base for the group search
* `ldap.groups.groupRoleAttribute` — ignored by this implementation
* `ldap.groups.searchSubtree` — boolean value, true indicates that we search the subtree of the LDAP base
* `ldap.groups.groupSearchFilter` — similar to a user filter, most common is `member={0}`
* `ldap.groups.maxSearchDepth` — how many levels deep do we search for nested groups
  Set this value to 1 to disable nested groups. The default is 10
* `ldap.groups.autoAdd` — has no effect in this configuration, as if the mapping doesn't exist
  and is valid, there will not be authorities assigned to the user

<pre>
spring_profiles: ldap
ldap:
  profile:
    file: ldap/ldap-search-and-bind.xml
  base:
    url: 'ldap://localhost:10389/'
    userDn: 'cn=admin,ou=Users,dc=test,dc=com'
    password: 'password'
    searchBase: ''
    searchFilter: 'cn={0}'
  groups:
    file: ldap/ldap-groups-map-to-scopes.xml    
    searchBase: ou=scopes,dc=test,dc=com
    searchSubtree: true
    groupSearchFilter: member={0}
    maxSearchDepth: 10
    autoAdd: true
</pre>

### Populating External Group Mappings
Once you have configured UAA to map Ldap Groups to Scopes, you can use the Cloud Controller API to manage the group mappings:
* [List External Group mapping](https://github.com/cloudfoundry/uaa/blob/master/docs/UAA-APIs.rst#list-external-group-mapping-get-groups-external)
* [Create a Group mapping](https://github.com/cloudfoundry/uaa/blob/master/docs/UAA-APIs.rst#create-a-group-mapping-post-groups-external)
* [Remove a group mapping](https://github.com/cloudfoundry/uaa/blob/master/docs/UAA-APIs.rst#remove-a-group-mapping-delete-groups-external-displayname-displayname-externalgroup-externalgroup-origin-origin)

# LDAP Email integration
As you may have noticed through the different examples, the property `ldap.base.mailAttributeName` is always 
configured, and even has a default value. Each time the UAA authenticates an LDAP user, it will update the 
user's email record in the database. This is so that systems that provide notifications have an email 
address that is as current as the user's last authentication.

## Generating an email address if the LDAP mail attribute is empty
If an LDAP user does not have an email address, the UAA can automatically generate one.

<pre>
spring_profiles: ldap
ldap:
  profile:
    file: ldap/ldap-search-and-bind.xml
  base:
    url: 'ldap://localhost:10389/'
    userDn: 'cn=admin,ou=Users,dc=test,dc=com'
    password: 'password'
    searchBase: ''
    searchFilter: 'cn={0}'
    mailAttributeName: 'mail'
    mailSubstitute: 'generated-{0}@company.example.com'
    mailSubstituteOverridesLdap: true
</pre>

In the above example, if user `marissa` has a mail record, her UAA email will be set to the email address she has on file.
However, if `marissa` does not have an email address in the `mail` attribute, her UAA email will become
`generated-marissa@company.example.com`.

## Overriding the LDAP email address
The UAA provides the ability to override the email address that is set in LDAP
by setting the `mailSubstituteOverridesLdap` flag to true.

<pre>
spring_profiles: ldap
ldap:
  profile:
    file: ldap/ldap-search-and-bind.xml
  base:
    url: 'ldap://localhost:10389/'
    userDn: 'cn=admin,ou=Users,dc=test,dc=com'
    password: 'password'
    searchBase: ''
    searchFilter: 'cn={0}'
    mailAttributeName: 'mail'
    mailSubstitute: 'generated-{0}@company.example.com'
    mailSubstituteOverridesLdap: true
</pre>
In the above example, the user `marissa`'s  UAA email always become `generated-marissa@company.example.com`.

# Samples

# Configuration References

* <a name="#ldap.profiles.file">`ldap.profiles.file`</a> 
  authentication file reference. 
  Value must be a file path to a Spring XML configuration file that delivers a bean
  named `ldapAuthProvider` used by the [LDAP authentication manager](https://github.com/cloudfoundry/uaa/blob/develop/uaa/src/main/webapp/WEB-INF/spring/ldap-integration.xml#L44-44)
  There are three different values available with the 
    - ldap/ldap-simple-bind.xml
    - ldap/ldap-search-and-bind.xml
    - ldap/ldap-search-and-compare.xml


* <a name="ldap.base.url">`ldap.base.url`</a> 
  A URL pointing to the LDAP server, must start with `ldap://` or `ldaps://`
  When using SSL, a ldaps URL, the certificate must be trusted, or be imported in the JVM
  trust store. The string value may contain multiple LDAP URLs, space delimited.
  <br/>This property is always used.


* <a name="ldap.base.referral">`ldap.base.referral`</a>
  Should the LDAP client instruct the server to follow referrals.
  Possible values are `ignore` and `follow`. The default is `follow`
  <br/>This property is always used.


* <a name="ldap.base.userDnPattern">`ldap.base.userDnPattern`</a>
  one or more patterns used to construct DN.
  Contains one or more patterns used to construct a DN.
  A pattern can look like `cn={0},ou=Users,dc=test,dc=com}`
  where `{0}` will be replaced with the user's input.
  the `userDnPattern` property can contain multiple patterns, 
  that will be tried in sequence. The patterns are delimited by the
  `userDnPatternDelimiter` character
  <br/>This property is used with the simple bind authentication mechanism.


* <a name="ldap.base.userDnPatternDelimiter">`ldap.base.userDnPatternDelimiter`</a>
  the delimiter character to break up multiple patterns
  in the `ldap.base.userDnPattern` property.
  Default is semi colon `;`
  <br/>This property is used with the simple bind authentication mechanism.


* <a name="ldap.base.mailAttributeName">`ldap.base.mailAttributeName`</a> 
  the name of the attribute that contains the user's email address
  Default value is `mail`
  If an email address is not available, one will be generated for the user.
  <br/>This property is always used.


* <a name="ldap.base.mailSubstitute">`ldap.base.mailSubstitute`</a> 
  Defines a pattern, `{0}@ldap-generated.email.com`, that the system
  uses to generate an email address based on the username for the user.
  This property will set the email address for the user if the LDAP 
  email address is null or if the property `ldap.base.mailSubstituteOverridesLdap`
  is set to true. The pattern must contain `{0}` to be substituted for the username.
  Default value is `null`
  <br/>This property is optional


* <a name="ldap.base.mailSubstituteOverridesLdap">`ldap.base.mailSubstituteOverridesLdap`</a> 
  If set to true and the property/pattern `ldap.base.mailSubstitute` is defined
  the users email address will be generated from the pattern, always.
  Default value is `false`
  <br/>This property is optional


* <a name="ldap.base.userDn">`ldap.base.userDn`</a>
  The DN for the LDAP credentials used to search the directory.
  When searching the LDAP directory, UAA uses a preferably read-only account
  to find the DN for a user matching a user-inputted username.
  The userDn property is a complete DN for an account that has search privileges.
  <br/>This property is used with the 'search and bind' and 
  'search and compare' authentication mechanisms.


* <a name="ldap.base.password">`ldap.base.password`</a>
  Password credentials for the above account/DN to search the 
  LDAP directory
  <br/>This property is used with the 'search and bind' and 
  'search and compare' authentication mechanisms.


* <a name="ldap.base.searchBase">`ldap.base.searchBase`</a>
  Specify only if a part of the directory should be searched, for example
  `dc=test,dc=com`. It is the [user-search-base](http://docs.spring.io/spring-security/site/docs/3.0.x/reference/ldap.html)
  property of Spring Security LDAP.
  <br/>This property is used with the 'search and bind' and 
  'search and compare' authentication mechanisms.


* <a name="ldap.base.searchFilter">`ldap.base.searchFilter`</a>
  the search filter used for the query. `{0}` is used to annotate 
  where the username will be inserted. For example `cn={0}` will search the LDAP directory records
  where the attribute `cn` matches the user's input.
  <br/>This property is used with the 'search and bind' and 
    'search and compare' authentication mechanisms.


* <a name="ldap.base.passwordAttributeName">`ldap.base.passwordAttributeName`</a>
  the name of the LDAP attribute that holds the password to be compared with user's input
  <br/>This property is used with the 'search and compare' authentication mechanism.


* <a name="ldap.base.localPasswordCompare">`ldap.base.localPasswordCompare`</a>
  set to true if the comparison should be done locally
  Setting this value to false, implies that rather than retrieving the password, the UAA
  will run a query to match the password. In order for this query to work, you must know what 
  type of hash/encoding/salt is used for the LDAP password.
  <br/>This property is used with the 'search and compare' authentication mechanism.


* <a name="ldap.base.passwordEncoder">`ldap.base.passwordEncoder`</a>
  A fully qualified Java classname to a password encoder.
  The [default](https://github.com/cloudfoundry/uaa/blob/master/model/src/main/java/org/cloudfoundry/identity/uaa/provider/ldap/DynamicPasswordComparator.java#L20-20)
  uses the Apache Directory Server password utilities to support several different encodings.
  <br/>This property is used with the 'search and compare' authentication mechanism.


* <a name="ldap.groups.file">`ldap.groups.file`</a>
  group integration file reference. 
  Value must be a file path to a Spring XML configuration file that delivers a bean
  named `ldapAuthoritiesPopulator` used by the 
  [LDAP authentication provider](https://github.com/cloudfoundry/uaa/blob/develop/uaa/src/main/webapp/WEB-INF/spring/ldap/ldap-search-and-bind.xml#L42-42)
    - set to `ldap/ldap-groups-null.xml` to never retrieve group information (group integration disabled)
    - set to `ldap/ldap-groups-as-scopes.xml` to directly map LDAP groups to scopes
    - set to `ldap/ldap-groups-map-to-scopes.xml` to leverage the external_group_mappings table to 
      map an LDAP group to one or more UAA scopes
  <br/>This property is always used, but may be omitted when no group integration is desired.


* <a name="ldap.groups.ignorePartialResultException">`ldap.groups.ignorePartialResultException`</a>
    How should the client react when it receives a `partial results` message back from the LDAP server.
    If set to true, it is ignored. If set to false, authentication and group search will be marked as failed.
    Default is `true`. User searches are always ignoring partial results and always expect 1 result back from the query.


* <a name="ldap.groups.searchBase">`ldap.groups.searchBase`</a>
  the search base for the group search. This references the 
  [group-search-base](http://docs.spring.io/spring-security/site/docs/3.0.x/reference/ldap.html)
  property in Spring Security LDAP
  <br/>This property is always used but may be omitted when no group integration is desired.


* <a name="ldap.groups.groupRoleAttribute">`ldap.groups.groupRoleAttribute`</a>
  the name of the attribute in the LDAP record that contains the scope name(s).
  In case of multiple scopes, they must be delimited by a comma `,`
  <br/>This property is used by the LDAP Groups as Scopes mapping


* <a name="ldap.groups.searchSubtree">`ldap.groups.searchSubtree`</a>
  boolean value, true indicates that we search the subtree of the LDAP base.
  The default value is true.
  <br/>This property is used when group integration is enabled


* <a name="ldap.groups.groupSearchFilter">`ldap.groups.groupSearchFilter`</a>
  similar to a user filter, most common is `member={0}`.
  This is the search filter used when user group memberships are retrieved.
  For nested Active Directory groups, this string can be modified.
  Initially the `{0}` will be replaced with the user's DN and then 
  for statically nested groups, the `{0}` will be replaced with the group DNs
  to search nested groups in the hierarchy.
  <br/>This property is used when group integration is enabled


* <a name="ldap.groups.maxSearchDepth">`ldap.groups.maxSearchDepth`</a>
  how many levels deep do we search for nested groups
  Set this value to 1 to disable nested groups. The default is 10
  <br/>This property is used when group integration is enabled but does not apply
  when the [group search filter](#ldap.groups.groupSearchFilter)
  contains an Active Directory command to retrieve nested groups and should then be set to 1
  to avoid unnecessary queries.


* <a name="ldap.groups.autoAdd">`ldap.groups.autoAdd`</a> 
  boolean value, true indicates that groups(scopes) will be added automatically if 
  they don't exist
  <br/>This property is used by the LDAP Groups as Scopes mapping 


* <a name="ldap.emailDomain">`ldap.emailDomain`</a>
  List<String> value,
  Optional List of email domains associated with the UAA provider that selects an authentication source for an invited user.
  If null and no domains are explicitly matched with any other providers, the UAA acts as a catch-all,
  wherein the email will be associated with the UAA provider. Wildcards supported.


* <a name="ldap.externalGroupsWhitelist">`ldap.externalGroupsWhitelist`</a>
  List<String> value,
  Optional List of external groups that will be included in the ID Token if the `roles` scope is requested.
  The list should contain `DN` values for the groups that are associated with the user.
  The display name of the group in the ID token will be the taken from the `ldap.groups.groupRoleAttribute` attribute


* <a name="ldap.attributeMappings">`ldap.attributeMappings`</a>
  Map<String,Object> value where Object can be a String or a List<String>,
  Optional List of UAA attributes mapped to attributes from LDAP that are presented as part of the ID token
  when the `profile` scope is requested.
  Currently we support mapping for keys `given_name`(String), `family_name`(String), `phone_number`(String).
  LDAP integration also supports custom user attributes to be populated in the id_token when the `user_attributes` scope
  is requested. The attributes are pulled out of the user records and have the format
  `user.attribute.<name of attribute in ID token>: <ldap attribute name>`

<pre>
ldap:
  attributeMappings:
    first_name: givenname
    family_name: sn
    phone_number: telephonenumber
    user:
      attribute:
        employeeCostCenter: costCenter
        terribleBosses: manager
</pre>
