==================
UAA Sysadmin Guide
==================

.. contents::

UAA
===

UAA is the User Account and Authentication service. It is used to
coordinate identity operations.

A “client” in the context of identity is an application doing something on
behalf of the end user (or on behalf of itself).

It’s important to know how data flows between client applications and the UAA. The sequences
of data movement satisfy different identity requirements.

The login flow: (`view diagram
source <http://www.websequencediagrams.com/?lz=YnJvd3Nlci0-cG9ydGFsOiBjbGljayBsb2dpbgoADgYtPgAeBzogc2V0IHNlc3Npb24gY29va2llLCByZWRpcmVjdAoAQgkAOAU6IGdldCAvYXV0aG9yaXplCgBOBQBBC2JsYW5rIGZvcm0AKRFwb3N0IGNyZWRlbnRpYWxzADQIdWFhAAoTdWFhAGsJAGcIYXQAgR0GZABmEgAREgCBMBQAggcIcHJlc2VudABFFACCFggAgREFAGYTbm90ZSBvdmVyIACBMwVleGNoYW5nZQCBEQUgZm9yIHJlZnJlc2ggYW5kIGFjY2VzcyB0b2tlbgCBTAcAgwoIAA0aAFgKAIM2CGFzc29jaWF0ZQBDByB3aXRoAIMrCACDPhJhZG1pbiBwYWdl&s=roundgreen>`_)

.. figure:: http://www.websequencediagrams.com/cgi-bin/cdraw?lz=YnJvd3Nlci0-cG9ydGFsOiBjbGljayBsb2dpbgoADgYtPgAeBzogc2V0IHNlc3Npb24gY29va2llLCByZWRpcmVjdAoAQgkAOAU6IGdldCAvYXV0aG9yaXplCgBOBQBBC2JsYW5rIGZvcm0AKRFwb3N0IGNyZWRlbnRpYWxzADQIdWFhAAoTdWFhAGsJAGcIYXQAgR0GZABmEgAREgCBMBQAggcIcHJlc2VudABFFACCFggAgREFAGYTbm90ZSBvdmVyIACBMwVleGNoYW5nZQCBEQUgZm9yIHJlZnJlc2ggYW5kIGFjY2VzcyB0b2tlbgCBTAcAgwoIAA0aAFgKAIM2CGFzc29jaWF0ZQBDByB3aXRoAIMrCACDPhJhZG1pbiBwYWdl&s=roundgreen
   :align: center
   :alt:

The client keeps track of the browser through a cookie to track its
http(s) session. The refresh and access tokens are kept private and not
shared directly with the browser.

An authenticated operation flow: (`view diagram
source <http://www.websequencediagrams.com/?lz=YnJvd3Nlci0-cG9ydGFsOiBhZG1pbiByZXF1ZXN0Cm5vdGUgb3ZlciAAGAhsb29rIHVwIHRva2VuIGZyb20gc2Vzc2lvbgoAPQYtPmNjOiBwcmVzZW50ACAHdG8gYWNjZXNzIEFQSXMgb24gdXNlcidzIGJlaGFsZgBcC2NjOiB2ZXJpZnkAWwdzaWduYXR1cmUsIGF0dHJpYnV0ZXMAIg9wZXJmb3JtIGFjdGlvbgpjYwCBRQpBUEkgcmVzcG9uc2UAgRgJAIFuBzogcmVuZGVyABgJ&s=roundgreen>`_)

.. figure:: http://www.websequencediagrams.com/cgi-bin/cdraw?lz=YnJvd3Nlci0-cG9ydGFsOiBhZG1pbiByZXF1ZXN0Cm5vdGUgb3ZlciAAGAhsb29rIHVwIHRva2VuIGZyb20gc2Vzc2lvbgoAPQYtPmNjOiBwcmVzZW50ACAHdG8gYWNjZXNzIEFQSXMgb24gdXNlcidzIGJlaGFsZgBcC2NjOiB2ZXJpZnkAWwdzaWduYXR1cmUsIGF0dHJpYnV0ZXMAIg9wZXJmb3JtIGFjdGlvbgpjYwCBRQpBUEkgcmVzcG9uc2UAgRgJAIFuBzogcmVuZGVyABgJ&s=roundgreen
   :align: center
   :alt:

This flow takes place after the authentication flow above. The browser
can now make a request to the portal. The portal looks up the
appropriate token from the session and uses it to make the request.

Login server
============

The login server component used to be separate from UAA.
It has now been merged into the UAA so it can present an
appropriate visual rendering of the login page and authentication
interfaces. The login-server is now the login module in the UAA repository.

The login also has additional logic to support the autologin
flow. This is to allow a client to sign in on behalf of the user using
the client’s own credentials. This is needed when a user needs to be
signed in after resetting his password.

The autologin flow: (`view diagram
source <http://www.websequencediagrams.com/?lz=CmJyb3dzZXItPnBvcnRhbDogaW5pdGlhdGUgcmVzZXQgcGFzc3dvcmQKbm90ZSBvdmVyIAAiCGVtYWlsIGEAIgdrZXkAOxJwb3N0ABYKIGFuZCBuZXcAOhsKIHZlcmlmeQBKC2VuZCBub3RlCgCBHAYtPmxvZ2luOiAvYXV0bwAHBSArAE0JICsAgRgHIHNlY3JldCBvbiBodHRwIGJhc2ljCgA2BS0-dWFhOgCBRgt1YWE6IAogQ3JlYXRlIHRlbXBvcmFyeSBjb2RlAHUKdWFhAHMJAHEKAB8FAFAHAII7CAAPDwCBMAgAgmQHOiByZW5kZXIgcmVkaXJlY3Qgd2l0aABnBgCCLxJyZXNlbnQAOw4AgXYLaG9yaXplICsAew0AgUsFYXUATQgAgVsOCiBFeGNoYW5nZQCBWwUgZm9yIHRva2VucwCBVRZyZWZyZXNoLCBhY2Nlc3MAJAgAgWQPADsHAIM9E2Fzc29jAIRMBQBgBgCBaAZzZXNzaW9uAINLEgCCFRAAhHgIIACBLgZkLCBsb2dnZWQgaW4K&s=roundgreen>`_)

.. figure:: http://www.websequencediagrams.com/cgi-bin/cdraw?lz=YnJvd3Nlci0-cG9ydGFsOiBpbml0aWF0ZSByZXNldCBwYXNzd29yZApub3RlIG92ZXIgACIIZW1haWwgYQAiB2tleQoAPBFwb3N0ABYKIGFuZCBuZXcAOhsKIHZlcmlmeQBKC2VuZCBub3RlCgCBHAYtPmxvZ2luOiAvYXV0bwAHBSArAE0JICsAgRgHIHNlY3JldCBvbiBodHRwIGJhc2ljCgA2BS0-dWFhOgCBRgt1YWE6IAogQ3JlYXRlIHRlbXBvcmFyeSBjb2RlAHUKdWFhAHMJAHEKAB8FAFAHAII7CAAPDwCBMAgAgmQHOiByZW5kZXIgcmVkaXJlY3Qgd2l0aABnBgCCLxJyZXNlbnQAOw4AgXYLaG9yaXplICsAew0AgUsFYXUATQgAgVsOCiBFeGNoYW5nZQCBWwUgZm9yIHRva2VucwCBVRZyZWZyZXNoLCBhY2Nlc3MAJAgAgWQPADsHAIM9E2Fzc29jAIRMBQBgBgCBaAZzZXNzaW9uAINLEgCCFRAAhHgIIACBLgZkLCBsb2dnZWQgaW4K&s=roundgreen
   :align: center
   :alt:

Local development and deployment
================================

These apply if you are developing identity integration in your own
application, outside a bosh deployment scenario.

Requirements:

::

    java >= 17

Clone, build UAA server:

::

    git clone git@github.com:cloudfoundry/uaa.git
    cd uaa
    ./gradlew clean assemble


Run Servers (using the UAA version <X> from above):

::

    ./gradlew run


Configuration
=============

uaa.yml drives uaa behavior.  There is a default file in the WAR that
you should not touch.  Overrides and additions can come from an external
location, the most convenient way to specify that is through an
environment variable (or system property in the JVM) named CLOUDFOUNDRY\_CONFIG\_PATH.
The UAA will then look for a file named $CLOUDFOUNDRY\_CONFIG\_PATH/uaa.yml.

In addition to be able to override configuration through file based locations, complete Yaml can also be
written as an environment variable. For a Cloud Foundry application this could look like.

::

    ---
      applications:
      - name: standalone-uaa-cf-war
        memory: 4096M
        instances: 1
        host: standalone-uaa
        path: cloudfoundry-identity-uaa-0.0.0-SNAPSHOT.war
        env:
          JBP_CONFIG_SPRING_AUTO_RECONFIGURATION: '[enabled: false]'
          JBP_CONFIG_TOMCAT: '{tomcat: { version: 9.0.+ }}'
          SPRING_PROFILES_ACTIVE: hsqldb
          JAVA_OPTS: '-Djava.security.egd=file:/dev/./urandom -Dlogging.config=/usr/local/tomcat/conf/log4j2.properties'
          UAA_CONFIG_YAML: |
            uaa.url: http://standalone-uaa.cfapps.io
            login.url: http://standalone-uaa.cfapps.io
            smtp:
              host: mail.server.host
              port: 3535



Or as an alternative, set the yaml configuration as a string for an environment variable using the set-env command

::

    cf set-env sample-uaa-cf-war UAA_CONFIG_YAML '{ uaa.url: http://uaa.myapp.com, login.url: http://uaa.myapp.com, smtp: { host: mail.server.host, port: 3535 } }'

Database
--------

UAA will use an in-memory database that is torn down between runs unless
you choose a spring profile or a specific database configuration as a
toplevel setting in uaa.yml. An example connecting to a postgres
database:

.. code-block:: yaml

   database:
      driverClassName: org.postgresql.Driver
      url: jdbc:postgresql://localhost:5432/uaadb
      username: postgres
      password: password

Token signing
-------------

UAA supports either symmetric key encryption (shared secrets) or public
key encryption, however it is strongly recommended to use public key encryption.

.. code-block:: yaml

   jwt:
     token:
       policy:
         activeKeyId: key-id-1-or-better-a-UUID
         keys:
           key-id-1-or-better-a-UUID:
             signingAlg: RS256
             signingKey: …
             signingCert: …
           key-id-2-or-better-a-UUID:
             signingAlg: RS512
             signingKey: …

If you want to use symmetric key encryption, signing and verification values should be the same and the signingAlg can be from HS256 to HS512.
The public or asymmetric key encryption requires at least a signingKey. This key must be compatible to the signingAlg. If no parameter signingAlg is
specified the default either RS256 or HS256 is taken. The algorithm none is not supported. This default depends on the key and its format. For other
algorithms, e.g. see the supported ones in RFC 7518 (https://datatracker.ietf.org/doc/html/rfc7518#section-3.1), the signingKey must be compatible,
e.g. ES256. If you set signingCert, then the token_key endpoint contain the x5c claim with the PEM encoded X509 representation and x5t with its
thumbprint in order to have a unique identitfier. The value of x5c can be used as trust anchor towards OIDC Identity Proviers, e.g. Azure AD
from Microsoft and SAP Cloud Identity Service uses x509 as trust anchor for JWT client authentication.
If no signingCert is defined, then both claims does not appear in token_key response.

Generating new asymmetric key pairs for RSA based algorithm

::

    mkdir temp_uaa_certs
    cd temp_uaa_certs
    openssl genrsa -out privkey.pem 2048
    openssl rsa -pubout -in privkey.pem -out pubkey.pem

Generating new asymmetric key pairs for Elliptic Curve based algorithm, e.g. ES256

::

    openssl ecparam -genkey -name prime256v1 -noout -out ec256-key-pair.pem

Aysmmetric key pairs can be set directly in the yaml file using block literals.
Make sure the entire key is indented.

.. code-block:: yaml

   jwt:
     token:
       policy:
         activeKeyId: key-id-1-or-better-a-UUID
         keys:
           key-id-1-or-better-a-UUID:
             signingAlg: RS256
             signingKey: |
               -----BEGIN RSA PRIVATE KEY-----
               MIIEowIBAAKCAQEAyV3Ws3gLOvi169ZPx8v3t9UZpxcG0fqtQzC4X+Ff7dlx4w6P
               ...
               pYPYK4M+4Gwi7O49a63G+lzX7BqUWYBXR84iZG+vWz2F3ICjiOIz
               -----END RSA PRIVATE KEY-----
             signingCert: |
               -----BEGIN CERTIFICATE-----
               MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyV3Ws3gLOvi169ZPx8v3
               ...
               XwIDAQAB
               -----END PUBLIC KEY-----


Token signing rotation
----------------------

The key rotation is a change of parameter jwt.token.policy.activeKeyId. The key identifier of each entry appears in token_key response with
claim kid. It is the identifier for key resolution, therefore this definition should be unique. Parameter activeKeyId specifies the current active
key, which is used for signing the JWT based tokens (id_token, access_token, refresh_token), see UAA-Tokens.md. After the change of activeKeyId
the replaced key should not be removed but it should be kept some time in order to allow a signature verification for clients for a period of time.
If you use UAA as proxy to other OIDC Providers, then this communication can be protected with JWT authentication and the key for this JWT signing
can be different to the activeKeyId.


Clients
-------

Specify autoapprove in the client section when the user should not be
asked to approve a token grant expicitly. This
avoids redundant and annoying requests to grant permission when there is
not a reasonable need to ever deny them.

.. code-block:: yaml

   oauth:
      client:
         autoapprove:
            - cf
            - support-signon

Individual client settings in uaa.yml go in sections under “clients”
using the client name:

.. code-block:: yaml

   oauth:
      clients:
         portal:
            name: Portal App
            override: true
            scope: openid,cloud_controller.read,cloud_controller.write
            authorities: openid,cloud_controller.read,cloud_controller.write

Override defaults to false; when true, the client settings in this
section can override client settings saved if you have a persistent
database. It’s recommended to have this property present and set to
true; declare it as false only if you need the db to take precedence.

Access Control Data
-------------------

A scope specifies a privilege users can ask this client to assert on
their behalf.

An authority specifies a privilege the client can assert on its own.

User Bootstrapping
------------------

uaa.yml entries can used to set up users for development. This is not
suitable for staging or production but useful in testing. If you specified
a persistent db above and the
user account exists, it may not be updated with a new password.
Group membership will be updated automatically in a future release.

scim is a toplevel attribute in uaa.yml. Login, password, and groups can
be defined on the new user.

.. code-block:: yaml

   scim:
      users:
         - sre@vmware.com|apassword|scim.write,scim.read,openid

A scope cannot be added to a token granted by the UAA unless the user is
in the corresponding group with the same name (some default groups are
always available and do not need to be explicitly populated: openid,
password.write, cloud\_controller.read, cloud\_controller.write,
tokens.read, tokens.write).

Bosh development & debug
========================

Bosh deployments can be tricky to debug.

You should examine the steps of the flow you are expecting and find
the point at which it misbehaves. If any one point in the flow is broken, for example an
endpoint misconfigured or an identity test failing, you will see the
flow break down at that point.

vms to look at are uaa, login, and the vm with your client application.

Go the uaa machine to monitor logs with:

::

    bosh ssh uaa 0
    tail -f /var/vcap/sys/log/uaa/uaa.log

You can watch headers to confirm the kind of flow you want with tcpdump,
for example if you ssh into the login server:

::

    bosh ssh login 0
    sudo tcpdump 'tcp port 80 and host uaa.cf116.dev.las01.vcsops.com' -i any -A

uaac and cf can take a --trace option which shows each online interaction.

"uaac target" your uaa if you haven't already.

"uaac token decode" functions can be used to examine tokens.
Make sure attributes like scopes match what you expect.
This function can take a verification key to make sure the token is signed as you expect.

"uaac signing key" can be used to get the signing key the uaa server is using. Pass -c and -s
for a client to retrieve a symmetric key.


Live data viewing and manipulation
==================================

cf and uaac each need a target. cf points to a cloud controller and uaac to a uaa instance.

::

    cf target api.cf116.dev.las01.vcsops.com
    uaac target uaa.cf116.dev.las01.vcsops.com # dev deployment
    uaac target uaa.cfpartners.cloudfoundry.com # production
    uaac target localhost:8080/uaa # local dev

uaac context will contain clients or an end user id. These are added to
your context after authenticating.

::

    uaac token client get admin # default pass adminsecret
    uaac token client get cf
    uaac token client get dashboard # get dashboard context

Learn about your context

::

    uaac contexts # show your target and all contexts with it

You see scopes granted through this token. jti is a token identifier,
used for operations like deleting a token.

Access to Users and Groups
--------------------------

User, group, and client changes below will be persisted if you have UAA backed by a persistent db.

If your admin client is denied access to modify scim, you will need to
add scim.write to its authorities list, delete and get the token again.

::

    uaac client update admin --authorities "clients.write clients.read uaa.admin scim.read scim.write"
    uaac token delete
    uaac token client get admin

Manage Users
------------

The cf client can be used for user registrations:

::

    cf create-user sre@vmware.com mypassword
    uaac users # examine all users
    uaac user ids # look up user ids -- only works outside production

Register a new user

::

    uaac user add

Manage Groups
-------------

Groups limit what scopes an entity has and
what can be delegated by this client or user.

Make a user a member of the dashboard group to open the dashboard:

::

    uaac member add dashboard.user sre@vmware.com
    uaac -t user add --given_name Bill --emails bt@vmware.com --password test bt@vmware.com

Manage client registrations
---------------------------

Clients registrations can also be changed in a live system.

::

    uaac token client get admin # admin has client scopes
    uaac clients # list the clients uaa knows about

Create new clients:

::

    uaac client add media_server --scope openid,scim.read,scim.write --authorized_grant_types client_credentials --authorities oauth.login

UAA Signing
-----------

Tokens are signed by the UAA. Signatures are checked for validity. Get the configuration
of the UAA signing key if you are dealing with invalid token errors.

This will print the public key without requiring a password if using
public key verification:

::

    uaac signing key

if access is denied, use client credentials that allow access to the symmetric key:

::

    uaac signing key -c admin -s adminsecret

Additional Resources
====================

UAA documentation in docs/

#. UAA-APIs.rst: API document, kept updated
#. UAA-CC-ACM-CF-Interactions.rst: flows for operations between parts
#. UAA-Overview.rst: comparisons with oauth2
#. UAA-Security.md: accounts, bootstrapping, scopes for access control
#. UAA\_presentation.pdf: Overview presentation, outline for internal developers
#. CF-Identity-Services-Preface.rst: justification and design overview

Login-server documentation in docs/

#. Login-APIs.md: login-server specifics like autologin

Improving this Document
=======================

#. Hyperlink other documentation
#. Link from main README
#. Expand examples for tcpdump and debugging
