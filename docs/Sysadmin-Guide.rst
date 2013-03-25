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

The login server component is separate from UAA so it can present an
appropriate visual rendering of the login page and authentication
interfaces.

The login server also has additional logic to support the autologin
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

    maven 3.0.4
    java >= 1.6

Older versions of maven will likely appear to work at first but
eventually fail with an unhelpful error. Be sure mvn -v reports 3.0.4.
It’s best if you only have one version installed.

Clone, build UAA server:

::

    git clone git@github.com:cloudfoundry/uaa.git
    cd uaa
    mvn clean install

Note the version number that you just built (e.g. look in the pom or in
uaa/target for the version label on the WAR file).

Clone, build login-server:

::

    git clone git@github.com:cloudfoundry/login-server.git
    cd login-server
    mvn clean install

Run Servers (using the UAA version <X> from above):

::

    cd login-server && mvn tomcat:run -P integration 

You can add -Didentity.version=<X> if you need to match a specific UAA build.

or to just run the UAA: 

::

    cd uaa && mvn tomcat7:run)

Configuration
=============

uaa.yml drives uaa behavior.  There is a default file in the WAR that
you should not touch.  Overrides and additions can come from an external
location, the most convenient way to specify that is through an
environment variable (or system property in the JVM):
$CLOUDFOUNDRY\_CONFIG\_PATH/uaa.yml.

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

UAA can use either symmetric key encryption (shared secrets) or public
key encryption.

.. code-block:: yaml

   jwt:
      token:
         signing-key: …
         verification-key: …

If you want to use symmetric key encryption, signing and verification values should be the same.

Generating new asymmetric key pairs

::

    mkdir temp_uaa_certs
    cd temp_uaa_certs
    openssl genrsa -out privkey.pem 2048
    openssl rsa -pubout -in privkey.pem -out pubkey.pem

Aysmmetric key pairs can be set directly in the yaml file using block literals.
Make sure the entire key is indented.

.. code-block:: yaml

   jwt:
      token:
         signing-key: |
            -----BEGIN RSA PRIVATE KEY-----
            MIIEowIBAAKCAQEAyV3Ws3gLOvi169ZPx8v3t9UZpxcG0fqtQzC4X+Ff7dlx4w6P
            ...
            pYPYK4M+4Gwi7O49a63G+lzX7BqUWYBXR84iZG+vWz2F3ICjiOIz
            -----END RSA PRIVATE KEY-----
         verification-key: |
            -----BEGIN PUBLIC KEY-----
            MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyV3Ws3gLOvi169ZPx8v3
            ...
            XwIDAQAB
            -----END PUBLIC KEY-----

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
            - vmc
            - support-signon

Individual client settings in uaa.yml go in sections under “clients”
using the client name:

.. code-block:: yaml

   oauth:
      clients:
         portal:
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

uaac and vmc can take a --trace option which shows each online interaction.

"uaa target" your uaa if you haven't already.

"uaac token decode" functions can be used to examine tokens. 
Make sure attributes like scopes match what you expect. 
This function can take a verification key to make sure the token is signed as you expect.

"uaac signing key" can be used to get the signing key the uaa server is using. Pass -c and -s
for a client to retrieve a symmetric key.


Live data viewing and manipulation
==================================

vmc and uaac each need a target. vmc points to a cloud controller and uaac to a uaa instance.

::

    vmc target api.cf116.dev.las01.vcsops.com
    uaac target uaa.cf116.dev.las01.vcsops.com # dev deployment
    uaac target uaa.cfpartners.cloudfoundry.com # production
    uaac target localhost:8080/uaa # local dev

uaac context will contain clients or an end user id. These are added to
your context after authenticating.

::

    uaac token client get admin # default pass adminsecret
    uaac token client get vmc
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

The vmc client can be used for user registrations:

::

    vmc add-user --email sre@vmware.com # prompts for new password
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

Run vcap yeti tests with a deployment
-------------------------------------

Put in .bash\_profile or another script you source:

::

    export VCAP_BVT_TARGET=api.cf116.dev.las01.vcsops.com
    export VCAP_BVT_USER=sre@vmware.com
    export VCAP_BVT_USER_PASSWD=an_admin_pw

Make sre@vmware.com an admin if you want to do parallel yeti tests

::

    uaac user update sre@vmware.com --authorities "cloud_controller.admin"

Manually deploy an app

::

    vmc login
    vmc create-org org1
    vmc login
    vmc create-space space1
    vmc login # select space1
    vmc push # in an app dir

Execute the yeti suite with retries in case of timeouts

::

    vmc target api.cf116.dev.las01.vcsops.com
    vmc login # sre@vmware.com
    vmc add-user --email admin@vmware.com
    git clone https://github.com/cloudfoundry/vcap-yeti.git
    cd vcap-yeti
    git checkout
    ./update
    bundle exec rake full rerun_failure # admin@vmware.com test

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

    vmc signing key -c admin -s adminsecret

Additional Resources
====================

UAA documentation in docs/

#. UAA-APIs.rst: API document, kept updated
#. UAA-CC-ACM-VMC-Interactions.rst: flows for operations between parts
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
