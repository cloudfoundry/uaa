<?php

$config = [

    // This is a authentication source which handles admin authentication.
    'admin' => [
        // The default is to use core:AdminPassword, but it can be replaced with
        // any authentication source.

        'core:AdminPassword',
    ],


    // An authentication source which can authenticate against both SAML 2.0
    // and Shibboleth 1.3 IdPs.
    'default-sp' => [
        'saml:SP',

        // The entity ID of this SP.
        // Can be NULL/unset, in which case an entity ID is generated based on the metadata URL.
        'entityID' => null,

        // The entity ID of the IdP this SP should contact.
        // Can be NULL/unset, in which case the user will be shown a list of available IdPs.
        'idp' => null,

        // The URL to the discovery service.
        // Can be NULL/unset, in which case a builtin discovery service will be used.
        'discoURL' => null,

        /*
         * The attributes parameter must contain an array of desired attributes by the SP.
         * The attributes can be expressed as an array of names or as an associative array
         * in the form of 'friendlyName' => 'name'. This feature requires 'name' to be set.
         * The metadata will then be created as follows:
         * <md:RequestedAttribute FriendlyName="friendlyName" Name="name" />
         */
        /*
        'name' => [
            'en' => 'A service',
            'no' => 'En tjeneste',
        ],

        'attributes' => [
            'attrname' => 'urn:oid:x.x.x.x',
        ],
        'attributes.required' => [
            'urn:oid:x.x.x.x',
        ],
        */
    ],

    'example-userpass' => [
        'exampleauth:UserPass',

        // Give the user an option to save their username for future login attempts
        // And when enabled, what should the default be, to save the username or not
        'remember.username.enabled' => TRUE,
        'remember.username.checked' => TRUE,

        'marissa:koala' => [
            'uid' => 'marissa@test.org',
            'eduPersonAffiliation' => ['member', 'marissa'],
            'emailAddress' => 'marissa@test.org'
        ],

        'marissa2:saml2' => [
            'uid' => 'marissa2@test.org',
            'eduPersonAffiliation' => ['member', 'marissa2'],
            'emailAddress' => 'marissa2@test.org'
        ],

        'marissa3:saml2' => [
            'uid' => 'marissa3@test.org',
            'eduPersonAffiliation' => ['member', 'marissa3'],
            'emailAddress' => 'marissa3@test.org'
        ],

        'marissa4:saml2' => [
            'uid' => 'marissa4',
            'eduPersonAffiliation' => ['member', 'marissa4'],
            'emailAddress' => 'marissa4@test.org',
            'groups' => ['saml.user', 'saml.admin'],
        ],

        'marissa5:saml5' => [
            'uid' => 'marissa5',
            'eduPersonAffiliation' => ['member', 'marissa5'],
            'emailAddress' => 'marissa5@test.org',
            'groups' => ['saml.user', 'saml.admin'],
            'costCenter' => 'Denver,CO',
            'manager' => ['John the Sloth', 'Kari the Ant Eater'],
        ],

        'marissa6:saml6' => [
            'uid' => 'marissa6',
            'eduPersonAffiliation' => ['member'],
            'emailAddress' => 'marissa6@test.org',
            'groups' => ['saml.user', 'saml.admin'],
            'costCenter' => 'Denver,CO',
            'manager' => ['John the Sloth', 'Kari the Ant Eater'],
        ],

        'user_only_for_invitations_test:saml' => [
            'uid' => 'user_only_for_invitations_test',
            'eduPersonAffiliation' => ['member', 'user_only_for_invitations_test'],
            'emailAddress' => 'testinvite@test.org',
            'groups' => ['saml.user', 'saml.admin'],
            'costCenter' => 'Denver,CO',
            'manager' => ['John the Sloth', 'Kari the Ant Eater'],
        ],

        'user:password' => [
            'uid' => 'testuser@spring.security.saml',
            'eduPersonAffiliation' => ['member', 'user'],
            'emailAddress' => 'testuser@spring.security.saml'
        ],
    ],




];