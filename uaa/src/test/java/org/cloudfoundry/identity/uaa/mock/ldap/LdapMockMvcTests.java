package org.cloudfoundry.identity.uaa.mock.ldap;

import static org.cloudfoundry.identity.uaa.provider.ldap.ProcessLdapProperties.NONE;
import static org.cloudfoundry.identity.uaa.provider.ldap.ProcessLdapProperties.SIMPLE;

class LdapMockMvcTests {
    // See below for actual tests. This class is just to set the filename.
}

class LdapSimpleBindTest extends AbstractLdapMockMvcTest {
    LdapSimpleBindTest() {
        super(
                "ldap-simple-bind.xml",
                "ldap-groups-null.xml",
                "ldap://localhost:33389",
                NONE
        );
    }
}

class LdapSearchAndCompareTest extends AbstractLdapMockMvcTest {
    LdapSearchAndCompareTest() {
        super(
                "ldap-search-and-compare.xml",
                "ldap-groups-as-scopes.xml",
                "ldaps://localhost:33636",
                NONE
        );
    }
}

class LdapSearchAndBindTest extends AbstractLdapMockMvcTest {
    LdapSearchAndBindTest() {
        super(
                "ldap-search-and-bind.xml",
                "ldap-groups-map-to-scopes.xml",
                "ldap://localhost:33389",
                SIMPLE
        );
    }
}
