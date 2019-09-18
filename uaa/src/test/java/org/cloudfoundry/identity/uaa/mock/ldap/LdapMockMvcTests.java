package org.cloudfoundry.identity.uaa.mock.ldap;

import org.cloudfoundry.identity.uaa.mock.util.ApacheDSHelper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.security.ldap.server.ApacheDsSSLContainer;

import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_TLS_NONE;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_TLS_SIMPLE;

class LdapMockMvcTests {
    // See below for actual tests. This class is just to set the filename.
}

// All of the copied and pasted code between the three classes below
// is because it is quite expensive to start ApacheDS in the BeforeEach,
// and because we would like these three classes to use different port
// numbers so these test classes can be run in parallel.
//
// At the time of writing, caching the ApacheDs server like this is saving us
// 30 seconds off our test time.
//
// Since JUnit BeforeAll's must be static, each of these classes
// needs to have copy/pasted static members and methods.

class LdapSimpleBindTest extends AbstractLdapMockMvcTest {
    private static ApacheDsSSLContainer ldapContainer;
    private static int ldapPort = 44389;
    private static int ldapSPort = 44336;

    LdapSimpleBindTest() {
        super(
                "ldap-simple-bind.xml",
                "ldap-groups-null.xml",
                "ldap://localhost:" + ldapPort,
                LDAP_TLS_NONE
        );
    }

    @BeforeAll
    static void beforeAll() throws Exception {
        ldapContainer = ApacheDSHelper.start(ldapPort, ldapSPort);
    }

    @AfterAll
    static void afterAll() {
        ldapContainer.stop();
    }

    @Override
    protected void ensureLdapServerIsRunning() throws Exception {
        if (!ldapContainer.isRunning()) {
            ldapContainer = ApacheDSHelper.start(ldapPort, ldapSPort);
        }
    }

    @Override
    protected void stopLdapServer() {
        if (ldapContainer.isRunning()) {
            ldapContainer.stop();
        }
    }

    @Override
    protected int getLdapPort() {
        return ldapPort;
    }

    @Override
    protected int getLdapSPort() {
        return ldapSPort;
    }
}

class LdapSearchAndCompareTest extends AbstractLdapMockMvcTest {
    private static ApacheDsSSLContainer ldapContainer;
    private static int ldapPort = 44390;
    private static int ldapSPort = 44337;

    LdapSearchAndCompareTest() {
        super(
                "ldap-search-and-compare.xml",
                "ldap-groups-as-scopes.xml",
                "ldaps://localhost:" + ldapSPort,
                LDAP_TLS_NONE
        );
    }

    @BeforeAll
    static void beforeAll() throws Exception {
        ldapContainer = ApacheDSHelper.start(ldapPort, ldapSPort);
    }

    @AfterAll
    static void afterAll() {
        ldapContainer.stop();
    }

    @Override
    protected void ensureLdapServerIsRunning() throws Exception {
        if (!ldapContainer.isRunning()) {
            ldapContainer = ApacheDSHelper.start(ldapPort, ldapSPort);
        }
    }

    @Override
    protected void stopLdapServer() {
        if (ldapContainer.isRunning()) {
            ldapContainer.stop();
        }
    }

    @Override
    protected int getLdapPort() {
        return ldapPort;
    }

    @Override
    protected int getLdapSPort() {
        return ldapSPort;
    }
}

class LdapSearchAndBindTest extends AbstractLdapMockMvcTest {
    private static ApacheDsSSLContainer ldapContainer;
    private static int ldapPort = 44391;
    private static int ldapSPort = 44338;

    LdapSearchAndBindTest() {
        super(
                "ldap-search-and-bind.xml",
                "ldap-groups-map-to-scopes.xml",
                "ldap://localhost:" + ldapPort,
                LDAP_TLS_SIMPLE
        );
    }

    @BeforeAll
    static void beforeAll() throws Exception {
        ldapContainer = ApacheDSHelper.start(ldapPort, ldapSPort);
    }

    @AfterAll
    static void afterAll() {
        ldapContainer.stop();
    }

    @Override
    protected void ensureLdapServerIsRunning() throws Exception {
        if (!ldapContainer.isRunning()) {
            ldapContainer = ApacheDSHelper.start(ldapPort, ldapSPort);
        }
    }

    @Override
    protected void stopLdapServer() {
        if (ldapContainer.isRunning()) {
            ldapContainer.stop();
        }
    }

    @Override
    protected int getLdapPort() {
        return ldapPort;
    }

    @Override
    protected int getLdapSPort() {
        return ldapSPort;
    }
}
