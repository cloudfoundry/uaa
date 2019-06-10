package org.cloudfoundry.identity.uaa.mock.ldap;

import org.cloudfoundry.identity.uaa.mock.util.ApacheDSHelper;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.security.ldap.server.ApacheDsSSLContainer;

import java.util.concurrent.atomic.AtomicInteger;

import static org.cloudfoundry.identity.uaa.mock.ldap.LdapMockMvcTests.getRandomPort;
import static org.cloudfoundry.identity.uaa.provider.ldap.ProcessLdapProperties.NONE;
import static org.cloudfoundry.identity.uaa.provider.ldap.ProcessLdapProperties.SIMPLE;

class LdapMockMvcTests {
    private static AtomicInteger portOffset = new AtomicInteger(0);

    synchronized static int getRandomPort() {
        return 44389 + portOffset.getAndIncrement();
    }
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
    private static ApacheDsSSLContainer apacheDs;
    private static int ldapPort = getRandomPort();
    private static int ldapSPort = getRandomPort();

    LdapSimpleBindTest() {
        super(
                "ldap-simple-bind.xml",
                "ldap-groups-null.xml",
                "ldap://localhost:" + ldapPort,
                NONE
        );
    }

    @BeforeAll
    static void beforeAll() throws Exception {
        apacheDs = ApacheDSHelper.start(ldapPort, ldapSPort);
    }

    @AfterAll
    static void afterAll() {
        apacheDs.stop();
    }

    @Override
    protected void ensureLdapServerIsRunning() throws Exception {
        if (!apacheDs.isRunning()) {
            apacheDs = ApacheDSHelper.start(ldapPort, ldapSPort);
        }
    }

    @Override
    protected void stopLdapServer() {
        if (apacheDs.isRunning()) {
            apacheDs.stop();
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
    private static ApacheDsSSLContainer apacheDs;
    private static int ldapPort = getRandomPort();
    private static int ldapSPort = getRandomPort();

    LdapSearchAndCompareTest() {
        super(
                "ldap-search-and-compare.xml",
                "ldap-groups-as-scopes.xml",
                "ldaps://localhost:" + ldapSPort,
                NONE
        );
    }

    @BeforeAll
    static void beforeAll() throws Exception {
        apacheDs = ApacheDSHelper.start(ldapPort, ldapSPort);
    }

    @AfterAll
    static void afterAll() {
        apacheDs.stop();
    }

    @Override
    protected void ensureLdapServerIsRunning() throws Exception {
        if (!apacheDs.isRunning()) {
            apacheDs = ApacheDSHelper.start(ldapPort, ldapSPort);
        }
    }

    @Override
    protected void stopLdapServer() {
        if (apacheDs.isRunning()) {
            apacheDs.stop();
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
    private static ApacheDsSSLContainer apacheDs;
    private static int ldapPort = getRandomPort();
    private static int ldapSPort = getRandomPort();

    LdapSearchAndBindTest() {
        super(
                "ldap-search-and-bind.xml",
                "ldap-groups-map-to-scopes.xml",
                "ldap://localhost:" + ldapPort,
                SIMPLE
        );
    }

    @BeforeAll
    static void beforeAll() throws Exception {
        apacheDs = ApacheDSHelper.start(ldapPort, ldapSPort);
    }

    @AfterAll
    static void afterAll() {
        apacheDs.stop();
    }

    @Override
    protected void ensureLdapServerIsRunning() throws Exception {
        if (!apacheDs.isRunning()) {
            apacheDs = ApacheDSHelper.start(ldapPort, ldapSPort);
        }
    }

    @Override
    protected void stopLdapServer() {
        if (apacheDs.isRunning()) {
            apacheDs.stop();
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
