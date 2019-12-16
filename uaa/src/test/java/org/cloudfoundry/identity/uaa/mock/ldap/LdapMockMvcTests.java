package org.cloudfoundry.identity.uaa.mock.ldap;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderValidationRequest;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.test.InMemoryLdapServer;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.jupiter.api.*;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_TLS_NONE;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

class LdapMockMvcTests {
    // See below for actual tests. This class is just to set the filename.
}

// All of the copied and pasted code between the three classes below
// is because it is quite expensive to start an LDAP Server in the BeforeEach,
// and because we would like these three classes to use different port
// numbers so these test classes can be run in parallel.
//
// At the time of writing, caching the LDAP Server like this is saving us
// 30 seconds off our test time.
//
// Since JUnit BeforeAll's must be static, each of these classes
// needs to have copy/pasted static members and methods.

class LdapSimpleBindTest extends AbstractLdapMockMvcTest {
    private static InMemoryLdapServer ldapContainer;
    private static int ldapPort = 44389;

    LdapSimpleBindTest() {
        super(
                "ldap-simple-bind.xml",
                "ldap-groups-null.xml",
                LDAP_TLS_NONE
        );
    }

    @BeforeAll
    static void beforeAll() {
        ldapContainer = InMemoryLdapServer.startLdap(ldapPort);
    }

    @AfterAll
    static void afterAll() {
        ldapContainer.stop();
    }

    @Override
    protected void ensureLdapServerIsRunning() {
        if (!ldapContainer.isRunning()) {
            ldapContainer = InMemoryLdapServer.startLdap(ldapPort);
        }
    }

    @Override
    protected void stopLdapServer() {
        if (ldapContainer.isRunning()) {
            ldapContainer.stop();
        }
    }

    @Override
    protected String getLdapOrLdapSBaseUrl() {
        return "ldap://localhost:" + ldapPort;
    }
}

class LdapSearchAndCompareTest extends AbstractLdapMockMvcTest {
    private static InMemoryLdapServer ldapContainer;
    private static int ldapPort = 44390;
    private static int ldapSPort = 44337;

    LdapSearchAndCompareTest() {
        super(
                "ldap-search-and-compare.xml",
                "ldap-groups-as-scopes.xml",
                LDAP_TLS_NONE
        );
    }

    @BeforeAll
    static void beforeAll() {
        ldapContainer = InMemoryLdapServer.startLdapWithTls(ldapPort, ldapSPort, KEYSTORE);
    }

    @AfterAll
    static void afterAll() {
        ldapContainer.stop();
    }

    @Override
    protected void ensureLdapServerIsRunning() {
        if (!ldapContainer.isRunning()) {
            ldapContainer = InMemoryLdapServer.startLdapWithTls(ldapPort, ldapSPort, KEYSTORE);
        }
    }

    @Override
    protected void stopLdapServer() {
        if (ldapContainer.isRunning()) {
            ldapContainer.stop();
        }
    }

    @Override
    protected String getLdapOrLdapSBaseUrl() {
        return "ldaps://localhost:" + ldapSPort;
    }
}

class LdapSearchAndBindTest extends AbstractLdapMockMvcTest {
    private static InMemoryLdapServer ldapContainer;
    private static int ldapPort = 44391;
    private static int ldapSPort = 44338;

    LdapSearchAndBindTest() {
        super(
                "ldap-search-and-bind.xml",
                "ldap-groups-map-to-scopes.xml",
                LDAP_TLS_NONE
        );
    }

    @BeforeAll
    static void beforeAll() {
        ldapContainer = InMemoryLdapServer.startLdapWithTls(ldapPort, ldapSPort, KEYSTORE);
    }

    @AfterAll
    static void afterAll() {
        ldapContainer.stop();
    }

    @Override
    protected void ensureLdapServerIsRunning() {
        if (!ldapContainer.isRunning()) {
            ldapContainer = InMemoryLdapServer.startLdapWithTls(ldapPort, ldapSPort, KEYSTORE);
        }
    }

    @Override
    protected void stopLdapServer() {
        if (ldapContainer.isRunning()) {
            ldapContainer.stop();
        }
    }

    @Override
    protected String getLdapOrLdapSBaseUrl() {
        return "ldap://localhost:" + ldapPort;
    }

    @Nested
    @DefaultTestContext
    class LdapConfiguration {

        private IdentityProvider<LdapIdentityProviderDefinition> identityProvider;
        private LdapIdentityProviderDefinition definition;
        private IdentityProviderValidationRequest request;
        private MockHttpServletRequestBuilder baseRequest;
        private String identityAccessToken;

        @BeforeEach
        void setUp() throws Exception {
            IdentityProviderValidationRequest.UsernamePasswordAuthentication validUserCredentials = new IdentityProviderValidationRequest.UsernamePasswordAuthentication("marissa2", LDAP);
            identityAccessToken = MockMvcUtils.getClientOAuthAccessToken(getMockMvc(), "identity", "identitysecret", "");
            final String adminAccessToken = MockMvcUtils.getClientOAuthAccessToken(getMockMvc(), "admin", "adminsecret", "");
            IdentityZone zone = MockMvcUtils.createZoneUsingWebRequest(getMockMvc(), identityAccessToken);
            String zoneAdminToken = MockMvcUtils.getZoneAdminToken(getMockMvc(), adminAccessToken, zone.getId());

            definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
                    getLdapOrLdapSBaseUrl(),
                    "cn=admin,ou=Users,dc=test,dc=com",
                    "adminsecret",
                    "dc=test,dc=com",
                    "cn={0}",
                    "ou=scopes,dc=test,dc=com",
                    "member={0}",
                    "mail",
                    null,
                    false,
                    true,
                    true,
                    10,
                    true
            );

            identityProvider = new IdentityProvider<>();
            identityProvider.setOriginKey(LDAP);
            identityProvider.setName("Test ldap provider");
            identityProvider.setType(LDAP);
            identityProvider.setActive(true);
            identityProvider.setIdentityZoneId(zone.getId());
            identityProvider.setConfig(definition);

            request = new IdentityProviderValidationRequest(identityProvider, validUserCredentials);

            baseRequest = post("/identity-providers/test")
                    .header("Accept", APPLICATION_JSON_VALUE)
                    .header("Content-Type", APPLICATION_JSON_VALUE)
                    .header("Authorization", "Bearer " + zoneAdminToken)
                    .contentType(APPLICATION_JSON)
                    .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());
        }

        @Test
        void happyPath() throws Exception {
            getMockMvc().perform(
                    baseRequest.content(JsonUtils.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(content().string("\"ok\""));
        }

        @Test
        void invalidUserCredentials() throws Exception {
            IdentityProviderValidationRequest.UsernamePasswordAuthentication invalidUserCredentials
                    = new IdentityProviderValidationRequest.UsernamePasswordAuthentication("marissa2", "!!! BAD PASSWORD !!!");
            IdentityProviderValidationRequest invalidUserRequest = new IdentityProviderValidationRequest(identityProvider, invalidUserCredentials);

            getMockMvc().perform(
                    baseRequest.content(JsonUtils.writeValueAsString(invalidUserRequest)))
                    .andExpect(status().isExpectationFailed())
                    .andExpect(content().string("\"bad credentials\""));
        }

        @Test
        void insufficientScope() throws Exception {
            IdentityZone zone = MockMvcUtils.createZoneUsingWebRequest(getMockMvc(), identityAccessToken);

            MockHttpServletRequestBuilder post = post("/identity-providers/test")
                    .header("Accept", APPLICATION_JSON_VALUE)
                    .header("Content-Type", APPLICATION_JSON_VALUE)
                    .header("Authorization", "Bearer " + identityAccessToken)
                    .contentType(APPLICATION_JSON)
                    .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());

            getMockMvc().perform(post)
                    .andExpect(status().isForbidden());
        }

        @Test
        void invalidBindPassword() throws Exception {
            definition.setBindPassword("!!!!!!!INVALID_BIND_PASSWORD!!!!!!!");

            getMockMvc().perform(
                    baseRequest.content(JsonUtils.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
                    .andExpect(content().string(containsString("Caused by:")));
        }

        @Test
        void invalidLdapUrl() throws Exception {
            definition.setBaseUrl("ldap://foobar:9090");

            getMockMvc().perform(
                    baseRequest.content(JsonUtils.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
                    .andExpect(content().string(containsString("Caused by:")));
        }

        @Test
        void invalidSearchBase() throws Exception {
            definition.setUserSearchBase(",,,,,dc=INVALID,dc=SEARCH_BASE");

            getMockMvc().perform(
                    baseRequest.content(JsonUtils.writeValueAsString(request)))
                    .andExpect(status().isBadRequest())
                    .andExpect(content().string(containsString("Caused by:")));
        }

        /**
         * TODO: We're not sure what this test is trying to do
         * Is the UAA SSL configuration invalid?
         * Is the LDAP server configuration invalid?
         */
        @Test
        void unableToConnectToLdapWithInvalidSsl() {
            int port = 37000 + getRandomPortOffset();
            int sslPort = 38000 + getRandomPortOffset();

            try (InMemoryLdapServer inMemoryLdapServer = InMemoryLdapServer.startLdapWithTls(port, sslPort, null)) {
                definition.setBaseUrl(inMemoryLdapServer.getLdapSBaseUrl());
                definition.setSkipSSLVerification(false);

                getMockMvc().perform(
                        baseRequest.content(JsonUtils.writeValueAsString(request)))
                        .andDo(print())
                        .andExpect(status().isBadRequest())
                        .andExpect(content().string(containsString("Caused by:")));
            } catch (Exception ignored) {

            }
        }

        /**
         * TODO: We're not sure what this test is trying to do
         * Is the UAA SSL configuration invalid?
         * Is the LDAP server configuration invalid?
         */
        @Test
        void ableToConnectToLdapWithInvalidSsl_WithSkipValidation() throws Exception {
            definition.setBaseUrl("ldaps://localhost:" + ldapSPort);

            getMockMvc().perform(
                    baseRequest.content(JsonUtils.writeValueAsString(request)))
                    .andExpect(status().isOk())
                    .andExpect(content().string("\"ok\""));
        }
    }
}
