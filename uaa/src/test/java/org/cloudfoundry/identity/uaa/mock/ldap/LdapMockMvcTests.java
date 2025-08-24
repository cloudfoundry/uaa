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
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.io.File;

import static org.assertj.core.api.Assertions.fail;
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

    LdapSimpleBindTest() {
        super(
                "ldap-simple-bind.xml",
                "ldap-groups-null.xml",
                LDAP_TLS_NONE
        );
    }

    @BeforeAll
    static void beforeAll() {
        ldapContainer = InMemoryLdapServer.startLdap();
    }

    @AfterAll
    static void afterAll() {
        ldapContainer.stop();
    }

    @Override
    protected void ensureLdapServerIsRunning() {
        if (!ldapContainer.isRunning()) {
            ldapContainer = InMemoryLdapServer.startLdap();
        }
    }

    @Override
    protected void stopLdapServer() {
        if (ldapContainer.isRunning()) {
            ldapContainer.stop();
        }
    }

    @Override
    protected String getLdapUrl() {
        return ldapContainer.getUrl();
    }
}

class LdapSearchAndCompareTest extends AbstractLdapMockMvcTest {
    private static InMemoryLdapServer ldapContainer;

    LdapSearchAndCompareTest() {
        super(
                "ldap-search-and-compare.xml",
                "ldap-groups-as-scopes.xml",
                LDAP_TLS_NONE
        );
    }

    @BeforeAll
    static void beforeAll() {
        ldapContainer = InMemoryLdapServer.startLdapWithTls(KEYSTORE);
    }

    @AfterAll
    static void afterAll() {
        ldapContainer.stop();
    }

    @Override
    protected void ensureLdapServerIsRunning() {
        if (!ldapContainer.isRunning()) {
            ldapContainer = InMemoryLdapServer.startLdapWithTls(KEYSTORE);
        }
    }

    @Override
    protected void stopLdapServer() {
        if (ldapContainer.isRunning()) {
            ldapContainer.stop();
        }
    }

    @Override
    protected String getLdapUrl() {
        return ldapContainer.getUrl();
    }
}

class LdapSearchAndBindTest extends AbstractLdapMockMvcTest {
    private static InMemoryLdapServer ldapContainer;

    LdapSearchAndBindTest() {
        super(
                "ldap-search-and-bind.xml",
                "ldap-groups-map-to-scopes.xml",
                LDAP_TLS_NONE
        );
    }

    @BeforeAll
    static void beforeAll() {
        ldapContainer = InMemoryLdapServer.startLdapWithTls(KEYSTORE);
    }

    @AfterAll
    static void afterAll() {
        ldapContainer.stop();
    }

    @Override
    protected void ensureLdapServerIsRunning() {
        if (!ldapContainer.isRunning()) {
            ldapContainer = InMemoryLdapServer.startLdapWithTls(KEYSTORE);
        }
    }

    @Override
    protected void stopLdapServer() {
        if (ldapContainer.isRunning()) {
            ldapContainer.stop();
        }
    }

    @Override
    protected String getLdapUrl() {
        return ldapContainer.getUrl();
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
                    getLdapUrl(),
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
            File expiredKeystore = new File(getClass().getClassLoader().getResource("certs/expired-self-signed-ldap-cert.jks").getFile());
            try (InMemoryLdapServer inMemoryLdapServer = InMemoryLdapServer.startLdapWithTls(expiredKeystore)) {
                definition.setBaseUrl(inMemoryLdapServer.getUrl());
                definition.setSkipSSLVerification(false);

                getMockMvc().perform(
                                baseRequest.content(JsonUtils.writeValueAsString(request)))
                        .andDo(print())
                        .andExpect(status().isBadRequest())
                        .andExpect(content().string(containsString("Caused by:")));
            } catch (Exception ignored) {
                fail("should not be able to connect to LDAP server");
            }
        }
    }
}
