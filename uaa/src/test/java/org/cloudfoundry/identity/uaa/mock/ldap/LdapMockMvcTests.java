package org.cloudfoundry.identity.uaa.mock.ldap;

import org.cloudfoundry.identity.uaa.mock.util.ApacheDSHelper;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderValidationRequest;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.security.ldap.server.ApacheDsSSLContainer;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.LDAP;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_TLS_NONE;
import static org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition.LDAP_TLS_SIMPLE;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assumptions.assumeTrue;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

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
    protected String getLdapOrLdapSBaseUrl() {
        return "ldap://localhost:" + ldapPort;
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
    protected String getLdapOrLdapSBaseUrl() {
        return "ldaps://localhost:" + ldapSPort;
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
    protected String getLdapOrLdapSBaseUrl() {
        return "ldap://localhost:" + ldapPort;
    }

    @Test
    void testLdapConfigurationBeforeSave() throws Exception {
        String identityAccessToken = MockMvcUtils.getClientOAuthAccessToken(getMockMvc(), "identity", "identitysecret", "");
        String adminAccessToken = MockMvcUtils.getClientOAuthAccessToken(getMockMvc(), "admin", "adminsecret", "");
        IdentityZone zone = MockMvcUtils.createZoneUsingWebRequest(getMockMvc(), identityAccessToken);
        String zoneAdminToken = MockMvcUtils.getZoneAdminToken(getMockMvc(), adminAccessToken, zone.getId());

        LdapIdentityProviderDefinition definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
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

        IdentityProvider provider = new IdentityProvider();
        provider.setOriginKey(LDAP);
        provider.setName("Test ldap provider");
        provider.setType(LDAP);
        provider.setConfig(definition);
        provider.setActive(true);
        provider.setIdentityZoneId(zone.getId());

        IdentityProviderValidationRequest.UsernamePasswordAuthentication token = new IdentityProviderValidationRequest.UsernamePasswordAuthentication("marissa2", LDAP);

        IdentityProviderValidationRequest request = new IdentityProviderValidationRequest(provider, token);
        System.out.println("request = \n" + JsonUtils.writeValueAsString(request));
        //Happy Day Scenario
        MockHttpServletRequestBuilder post = post("/identity-providers/test")
                .header("Accept", APPLICATION_JSON_VALUE)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + zoneAdminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request))
                .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());

        MvcResult result = getMockMvc().perform(post)
                .andExpect(status().isOk())
                .andReturn();

        assertEquals("\"ok\"", result.getResponse().getContentAsString());

        //Correct configuration, invalid credentials
        token = new IdentityProviderValidationRequest.UsernamePasswordAuthentication("marissa2", "koala");
        request = new IdentityProviderValidationRequest(provider, token);
        post = post("/identity-providers/test")
                .header("Accept", APPLICATION_JSON_VALUE)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + zoneAdminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request))
                .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());

        result = getMockMvc().perform(post)
                .andExpect(status().isExpectationFailed())
                .andReturn();
        assertEquals("\"bad credentials\"", result.getResponse().getContentAsString());

        //Insufficent scope
        post = post("/identity-providers/test")
                .header("Accept", APPLICATION_JSON_VALUE)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + identityAccessToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request))
                .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());

        getMockMvc().perform(post).andExpect(status().isForbidden()).andReturn();


        //Invalid LDAP configuration - change the password of search user
        definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
                getLdapOrLdapSBaseUrl(),
                "cn=admin,ou=Users,dc=test,dc=com",
                "adminsecret23",
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
        provider.setConfig(definition);
        request = new IdentityProviderValidationRequest(provider, token);
        post = post("/identity-providers/test")
                .header("Accept", APPLICATION_JSON_VALUE)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + zoneAdminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request))
                .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());

        result = getMockMvc().perform(post)
                .andExpect(status().isBadRequest())
                .andReturn();
        assertThat(result.getResponse().getContentAsString(), containsString("Caused by:"));

        //Invalid LDAP configuration - no ldap server
        definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
                "ldap://foobar:9090",
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
        provider.setConfig(definition);
        request = new IdentityProviderValidationRequest(provider, token);
        post = post("/identity-providers/test")
                .header("Accept", APPLICATION_JSON_VALUE)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + zoneAdminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request))
                .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());

        result = getMockMvc().perform(post)
                .andExpect(status().isBadRequest())
                .andReturn();
        assertThat(result.getResponse().getContentAsString(), containsString("Caused by:"));

        //Invalid LDAP configuration - invalid search base
        definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
                getLdapOrLdapSBaseUrl(),
                "cn=admin,ou=Users,dc=test,dc=com",
                "adminsecret",
                ",,,,,dc=test,dc=com",
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
        provider.setConfig(definition);
        request = new IdentityProviderValidationRequest(provider, token);
        post = post("/identity-providers/test")
                .header("Accept", APPLICATION_JSON_VALUE)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + zoneAdminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request))
                .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());

        result = getMockMvc().perform(post)
                .andExpect(status().isBadRequest())
                .andReturn();
        assertThat(result.getResponse().getContentAsString(), containsString("Caused by:"));

        token = new IdentityProviderValidationRequest.UsernamePasswordAuthentication("marissa2", LDAP);

        //SSL self signed cert problems
        definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
                "ldaps://localhost:" + ldapSPort,
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
                false
        );
        provider.setConfig(definition);
        request = new IdentityProviderValidationRequest(provider, token);
        post = post("/identity-providers/test")
                .header("Accept", APPLICATION_JSON_VALUE)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + zoneAdminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request))
                .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());
        result = getMockMvc().perform(post)
                .andExpect(status().isBadRequest())
                .andReturn();
        assertThat(result.getResponse().getContentAsString(), containsString("Caused by:"));
        definition.setSkipSSLVerification(true);
        provider.setConfig(definition);
        request = new IdentityProviderValidationRequest(provider, token);
        post = post("/identity-providers/test")
                .header("Accept", APPLICATION_JSON_VALUE)
                .header("Content-Type", APPLICATION_JSON_VALUE)
                .header("Authorization", "Bearer " + zoneAdminToken)
                .contentType(APPLICATION_JSON)
                .content(JsonUtils.writeValueAsString(request))
                .header(IdentityZoneSwitchingFilter.HEADER, zone.getId());

        result = getMockMvc().perform(post)
                .andExpect(status().isOk())
                .andReturn();
        assertThat(result.getResponse().getContentAsString(), containsString("\"ok\""));
    }

}
