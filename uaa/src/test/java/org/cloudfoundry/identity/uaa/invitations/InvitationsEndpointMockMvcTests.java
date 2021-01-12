package org.cloudfoundry.identity.uaa.invitations;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.login.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.test.ZoneSeeder;
import org.cloudfoundry.identity.uaa.test.ZoneSeederExtension;
import org.cloudfoundry.identity.uaa.zone.*;
import org.flywaydb.core.internal.util.StringUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import static org.apache.commons.lang3.StringUtils.contains;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.ORIGIN;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.invitations.InvitationsEndpoint.EMAIL;
import static org.cloudfoundry.identity.uaa.invitations.InvitationsEndpoint.USER_ID;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.readValue;
import static org.cloudfoundry.identity.uaa.util.JsonUtils.writeValueAsString;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.HEADER;
import static org.cloudfoundry.identity.uaa.zone.IdentityZoneSwitchingFilter.SUBDOMAIN_HEADER;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.*;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.*;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.REDIRECT_URI;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class InvitationsEndpointMockMvcTests {

    private String scimInviteToken;
    private RandomValueStringGenerator generator;
    private String clientId;
    private String clientSecret;
    private ClientDetails clientDetails;
    private String adminToken;
    private String authorities;
    private String emailDomain;

    @Autowired
    private WebApplicationContext webApplicationContext;
    @Autowired
    private MockMvc mockMvc;
    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @Autowired
    private JdbcIdentityProviderProvisioning jdbcIdentityProviderProvisioning;
    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @Autowired
    private ExpiringCodeStore expiringCodeStore;
    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @Autowired
    private IdentityZoneProvisioning identityZoneProvisioning;

    @BeforeEach
    void setUp() throws Exception {
        generator = new RandomValueStringGenerator();
        adminToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", "clients.read clients.write clients.secret scim.read scim.write clients.admin uaa.admin", null);
        clientId = generator.generate().toLowerCase();
        clientSecret = generator.generate().toLowerCase();
        authorities = "scim.read,scim.invite";
        clientDetails = MockMvcUtils.createClient(this.mockMvc, adminToken, clientId, clientSecret, Collections.singleton("oauth"), Arrays.asList("scim.read", "scim.invite"), Arrays.asList("client_credentials", "password"), authorities);
        scimInviteToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, clientId, clientSecret, "scim.read scim.invite", null);
        emailDomain = generator.generate().toLowerCase() + ".com";
        IdentityProvider uaaProvider = jdbcIdentityProviderProvisioning.retrieveByOrigin(UAA, IdentityZone.getUaaZoneId());
        if (uaaProvider.getConfig() == null) {
            uaaProvider.setConfig(new UaaIdentityProviderDefinition(null, null));
        }
        uaaProvider.getConfig().setEmailDomain(Arrays.asList(emailDomain, "example.com"));
        jdbcIdentityProviderProvisioning.update(uaaProvider, uaaProvider.getIdentityZoneId());
    }

    @AfterEach
    void cleanUpDomainList() {
        IdentityProvider uaaProvider = jdbcIdentityProviderProvisioning.retrieveByOrigin(UAA, IdentityZone.getUaaZoneId());
        uaaProvider.getConfig().setEmailDomain(null);
        jdbcIdentityProviderProvisioning.update(uaaProvider, uaaProvider.getIdentityZoneId());
    }

    @Test
    void inviteUserWithClientCredentials() throws Exception {
        String email = "user1@example.com";
        String redirectUrl = "example.com";
        InvitationsResponse response = sendRequestWithTokenAndReturnResponse(webApplicationContext, mockMvc, scimInviteToken, null, clientId, redirectUrl, email);
        assertResponseAndCodeCorrect(expiringCodeStore, new String[]{email}, redirectUrl, null, response, clientDetails);
    }

    @Test
    void inviteMultipleUsersWithClientCredentials() throws Exception {
        String[] emails = new String[]{"user1@" + emailDomain, "user2@" + emailDomain};
        String redirectUri = "example.com";
        InvitationsResponse response = sendRequestWithTokenAndReturnResponse(webApplicationContext, mockMvc, scimInviteToken, null, clientId, redirectUri, emails);
        assertResponseAndCodeCorrect(expiringCodeStore, emails, redirectUri, null, response, clientDetails);
    }

    @Test
    void inviteUserWithUserCredentials() throws Exception {
        String email = "user1@example.com";
        String redirectUri = "example.com";
        String userToken = MockMvcUtils.getScimInviteUserToken(mockMvc, clientId, clientSecret, null, "admin", "adminsecret");
        InvitationsResponse response = sendRequestWithTokenAndReturnResponse(webApplicationContext, mockMvc, userToken, null, clientId, redirectUri, email);
        assertResponseAndCodeCorrect(expiringCodeStore, new String[]{email}, redirectUri, null, response, clientDetails);
    }

    @Nested
    @DefaultTestContext
    @ExtendWith(ZoneSeederExtension.class)
    class WithOtherIdentityZone {

        private ZoneSeeder zoneSeeder;

        @BeforeEach
        void setUp(ZoneSeeder zoneSeeder) {
            this.zoneSeeder = zoneSeeder.withDefaults().withAdminClientWithClientCredentialsGrant();
        }

        @Test
        void inviteUserInZoneWithDefaultZoneZoneAdmin() throws Exception {
            String zonifiedAdminClientId = generator.generate().toLowerCase();
            String zonifiedAdminClientSecret = generator.generate().toLowerCase();

            ClientDetails zonifiedScimInviteClientDetails = MockMvcUtils.createClient(
                    mockMvc,
                    adminToken,
                    zonifiedAdminClientId,
                    zonifiedAdminClientSecret,
                    Collections.singleton("oauth"),
                    null,
                    Arrays.asList("client_credentials", "password"),
                    zoneSeeder.getAdminScope());
            String zonifiedScimInviteToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(
                    mockMvc,
                    zonifiedAdminClientId,
                    zonifiedAdminClientSecret,
                    zoneSeeder.getAdminScope(),
                    null);

            String email = "user1@example.com";
            String redirectUrl = "example.com";

            InvitationsRequest invitations = new InvitationsRequest(new String[]{email});

            String requestBody = writeValueAsString(invitations);

            MockHttpServletRequestBuilder post = post("/invite_users")
                    .param(OAuth2Utils.REDIRECT_URI, redirectUrl)
                    .header("Authorization", "Bearer " + zonifiedScimInviteToken)
                    .header(SUBDOMAIN_HEADER, zoneSeeder.getIdentityZoneSubdomain())
                    .contentType(APPLICATION_JSON)
                    .content(requestBody);

            MvcResult mvcResult = mockMvc.perform(post)
                    .andExpect(status().isOk())
                    .andReturn();

            InvitationsResponse invitationsResponse = readValue(mvcResult.getResponse().getContentAsString(), InvitationsResponse.class);
            assertResponseAndCodeCorrect(expiringCodeStore, new String[]{email}, redirectUrl, zoneSeeder.getIdentityZone(), invitationsResponse, zonifiedScimInviteClientDetails);
        }

        @Test
        void inviteUserInZoneWithDefaultZoneScimInvite() throws Exception {
            String zonifiedScimInviteClientId = generator.generate().toLowerCase();
            String zonifiedScimInviteClientSecret = generator.generate().toLowerCase();

            ClientDetails zonifiedScimInviteClientDetails = MockMvcUtils.createClient(
                    mockMvc,
                    adminToken,
                    zonifiedScimInviteClientId,
                    zonifiedScimInviteClientSecret,
                    Collections.singleton("oauth"),
                    null,
                    Arrays.asList("client_credentials", "password"),
                    "zones." + zoneSeeder.getIdentityZoneId() + ".scim.invite");
            String zonifiedScimInviteToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(
                    mockMvc,
                    zonifiedScimInviteClientId,
                    zonifiedScimInviteClientSecret,
                    "zones." + zoneSeeder.getIdentityZoneId() + ".scim.invite",
                    null);

            String email = "user1@example.com";
            String redirectUrl = "example.com";

            InvitationsRequest invitations = new InvitationsRequest(new String[]{email});

            String requestBody = writeValueAsString(invitations);

            MockHttpServletRequestBuilder post = post("/invite_users")
                    .param(OAuth2Utils.REDIRECT_URI, redirectUrl)
                    .header("Authorization", "Bearer " + zonifiedScimInviteToken)
                    .header(HEADER, zoneSeeder.getIdentityZoneId())
                    .contentType(APPLICATION_JSON)
                    .content(requestBody);

            MvcResult mvcResult = mockMvc.perform(post)
                    .andExpect(status().isOk())
                    .andReturn();

            InvitationsResponse invitationsResponse = readValue(mvcResult.getResponse().getContentAsString(), InvitationsResponse.class);
            assertResponseAndCodeCorrect(expiringCodeStore, new String[]{email}, redirectUrl, zoneSeeder.getIdentityZone(), invitationsResponse, zonifiedScimInviteClientDetails);

        }

        @Test
        void inviteUserInZoneWithDefaultZoneUaaAdmin() throws Exception {
            String email = "user1@example.com";
            String redirectUrl = "example.com";

            InvitationsRequest invitations = new InvitationsRequest(new String[]{email});

            String requestBody = writeValueAsString(invitations);

            MockHttpServletRequestBuilder post = post("/invite_users")
                    .param(OAuth2Utils.REDIRECT_URI, redirectUrl)
                    .header("Authorization", "Bearer " + adminToken)
                    .header(SUBDOMAIN_HEADER, zoneSeeder.getIdentityZoneSubdomain())
                    .contentType(APPLICATION_JSON)
                    .content(requestBody);

            MvcResult mvcResult = mockMvc.perform(post)
                    .andExpect(status().isOk())
                    .andReturn();

            InvitationsResponse invitationsResponse = readValue(mvcResult.getResponse().getContentAsString(), InvitationsResponse.class);
            BaseClientDetails defaultClientDetails = new BaseClientDetails();
            defaultClientDetails.setClientId("admin");
            assertResponseAndCodeCorrect(expiringCodeStore, new String[]{email}, redirectUrl, zoneSeeder.getIdentityZone(), invitationsResponse, defaultClientDetails);

        }

        @Test
        void inviteUserWithinZone() throws Exception {
            String zonedClientId = "zonedClientId";
            String zonedClientSecret = "zonedClientSecret";

            BaseClientDetails zonedClientDetails = (BaseClientDetails) MockMvcUtils.createClient(
                    mockMvc,
                    MockMvcUtils.getZoneAdminToken(
                            mockMvc,
                            adminToken,
                            zoneSeeder.getIdentityZoneId()),
                    zonedClientId,
                    zonedClientSecret,
                    Collections.singleton("oauth"),
                    Arrays.asList(
                            "scim.read",
                            "scim.invite"),
                    Arrays.asList(
                            "client_credentials",
                            "password"),
                    authorities,
                    Collections.singleton("http://redirect.uri"),
                    zoneSeeder.getIdentityZone());
            zonedClientDetails.setClientSecret(zonedClientSecret);
            String zonedScimInviteToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(
                    mockMvc,
                    zonedClientDetails.getClientId(),
                    zonedClientDetails.getClientSecret(),
                    "scim.read scim.invite",
                    zoneSeeder.getIdentityZoneSubdomain());

            String email = "user1@example.com";
            String redirectUrl = "example.com";
            InvitationsResponse response = sendRequestWithTokenAndReturnResponse(webApplicationContext, mockMvc, zonedScimInviteToken, zoneSeeder.getIdentityZone().getSubdomain(), zonedClientDetails.getClientId(), redirectUrl, email);

            assertResponseAndCodeCorrect(expiringCodeStore, new String[]{email}, redirectUrl, zoneSeeder.getIdentityZone(), response, zonedClientDetails);
        }

        @Test
        void acceptInvitationEmailWithinZone(@Autowired MultitenantJdbcClientDetailsService multitenantJdbcClientDetailsService) throws Exception {
            BrandingInformation branding = new BrandingInformation();
            branding.setCompanyName("Best Company");
            IdentityZoneConfiguration config = new IdentityZoneConfiguration();
            config.setBranding(branding);
            zoneSeeder.getIdentityZone().setConfig(config);

            identityZoneProvisioning.update(zoneSeeder.getIdentityZone());

            String scimInviteClientId = generator.generate();
            String scimInviteClientSecret = generator.generate();

            BaseClientDetails client = MockMvcUtils.getClientDetailsModification(
                    scimInviteClientId,
                    scimInviteClientSecret,
                    Collections.singleton("oauth"),
                    Arrays.asList("scim.read", "scim.invite"),
                    Arrays.asList("client_credentials", "password"),
                    authorities,
                    Collections.singleton("http://redirect.uri"));
            multitenantJdbcClientDetailsService.addClientDetails(client, zoneSeeder.getIdentityZoneId());
            String acceptInvitationLink = getAcceptInvitationLink(
                    webApplicationContext,
                    mockMvc,
                    scimInviteClientId,
                    scimInviteClientSecret,
                    generator,
                    emailDomain,
                    zoneSeeder.getIdentityZone(),
                    zoneSeeder.getAdminClientWithClientCredentialsGrant().getClientId(),
                    zoneSeeder.getPlainTextClientSecret(zoneSeeder.getAdminClientWithClientCredentialsGrant()));

            mockMvc.perform(get(acceptInvitationLink)
                    .header("Host", (zoneSeeder.getIdentityZoneSubdomain() + ".localhost")))
                    .andExpect(content().string(containsString("Create your account")))
                    .andExpect(content().string(containsString("Best Company")))
                    .andExpect(content().string(containsString("Create account")));
        }

    }

    @Test
    void multipleUsersEmailExistsWithOneOrigin() throws Exception {
        String clientAdminToken = MockMvcUtils.getClientOAuthAccessToken(mockMvc, "admin", "adminsecret", "");
        String username1 = generator.generate();
        String username2 = generator.generate();
        String email = generator.generate().toLowerCase() + "@" + emailDomain;
        ScimUser user1 = new ScimUser(null, username1, "givenName", "familyName");
        user1.setPrimaryEmail(email);
        user1.setOrigin(UAA);
        user1.setPassword("password");
        MockMvcUtils.createUser(mockMvc, clientAdminToken, user1);
        ScimUser user2 = new ScimUser(null, username2, "givenName", "familyName");
        user2.setPrimaryEmail(email);
        user2.setOrigin(UAA);
        user2.setPassword("password");
        MockMvcUtils.createUser(mockMvc, clientAdminToken, user2);

        String userToken = MockMvcUtils.getScimInviteUserToken(mockMvc, clientId, clientSecret, null, "admin", "adminsecret");
        InvitationsResponse response = sendRequestWithTokenAndReturnResponse(webApplicationContext, mockMvc, userToken, null, clientId, "example.com", email);
        assertEquals(0, response.getNewInvites().size());
        assertEquals(1, response.getFailedInvites().size());
        assertEquals("user.ambiguous", response.getFailedInvites().get(0).getErrorCode());
    }

    @Test
    void inviteUserWithInvalidEmails() throws Exception {
        String invalidEmail1 = "user1example.";
        String invalidEmail2 = "user1example@";
        String invalidEmail3 = "user1example@invalid";
        String redirectUrl = "test.com";
        InvitationsResponse response = sendRequestWithTokenAndReturnResponse(webApplicationContext, mockMvc, scimInviteToken, null, clientId, redirectUrl, invalidEmail1, invalidEmail2, invalidEmail3);
        assertEquals(0, response.getNewInvites().size());
        assertEquals(3, response.getFailedInvites().size());

        assertEquals("email.invalid", response.getFailedInvites().get(0).getErrorCode());
        assertEquals("email.invalid", response.getFailedInvites().get(1).getErrorCode());
        assertEquals("provider.non-existent", response.getFailedInvites().get(2).getErrorCode());
        assertEquals(invalidEmail1 + " is invalid email.", response.getFailedInvites().get(0).getErrorMessage());
        assertEquals(invalidEmail2 + " is invalid email.", response.getFailedInvites().get(1).getErrorMessage());
        assertEquals("No authentication provider found.", response.getFailedInvites().get(2).getErrorMessage());
    }

    @Test
    void acceptInvitationEmailWithDefaultCompanyName() throws Exception {
        mockMvc.perform(get(getAcceptInvitationLink(webApplicationContext, mockMvc, clientId, clientSecret, generator, emailDomain, null, "admin", "adminsecret")))
                .andExpect(content().string(containsString("Create your account")))
                .andExpect(content().string(containsString("Create account")));
    }

    @Test
    void acceptInvitationEmailWithCompanyName() throws Exception {
        IdentityZoneConfiguration defaultConfig = IdentityZoneHolder.get().getConfig();
        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName("Best Company");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setBranding(branding);
        IdentityZone defaultZone = IdentityZoneHolder.getUaaZone();
        defaultZone.setConfig(config);
        identityZoneProvisioning.update(defaultZone);
        try {
            mockMvc.perform(get(getAcceptInvitationLink(webApplicationContext, mockMvc, clientId, clientSecret, generator, emailDomain, null, "admin", "adminsecret")))
                    .andExpect(content().string(containsString("Create your Best Company account")))
                    .andExpect(content().string(containsString("Create Best Company account")))
                    .andExpect(content().string(not(containsString("Create account"))));
        } finally {
            defaultZone.setConfig(defaultConfig);
            identityZoneProvisioning.update(defaultZone);
        }
    }

    @Test
    void invitationsAcceptGetSecurity(@Autowired JdbcTemplate jdbcTemplate) throws Exception {
        jdbcTemplate.update("DELETE FROM expiring_code_store");

        String userToken = MockMvcUtils.getScimInviteUserToken(mockMvc, clientId, clientSecret, null, "admin", "adminsecret");
        sendRequestWithToken(webApplicationContext, mockMvc, userToken, clientId, "user1@" + emailDomain);

        String code = jdbcTemplate.queryForObject("SELECT code FROM expiring_code_store", String.class);
        assertNotNull("Invite Code Must be Present", code);

        MockHttpServletRequestBuilder accept = get("/invitations/accept")
                .param("code", code);

        mockMvc.perform(accept)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("<form action=\"/invitations/accept.do\" method=\"post\" novalidate=\"novalidate\">")));
    }

    private static InvitationsResponse sendRequestWithTokenAndReturnResponse(WebApplicationContext webApplicationContext,
                                                                             MockMvc mockMvc,
                                                                             String token,
                                                                             String subdomain,
                                                                             String clientId,
                                                                             String redirectUri,
                                                                             String... emails) throws Exception {
        return MockMvcUtils.sendRequestWithTokenAndReturnResponse(webApplicationContext,
                mockMvc, token, subdomain, clientId, redirectUri, emails);
    }

    private static void sendRequestWithToken(WebApplicationContext webApplicationContext, MockMvc mockMvc, String token, String clientId, String... emails) throws Exception {
        InvitationsResponse response = sendRequestWithTokenAndReturnResponse(webApplicationContext, mockMvc, token, null, clientId, "example.com", emails);
        assertThat(response.getNewInvites().size(), is(emails.length));
        assertThat(response.getFailedInvites().size(), is(0));
    }

    private static void assertResponseAndCodeCorrect(ExpiringCodeStore expiringCodeStore, String[] emails, String redirectUrl, IdentityZone zone, InvitationsResponse response, ClientDetails clientDetails) {
        for (int i = 0; i < emails.length; i++) {
            assertThat(response.getNewInvites().size(), is(emails.length));
            assertThat(response.getNewInvites().get(i).getEmail(), is(emails[i]));
            assertThat(response.getNewInvites().get(i).getOrigin(), is(OriginKeys.UAA));
            assertThat(response.getNewInvites().get(i).getUserId(), is(notNullValue()));
            assertThat(response.getNewInvites().get(i).getErrorCode(), is(nullValue()));
            assertThat(response.getNewInvites().get(i).getErrorMessage(), is(nullValue()));
            String link = response.getNewInvites().get(i).getInviteLink().toString();
            assertFalse(contains(link, "@"));
            assertFalse(contains(link, "%40"));
            if (zone != null && StringUtils.hasText(zone.getSubdomain())) {
                assertThat(link, startsWith("http://" + zone.getSubdomain() + ".localhost/invitations/accept"));
                IdentityZoneHolder.set(zone);
            } else {
                assertThat(link, startsWith("http://localhost/invitations/accept"));
            }

            String query = response.getNewInvites().get(i).getInviteLink().getQuery();
            assertThat(query, startsWith("code="));
            String code = query.split("=")[1];

            ExpiringCode expiringCode = expiringCodeStore.retrieveCode(code, IdentityZoneHolder.get().getId());
            IdentityZoneHolder.clear();
            assertThat(expiringCode.getExpiresAt().getTime(), is(greaterThan(System.currentTimeMillis())));
            assertThat(expiringCode.getIntent(), is(ExpiringCodeType.INVITATION.name()));
            Map<String, String> data = readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {
            });
            assertThat(data, is(not(nullValue())));
            assertThat(data.get(USER_ID), is(notNullValue()));
            assertThat(data.get(EMAIL), is(emails[i]));
            assertThat(data.get(ORIGIN), is(OriginKeys.UAA));
            assertThat(data.get(CLIENT_ID), is(clientDetails.getClientId()));
            assertThat(data.get(REDIRECT_URI), is(redirectUrl));
        }
    }

    private static String getAcceptInvitationLink(
            WebApplicationContext webApplicationContext,
            MockMvc mockMvc,
            String clientId,
            String clientSecret,
            RandomValueStringGenerator generator,
            String domain,
            IdentityZone zone,
            String adminClientId,
            String adminClientSecret) throws Exception {
        String userToken = MockMvcUtils.getScimInviteUserToken(mockMvc, clientId, clientSecret, zone, adminClientId, adminClientSecret);
        String email = generator.generate().toLowerCase() + "@" + domain;
        InvitationsResponse response = sendRequestWithTokenAndReturnResponse(webApplicationContext, mockMvc, userToken, zone == null ? null : zone.getSubdomain(), clientId, "example.com", email);
        return response.getNewInvites().get(0).getInviteLink().toString();
    }
}
