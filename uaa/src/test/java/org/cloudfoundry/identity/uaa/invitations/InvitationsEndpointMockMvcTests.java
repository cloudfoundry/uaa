package org.cloudfoundry.identity.uaa.invitations;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantJdbcClientDetailsService;
import org.flywaydb.core.internal.util.StringUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.util.Arrays;
import java.util.Collections;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.ORIGIN;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.UAA;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.CoreMatchers.nullValue;
import static org.hamcrest.CoreMatchers.startsWith;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.REDIRECT_URI;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class InvitationsEndpointMockMvcTests extends InjectedMockContextTest {

    private String scimInviteToken;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private String clientId;
    private String clientSecret;
    private ClientDetails clientDetails;
    private String adminToken;
    private String authorities;
    private String domain;
    private ExpiringCodeStore codeStore;

    @Before
    public void setUp() throws Exception {
        adminToken = utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", "clients.read clients.write clients.secret scim.read scim.write clients.admin", null);
        clientId = generator.generate().toLowerCase();
        clientSecret = generator.generate().toLowerCase();
        authorities = "scim.read,scim.invite";
        clientDetails = utils().createClient(this.getMockMvc(), adminToken, clientId, clientSecret, Collections.singleton("oauth"), Arrays.asList("scim.read","scim.invite"), Arrays.asList(new String[]{"client_credentials", "password"}), authorities);
        scimInviteToken = utils().getClientCredentialsOAuthAccessToken(getMockMvc(), clientId, clientSecret, "scim.read scim.invite", null);
        domain = generator.generate().toLowerCase()+".com";
        IdentityProvider<UaaIdentityProviderDefinition> uaaProvider = getWebApplicationContext().getBean(IdentityProviderProvisioning.class).retrieveByOrigin(UAA, IdentityZone.getUaa().getId());
        if (uaaProvider.getConfig()==null) {
            uaaProvider.setConfig(new UaaIdentityProviderDefinition(null,null));
        }
        uaaProvider.getConfig().setEmailDomain(Arrays.asList(domain, "example.com"));
        getWebApplicationContext().getBean(IdentityProviderProvisioning.class).update(uaaProvider);
        codeStore = getWebApplicationContext().getBean(ExpiringCodeStore.class);
    }

    @After
    public void cleanUpDomainList() throws Exception {
        IdentityProvider<UaaIdentityProviderDefinition> uaaProvider = getWebApplicationContext().getBean(IdentityProviderProvisioning.class).retrieveByOrigin(UAA, IdentityZone.getUaa().getId());
        uaaProvider.getConfig().setEmailDomain(null);
        getWebApplicationContext().getBean(IdentityProviderProvisioning.class).update(uaaProvider);
    }

    @Test
    public void invite_User_With_Client_Credentials() throws Exception {
        String email = "user1@example.com";
        String redirectUrl = "example.com";
        InvitationsResponse response = sendRequestWithTokenAndReturnResponse(scimInviteToken, null, clientId, redirectUrl, email);
        assertResponseAndCodeCorrect(new String[] {email}, redirectUrl, null, response, clientDetails);
    }

    @Test
    public void invite_Multiple_Users_With_Client_Credentials() throws Exception {
        String[] emails = new String[] {"user1@"+domain, "user2@"+domain};
        String redirectUri = "example.com";
        InvitationsResponse response = sendRequestWithTokenAndReturnResponse(scimInviteToken, null, clientId, redirectUri, emails);
        assertResponseAndCodeCorrect(emails, redirectUri, null, response, clientDetails);
    }

    @Test
    public void invite_User_With_User_Credentials() throws Exception {
        String email = "user1@example.com";
        String redirectUri = "example.com";
        String userToken = utils().getScimInviteUserToken(getMockMvc(), clientId, clientSecret, null);
        InvitationsResponse response = sendRequestWithTokenAndReturnResponse(userToken, null, clientId, redirectUri, email);
        assertResponseAndCodeCorrect(new String[] {email}, redirectUri, null, response, clientDetails);
    }

    @Test
    public void invite_User_Within_Zone() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.IdentityZoneCreationResult result = utils().createOtherIdentityZoneAndReturnResult(subdomain, getMockMvc(), getWebApplicationContext(), null);

        String zonedClientId = "zonedClientId";
        String zonedClientSecret = "zonedClientSecret";
        BaseClientDetails zonedClientDetails = (BaseClientDetails)utils().createClient(this.getMockMvc(), result.getZoneAdminToken(), zonedClientId, zonedClientSecret, Collections.singleton("oauth"), Arrays.asList("scim.read","scim.invite"), Arrays.asList("client_credentials", "password"), authorities, null, result.getIdentityZone());
        zonedClientDetails.setClientSecret(zonedClientSecret);
        String zonedScimInviteToken = utils().getClientCredentialsOAuthAccessToken(getMockMvc(), zonedClientDetails.getClientId(), zonedClientDetails.getClientSecret(), "scim.read scim.invite", subdomain);

        String email = "user1@example.com";
        String redirectUrl = "example.com";
        InvitationsResponse response = sendRequestWithTokenAndReturnResponse(zonedScimInviteToken, subdomain, zonedClientDetails.getClientId(), redirectUrl, email);

        assertResponseAndCodeCorrect(new String[] {email}, redirectUrl, subdomain, response, zonedClientDetails);
    }

    @Test
    public void multiple_Users_Email_Exists_With_One_Origin() throws Exception {
        String clientAdminToken = utils().getClientOAuthAccessToken(getMockMvc(), "admin", "adminsecret","");
        String username1 = generator.generate();
        String username2 = generator.generate();
        String email = generator.generate().toLowerCase()+"@"+domain;
        ScimUser user1 = new ScimUser(null, username1, "givenName", "familyName");
        user1.setPrimaryEmail(email);
        user1.setOrigin(UAA);
        utils().createUser(getMockMvc(), clientAdminToken, user1);
        ScimUser user2 = new ScimUser(null, username2, "givenName", "familyName");
        user2.setPrimaryEmail(email);
        user2.setOrigin(UAA);
        utils().createUser(getMockMvc(), clientAdminToken, user2);

        String userToken = utils().getScimInviteUserToken(getMockMvc(), clientId, clientSecret, null);
        InvitationsResponse response = sendRequestWithTokenAndReturnResponse(userToken, null, clientId, "example.com", email);
        assertEquals(0, response.getNewInvites().size());
        assertEquals(1, response.getFailedInvites().size());
        assertEquals("user.ambiguous", response.getFailedInvites().get(0).getErrorCode());
    }

    @Test
    public void accept_Invitation_Email_With_Default_CompanyName() throws Exception {
        ((MockEnvironment) getWebApplicationContext().getEnvironment()).setProperty("login.branding.companyName", "");
        getMockMvc().perform(get(getAcceptInvitationLink(null)))
                .andExpect(content().string(containsString("Create your account")))
                .andExpect(content().string(containsString("Create account")));
    }

    @Test
    public void accept_Invitation_Email_With_CompanyName() throws Exception {
        ((MockEnvironment) getWebApplicationContext().getEnvironment()).setProperty("login.branding.companyName", "Best Company");

        getMockMvc().perform(get(getAcceptInvitationLink(null)))
                .andExpect(content().string(containsString("Create your Best Company account")))
                .andExpect(content().string(containsString("Create Best Company account")))
                .andExpect(content().string(not(containsString("Create account"))));
    }

    @Test
    public void accept_Invitation_Email_Within_Zone() throws Exception {
        String subdomain = generator.generate();
        IdentityZone zone = utils().createOtherIdentityZone(subdomain, getMockMvc(), getWebApplicationContext());
        ((MockEnvironment) getWebApplicationContext().getEnvironment()).setProperty("login.branding.companyName", "Best Company");

        BaseClientDetails client = utils().getClientDetailsModification(clientId, clientSecret, Collections.singleton("oauth"), Arrays.asList("scim.read","scim.invite"), Arrays.asList(new String[]{"client_credentials", "password"}), authorities, Collections.EMPTY_SET);
        IdentityZone original = IdentityZoneHolder.get();
        try {
            IdentityZoneHolder.set(zone);
            getWebApplicationContext().getBean(MultitenantJdbcClientDetailsService.class).addClientDetails(client);
        } finally {
            IdentityZoneHolder.set(original);
        }
        String acceptInvitationLink = getAcceptInvitationLink(zone);

        getMockMvc().perform(get(acceptInvitationLink)
                .header("Host",(subdomain + ".localhost")))
                .andExpect(content().string(containsString("Create your account")))
                .andExpect(content().string(not(containsString("Best Company"))))
                .andExpect(content().string(containsString("Create account")));
    }

    @Test
    public void invitations_Accept_Get_Security() throws Exception {
        getWebApplicationContext().getBean(JdbcTemplate.class).update("DELETE FROM expiring_code_store");

        String userToken = utils().getScimInviteUserToken(getMockMvc(), clientId, clientSecret, null);
        sendRequestWithToken(userToken, null, clientId, "example.com", "user1@"+domain);

        String code = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("SELECT code FROM expiring_code_store", String.class);
        assertNotNull("Invite Code Must be Present", code);

        MockHttpServletRequestBuilder accept = get("/invitations/accept")
                .param("code", code);

        getMockMvc().perform(accept)
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("<form method=\"post\" novalidate=\"novalidate\" action=\"/invitations/accept.do\">")));
    }

    public static InvitationsResponse sendRequestWithTokenAndReturnResponse(String token,
                                                                            String subdomain,
                                                                            String clientId,
                                                                            String redirectUri,
                                                                            String...emails) throws Exception {
        return MockMvcUtils.utils().sendRequestWithTokenAndReturnResponse(getWebApplicationContext(),
                getMockMvc(), token, subdomain, clientId, redirectUri, emails);
    }

    public static void sendRequestWithToken(String token, String subdomain, String clientId, String redirectUri, String...emails) throws Exception {
        InvitationsResponse response = sendRequestWithTokenAndReturnResponse(token, subdomain, clientId, redirectUri, emails);
        assertThat(response.getNewInvites().size(), is(emails.length));
        assertThat(response.getFailedInvites().size(), is(0));
    }

    private void assertResponseAndCodeCorrect(String[] emails, String redirectUrl, String subdomain, InvitationsResponse response, ClientDetails clientDetails) {
        for (int i = 0; i < emails.length; i++) {
            assertThat(response.getNewInvites().size(), is(emails.length));
            assertThat(response.getNewInvites().get(i).getEmail(), is(emails[i]));
            assertThat(response.getNewInvites().get(i).getOrigin(), is(OriginKeys.UAA));
            assertThat(response.getNewInvites().get(i).getUserId(), is(notNullValue()));
            assertThat(response.getNewInvites().get(i).getErrorCode(), is(nullValue()));
            assertThat(response.getNewInvites().get(i).getErrorMessage(), is(nullValue()));
            if (StringUtils.hasText(subdomain)) {
                assertThat(response.getNewInvites().get(i).getInviteLink().toString(), startsWith("http://" + subdomain + ".localhost/invitations/accept"));
            } else {
                assertThat(response.getNewInvites().get(i).getInviteLink().toString(), startsWith("http://localhost/invitations/accept"));
            }

            String query = response.getNewInvites().get(i).getInviteLink().getQuery();
            assertThat(query, startsWith("code="));
            String code = query.split("=")[1];
            ExpiringCode expiringCode = codeStore.retrieveCode(code);
            assertThat(expiringCode.getExpiresAt().getTime(), is(greaterThan(System.currentTimeMillis())));
            Map<String, String> data = JsonUtils.readValue(expiringCode.getData(), new TypeReference<Map<String, String>>() {});
            assertThat(data.get(InvitationConstants.USER_ID), is(notNullValue()));
            assertThat(data.get(InvitationConstants.EMAIL), is(emails[i]));
            assertThat(data.get(ORIGIN), is(OriginKeys.UAA));
            assertThat(data.get(CLIENT_ID), is(clientDetails.getClientId()));
            assertThat(data.get(REDIRECT_URI), is(redirectUrl));
        }
    }

    private String getAcceptInvitationLink(IdentityZone zone) throws Exception {
        String userToken = utils().getScimInviteUserToken(getMockMvc(), clientId, clientSecret, zone);
        String email = generator.generate().toLowerCase() + "@"+domain;
        InvitationsResponse response = sendRequestWithTokenAndReturnResponse(userToken, zone==null?null:zone.getSubdomain(), clientId, "example.com", email);
        return response.getNewInvites().get(0).getInviteLink().toString();
    }
}
