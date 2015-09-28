package org.cloudfoundry.identity.uaa.invitations;

import org.cloudfoundry.identity.uaa.config.IdentityProviderBootstrap;
import org.cloudfoundry.identity.uaa.login.EmailService;
import org.cloudfoundry.identity.uaa.login.test.MockMvcTestClient;
import org.cloudfoundry.identity.uaa.login.util.FakeJavaMailSender;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.UaaIdentityProviderDefinition;
import org.flywaydb.core.internal.util.StringUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import javax.mail.Message;
import javax.mail.MessagingException;
import java.util.Arrays;
import java.util.Iterator;

import static org.cloudfoundry.identity.uaa.authentication.Origin.UAA;
import static org.cloudfoundry.identity.uaa.login.util.FakeJavaMailSender.MimeMessageWrapper;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createScimClient;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.core.Is.is;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class InvitationsEndpointMockMvcTests extends InjectedMockContextTest {

    private String scimInviteToken;
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private String clientId;
    private String clientSecret;
    private String adminToken;
    private String authorities;
    private FakeJavaMailSender fakeJavaMailSender = new FakeJavaMailSender();
    private JavaMailSender originalSender;
    private String domain;

    @Before
    public void setUp() throws Exception {
        getWebApplicationContext().getBean(IdentityProviderBootstrap.class).afterPropertiesSet();
        adminToken = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", "clients.read clients.write clients.secret scim.read scim.write", null);
        clientId = generator.generate().toLowerCase();
        clientSecret = generator.generate().toLowerCase();
        authorities = "scim.read,scim.invite";
        createScimClient(this.getMockMvc(), adminToken, clientId, clientSecret, "oauth", "scim.read,scim.invite", Arrays.asList(new MockMvcUtils.GrantType[] {MockMvcUtils.GrantType.client_credentials, MockMvcUtils.GrantType.password}), authorities);
        scimInviteToken = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(getMockMvc(), clientId, clientSecret, "scim.read scim.invite", null);
        domain = generator.generate().toLowerCase()+".com";
        IdentityProvider uaaProvider = getWebApplicationContext().getBean(IdentityProviderProvisioning.class).retrieveByOrigin(UAA, IdentityZone.getUaa().getId());
        uaaProvider.getConfigValue(UaaIdentityProviderDefinition.class).setEmailDomain(Arrays.asList(domain));
        getWebApplicationContext().getBean(IdentityProviderProvisioning.class).update(uaaProvider);
    }

    @Before
    public void setUpFakeMailServer() throws Exception {
        originalSender = getWebApplicationContext().getBean("emailService", EmailService.class).getMailSender();
        getWebApplicationContext().getBean("emailService", EmailService.class).setMailSender(fakeJavaMailSender);
    }

    @After
    public void restoreMailServer() throws Exception {
        getWebApplicationContext().getBean("emailService", EmailService.class).setMailSender(originalSender);
    }

    @Test
    public void testAcceptInvitationEmailWithOssBrand() throws Exception {
        ((MockEnvironment) getWebApplicationContext().getEnvironment()).setProperty("login.brand", "oss");

        getMockMvc().perform(get(getAcceptInvitationLink()))
            .andExpect(content().string(containsString("Create your account")))
            .andExpect(content().string(not(containsString("Pivotal ID"))))
            .andExpect(content().string(not(containsString("Create Pivotal ID"))))
            .andExpect(content().string(containsString("Create account")));
    }

    @Test
    public void testAcceptInvitationEmailWithPivotalBrand() throws Exception {
        ((MockEnvironment) getWebApplicationContext().getEnvironment()).setProperty("login.brand", "pivotal");

        getMockMvc().perform(get(getAcceptInvitationLink()))
            .andExpect(content().string(containsString("Create your Pivotal ID")))
            .andExpect(content().string(containsString("Pivotal products")))
            .andExpect(content().string(not(containsString("Create your account"))))
            .andExpect(content().string(containsString("Create Pivotal ID")))
            .andExpect(content().string(not(containsString("Create account"))));
    }

    @Test
    public void testAcceptInvitationEmailWithinZone() throws Exception {
        String subdomain = generator.generate();
        MockMvcUtils.utils().createOtherIdentityZone(subdomain, getMockMvc(), getWebApplicationContext());
        ((MockEnvironment) getWebApplicationContext().getEnvironment()).setProperty("login.brand", "pivotal");

        getMockMvc().perform(get(getAcceptInvitationLink())
                                 .with(new SetServerNameRequestPostProcessor(subdomain + ".localhost")))
            .andExpect(content().string(containsString("Create your account")))
            .andExpect(content().string(not(containsString("Pivotal ID"))))
            .andExpect(content().string(not(containsString("Create Pivotal ID"))))
            .andExpect(content().string(containsString("Create account")));
    }

    private String getAcceptInvitationLink() throws Exception {
        String userToken = MockMvcUtils.utils().getScimInviteUserToken(getMockMvc(), clientId, clientSecret);
        String email = generator.generate().toLowerCase() + "@"+domain;
        sendRequestWithToken(userToken, null, clientId, "example.com", email);
        Iterator<MimeMessageWrapper> receivedEmail = fakeJavaMailSender.getSentMessages().iterator();
        MimeMessageWrapper message = receivedEmail.next();
        MockMvcTestClient mockMvcTestClient = new MockMvcTestClient(getMockMvc());
        return mockMvcTestClient.extractLink(message.getContentString());
    }

    @Test
    public void test_Invitations_Accept_Get_Security() throws Exception {
        getWebApplicationContext().getBean(JdbcTemplate.class).update("DELETE FROM expiring_code_store");
        SecurityContext marissaContext = MockMvcUtils.utils().getMarissaSecurityContext(getWebApplicationContext());
        String email = generator.generate()+"@"+domain;

        String userToken = MockMvcUtils.utils().getScimInviteUserToken(getMockMvc(), clientId, clientSecret);
        sendRequestWithToken(userToken, null, clientId, "example.com", "user1@"+domain);

        String code = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("SELECT code FROM expiring_code_store", String.class);
        assertNotNull("Invite Code Must be Present", code);

        MockHttpServletRequestBuilder accept = get("/invitations/accept")
            .param("code", code);

        getMockMvc().perform(accept)
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("<form method=\"post\" novalidate=\"novalidate\" action=\"/invitations/accept.do\">")));
    }


    @Test
    public void testInviteUserWithClientCredentials() throws Exception {
        String email = "user1@example.com";
        sendRequestWithToken(scimInviteToken, null, clientId, "example.com", email);
        assertEmailsSent(email);
    }

    @Test
    public void testInviteMultipleUsersWithClientCredentials() throws Exception {
        String[] emails = new String[] {"user1@"+domain, "user2@"+domain};
        sendRequestWithToken(scimInviteToken, null, clientId, "example.com", emails);
        assertEmailsSent(emails);
    }

    @Test
    public void testInviteUserWithUserCredentials() throws Exception {
        String userToken = MockMvcUtils.utils().getScimInviteUserToken(getMockMvc(), clientId, clientSecret);
        sendRequestWithToken(userToken, null, clientId, "example.com", "user1@example.com");
        assertEmailsSent("user1@example.com");
    }

    @Test
    public void test_multiple_users_email_exists_with_one_origin() throws Exception {
        String clientAdminToken = utils().getClientOAuthAccessToken(getMockMvc(), "admin", "adminsecret","");
        String username1 = generator.generate();
        String username2 = generator.generate();
        String email = generator.generate().toLowerCase()+"@"+generator.generate().toLowerCase()+".com";
        ScimUser user1 = new ScimUser(null, username1, "givenName", "familyName");
        user1.setPrimaryEmail(email);
        user1.setOrigin(UAA);
        user1 = utils().createUser(getMockMvc(), clientAdminToken, user1);
        ScimUser user2 = new ScimUser(null, username2, "givenName", "familyName");
        user2.setPrimaryEmail(email);
        user2.setOrigin(UAA);
        user2 = utils().createUser(getMockMvc(), clientAdminToken, user2);

        String userToken = MockMvcUtils.utils().getScimInviteUserToken(getMockMvc(), clientId, clientSecret);
        InvitationsResponse response = sendRequestWithTokenAndReturnResponse(userToken, null, clientId, "example.com", email);
        assertEquals(0, response.getNewInvites().size());
        assertEquals(1, response.getFailedInvites().size());
        assertEquals("user.ambiguous", response.getFailedInvites().get(0).getErrorCode());

    }


    public static InvitationsResponse sendRequestWithTokenAndReturnResponse(String token,
                                                                            String subdomain,
                                                                            String clientId,
                                                                            String redirectUri,
                                                                            String...emails) throws Exception {
        InvitationsRequest invitations = new InvitationsRequest(emails);

        String requestBody = JsonUtils.writeValueAsString(invitations);

        MockHttpServletRequestBuilder post = post("/invite_users")
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, redirectUri)
            .header("Authorization", "Bearer " + token)
            .contentType(APPLICATION_JSON)
            .content(requestBody);
        if (StringUtils.hasText(subdomain)) {
            post.with(new SetServerNameRequestPostProcessor(subdomain+".localhost"));
        }
        MvcResult result = getMockMvc().perform(
            post
        )
            .andExpect(status().isOk())
            .andReturn();
        return JsonUtils.readValue(result.getResponse().getContentAsString(), InvitationsResponse.class);
    }
    public static void sendRequestWithToken(String token, String subdomain, String clientId, String redirectUri, String...emails) throws Exception {
        InvitationsResponse response = sendRequestWithTokenAndReturnResponse(token, subdomain, clientId, redirectUri, emails);
        assertThat(response.getNewInvites().size(), is(emails.length));
        assertThat(response.getFailedInvites().size(), is(0));
    }

    protected void assertEmailsSent(String...emails) throws MessagingException {
        assertEquals(emails.length, fakeJavaMailSender.getSentMessages().size());
        for (int i=0; i < emails.length; i++) {
            MimeMessageWrapper mimeMessageWrapper = fakeJavaMailSender.getSentMessages().get(i);
            assertEquals(1, mimeMessageWrapper.getRecipients(Message.RecipientType.TO).size());
            assertEquals(emails[i], mimeMessageWrapper.getRecipients(Message.RecipientType.TO).get(0).toString());
        }
    }

}
