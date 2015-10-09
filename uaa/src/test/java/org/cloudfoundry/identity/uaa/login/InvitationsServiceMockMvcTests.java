/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.invitations.InvitationsEndpointMockMvcTests;
import org.cloudfoundry.identity.uaa.invitations.InvitationsResponse;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.saml.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.util.FakeJavaMailSender;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.IdentityZoneCreationResult;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupMember;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.UaaIdentityProviderDefinition;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.net.URL;
import java.util.Arrays;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.cloudfoundry.identity.uaa.scim.ScimGroupMember.Role.MEMBER;
import static org.cloudfoundry.identity.uaa.scim.ScimGroupMember.Type.USER;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class InvitationsServiceMockMvcTests extends InjectedMockContextTest {

    public static final String REDIRECT_URI = "http://invitation.redirect.test";
    private JavaMailSender originalSender;
    private FakeJavaMailSender fakeJavaMailSender = new FakeJavaMailSender();
    private MockMvcUtils utils = MockMvcUtils.utils();
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private String clientId;
    private String clientSecret;
    private String adminToken;
    private String authorities;
    private String userInviteToken;

    public static class ZoneScimInviteData {
        private final IdentityZoneCreationResult zone;
        private final String adminToken;
        private final ClientDetails scimInviteClient;

        public ZoneScimInviteData(String adminToken,
                                  IdentityZoneCreationResult zone,
                                  ClientDetails scimInviteClient) {
            this.adminToken = adminToken;
            this.zone = zone;
            this.scimInviteClient = scimInviteClient;
        }

        public ClientDetails getScimInviteClient() {
            return scimInviteClient;
        }

        public IdentityZoneCreationResult getZone() {
            return zone;
        }

        public String getAdminToken() {
            return adminToken;
        }
    }

    public ZoneScimInviteData createZoneForInvites() throws Exception {
        IdentityZoneCreationResult zone = utils().createOtherIdentityZoneAndReturnResult(generator.generate(), getMockMvc(), getWebApplicationContext(), null);
        BaseClientDetails appClient = new BaseClientDetails("app","","scim.invite", "client_credentials,password,authorization_code","uaa.admin,clients.admin,scim.write,scim.read,scim.invite",REDIRECT_URI);
        appClient.setClientSecret("secret");
        appClient = utils().createClient(getMockMvc(), zone.getZoneAdminToken(), appClient, zone.getIdentityZone());
        appClient.setClientSecret("secret");
        String adminToken = utils().getClientCredentialsOAuthAccessToken(getMockMvc(),
                                                                         appClient.getClientId(),
                                                                         appClient.getClientSecret(),
                                                                         "",
                                                                         zone.getIdentityZone().getSubdomain());


        String username = new RandomValueStringGenerator().generate().toLowerCase()+"@example.com";
        ScimUser user = new ScimUser(clientId, username, "given-name", "family-name");
        user.setPrimaryEmail(username);
        user.setPassword("password");
        user = utils.createUserInZone(getMockMvc(), adminToken, user, zone.getIdentityZone().getSubdomain());
        user.setPassword("password");

        ScimGroup group = new ScimGroup("scim.invite");
        group.setMembers(Arrays.asList(new ScimGroupMember(user.getId(), USER, Arrays.asList(MEMBER))));

        return new ZoneScimInviteData(
            adminToken,
            zone,
            appClient
        );
    }

    @Before
    public void setUp() throws Exception {
        adminToken = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", "clients.read clients.write clients.secret scim.read scim.write", null);
        clientId = generator.generate().toLowerCase();
        clientSecret = generator.generate().toLowerCase();
        authorities = "scim.read,scim.invite";
        MockMvcUtils.utils().createClient(this.getMockMvc(), adminToken, clientId, clientSecret, "oauth", "scim.read,scim.invite", Arrays.asList(new MockMvcUtils.GrantType[]{MockMvcUtils.GrantType.client_credentials, MockMvcUtils.GrantType.password}), authorities, REDIRECT_URI, IdentityZone.getUaa());
        userInviteToken = MockMvcUtils.utils().getScimInviteUserToken(getMockMvc(), clientId, clientSecret);
        getWebApplicationContext().getBean(JdbcTemplate.class).update("delete from expiring_code_store");
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

    @Before
    @After
    public void clearOutCodeTable() {
        getWebApplicationContext().getBean(JdbcTemplate.class).update("DELETE FROM expiring_code_store");
        fakeJavaMailSender.clearMessage();
    }

    @Test
    public void inviteUser_Correct_Origin_Set() throws Exception {
        String email = new RandomValueStringGenerator().generate().toLowerCase()+"@test.org";
        inviteUser(email, userInviteToken, null, clientId, Origin.UAA);
    }

    protected <T> T queryUserForField(String email, String field, Class<T> type) {
        return getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("SELECT "+field+" FROM users WHERE email=?",type, email);
    }


    @Test
    public void test_authorize_with_invitation_login() throws Exception {
        String email = new RandomValueStringGenerator().generate().toLowerCase()+"@test.org";
        URL inviteLink = inviteUser(email, userInviteToken, null, clientId, Origin.UAA);
        assertEquals(Origin.UAA, getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select origin from users where username=?", new Object[]{email}, String.class));

        String code = extractInvitationCode(inviteLink.toString());
        MvcResult result = getMockMvc().perform(
            get("/invitations/accept")
                .param("code", code)
                .accept(MediaType.TEXT_HTML)
        )
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Email: " + email)))
            .andReturn();
        MockHttpSession inviteSession = (MockHttpSession) result.getRequest().getSession(false);
        assertNotNull(inviteSession);
        assertNotNull(inviteSession.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY));
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid";
        String clientId = "authclient-"+new RandomValueStringGenerator().generate();
        BaseClientDetails client = new BaseClientDetails(clientId, "", "openid","authorization_code","",redirectUri);
        client.setClientSecret("secret");
        String adminToken = utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", "", null);
        MockMvcUtils.utils().createClient(getMockMvc(), adminToken, client);

        String state = new RandomValueStringGenerator().generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
            .session(inviteSession)
            .param(OAuth2Utils.RESPONSE_TYPE, "code")
            .param(OAuth2Utils.SCOPE, "openid")
            .param(OAuth2Utils.STATE, state)
            .param(OAuth2Utils.CLIENT_ID, clientId)
            .param(OAuth2Utils.REDIRECT_URI, redirectUri);

        result = getMockMvc()
            .perform(authRequest)
            .andExpect(status().is3xxRedirection())
            .andReturn();
        String location = result.getResponse().getHeader("Location");
        assertThat(location, endsWith("/login"));
        assertEquals(-1, location.indexOf("code"));
    }

    @Test
    public void accept_invitation_should_not_log_you_in() throws Exception {
        String email = new RandomValueStringGenerator().generate().toLowerCase()+"@test.org";
        URL inviteLink = inviteUser(email, userInviteToken, null, clientId, Origin.UAA);
        assertEquals(Origin.UAA, getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select origin from users where username=?", new Object[]{email}, String.class));

        String code = extractInvitationCode(inviteLink.toString());
        MvcResult result = getMockMvc().perform(get("/invitations/accept")
                                                    .param("code", code)
                                                    .accept(MediaType.TEXT_HTML)
        )
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Email: " + email)))
            .andReturn();

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        getMockMvc().perform(
            get("/profile")
                .session(session)
                .accept(MediaType.TEXT_HTML)
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrlPattern("**/login"));

    }

    @Test
    public void accept_invitation_for_verified_user_sends_redirect() throws Exception {
        String email = new RandomValueStringGenerator().generate().toLowerCase() + "@test.org";
        URL inviteLink = inviteUser(email, userInviteToken, null, clientId, Origin.UAA);

        getWebApplicationContext().getBean(JdbcTemplate.class).update("UPDATE users SET verified=true WHERE email=?",email);
        assertTrue("User should not be verified", queryUserForField(email, "verified", Boolean.class));
        assertEquals(Origin.UAA, queryUserForField(email, Origin.ORIGIN, String.class));

        String code = extractInvitationCode(inviteLink.toString());
        getMockMvc().perform(
            get("/invitations/accept")
                .param("code", code)
                .accept(MediaType.TEXT_HTML)
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrl(REDIRECT_URI));
    }



        @Test
    public void accept_invitation_sets_your_password() throws Exception {
        String email = new RandomValueStringGenerator().generate().toLowerCase()+"@test.org";
        URL inviteLink = inviteUser(email, userInviteToken, null, clientId, Origin.UAA);

        assertFalse("User should not be verified", queryUserForField(email, "verified", Boolean.class));
        assertEquals(Origin.UAA, queryUserForField(email, Origin.ORIGIN, String.class));

        String code = extractInvitationCode(inviteLink.toString());
        MvcResult result = getMockMvc().perform(get("/invitations/accept")
                .param("code", code)
                .accept(MediaType.TEXT_HTML)
        )
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Email: " + email)))
            .andReturn();

        code = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select code from expiring_code_store", String.class);
        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        result = getMockMvc().perform(
            post("/invitations/accept.do")
                .session(session)
                .param("password", "s3cret")
                .param("password_confirmation", "s3cret")
                .param("code",code)
                .with(csrf())
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrl(REDIRECT_URI))
            .andReturn();

        assertTrue("User should be verified after password reset", queryUserForField(email, "verified", Boolean.class));

        session = (MockHttpSession) result.getRequest().getSession(false);
        getMockMvc().perform(
            get("/profile")
                .session(session)
                .accept(MediaType.TEXT_HTML)
        )
            .andExpect(status().isOk());
    }


    @Test
    public void invite_ldap_users_verifies_and_redirects() throws Exception {
        ZoneScimInviteData zone = createZoneForInvites();
        LdapIdentityProviderDefinition definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes("", "", "", "", "", "", "", "", "", false, false, false, 1, true);

        String domain = generator.generate().toLowerCase()+".com";
        definition.setEmailDomain(Arrays.asList(domain));
        IdentityProvider provider = createIdentityProvider(zone.getZone(), Origin.LDAP, definition);
        String email = new RandomValueStringGenerator().generate().toLowerCase()+"@"+domain;
        URL inviteLink = inviteUser(email, zone.getAdminToken(), zone.getZone().getIdentityZone().getSubdomain(), zone.getScimInviteClient().getClientId(), provider.getOriginKey());
        String code = extractInvitationCode(inviteLink.toString());

        assertFalse("User should not be verified", queryUserForField(email, "verified", Boolean.class));
        assertEquals(Origin.LDAP, queryUserForField(email, Origin.ORIGIN, String.class));

        ResultActions actions = getMockMvc().perform(get("/invitations/accept")
                .param("code", code)
                .accept(MediaType.TEXT_HTML)
                .header("Host", zone.getZone().getIdentityZone().getSubdomain() + ".localhost")
        );
        actions
            .andExpect(status().isFound())
            .andExpect(redirectedUrl(REDIRECT_URI));

        assertTrue("LDAP user should be verified after accepting invite", queryUserForField(email, "verified", Boolean.class));
    }

    @Test
    public void invite_saml_user_will_redirect_upon_accept() throws Exception {
        ZoneScimInviteData zone = createZoneForInvites();
        String entityID = generator.generate();
        String originKey = generator.generate().toLowerCase();
        String domain = generator.generate().toLowerCase()+".com";
        SamlIdentityProviderDefinition definition = getSamlIdentityProviderDefinition(zone.getZone(), entityID);
        definition.setEmailDomain(Arrays.asList(domain));
        definition.setIdpEntityAlias(originKey);
        IdentityProvider provider = createIdentityProvider(zone.getZone(), originKey, definition);

        String email = new RandomValueStringGenerator().generate().toLowerCase()+"@"+domain;
        URL inviteLink = inviteUser(email,zone.getAdminToken(), zone.getZone().getIdentityZone().getSubdomain(), zone.getScimInviteClient().getClientId(), provider.getOriginKey());
        String code = extractInvitationCode(inviteLink.toString());

        assertFalse("User should not be verified", queryUserForField(email, "verified", Boolean.class));
        assertEquals(originKey, queryUserForField(email, Origin.ORIGIN, String.class));


        getMockMvc().perform(
            get("/invitations/accept")
                .param("code", code)
                .accept(MediaType.TEXT_HTML)
                .header("Host", zone.getZone().getIdentityZone().getSubdomain() + ".localhost")
        )
            .andExpect(status().is3xxRedirection())
            .andExpect(redirectedUrl(REDIRECT_URI));


        assertEquals(provider.getOriginKey(), queryUserForField(email, Origin.ORIGIN, String.class));
        assertTrue("Saml user should be verified after clicking on the accept link", queryUserForField(email, "verified", Boolean.class));
    }

    protected IdentityProvider createIdentityProvider(IdentityZoneCreationResult zone, String nameAndOriginKey, AbstractIdentityProviderDefinition definition) throws Exception {
        IdentityProvider provider = new IdentityProvider();
        provider.setConfig(JsonUtils.writeValueAsString(definition));
        provider.setActive(true);
        provider.setIdentityZoneId(zone.getIdentityZone().getId());
        provider.setName(nameAndOriginKey);
        provider.setOriginKey(nameAndOriginKey);
        if (definition instanceof SamlIdentityProviderDefinition) {
            provider.setType(Origin.SAML);
        } else if (definition instanceof LdapIdentityProviderDefinition) {
            provider.setType(Origin.LDAP);
        } else if (definition instanceof UaaIdentityProviderDefinition) {
            provider.setType(Origin.UAA);
        }
        provider = utils.createIdpUsingWebRequest(getMockMvc(),
            zone.getIdentityZone().getId(),
            zone.getZoneAdminToken(),
            provider,
            status().isCreated());
        return provider;
    }

    protected SamlIdentityProviderDefinition getSamlIdentityProviderDefinition(IdentityZoneCreationResult zone, String entityID) {
        return new SamlIdentityProviderDefinition(
                String.format(utils.IDP_META_DATA, entityID),
                entityID,
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                0,
                false,
                true,
                "Test Saml Provider",
                null,
                zone.getIdentityZone().getId()
            );
    }

    public URL inviteUser(String email, String userInviteToken, String subdomain, String clientId, String expectedOrigin) throws Exception {
        InvitationsResponse response = InvitationsEndpointMockMvcTests.sendRequestWithTokenAndReturnResponse(userInviteToken, subdomain, clientId, REDIRECT_URI, email);
        assertEquals(1, response.getNewInvites().size());
        assertEquals(expectedOrigin, getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("SELECT origin FROM users WHERE username='" + email + "'", String.class));
        return response.getNewInvites().get(0).getInviteLink();
    }

    private String extractInvitationCode(String inviteLink) throws Exception {
        Pattern p = Pattern.compile("accept\\?code=(.*)");
        Matcher m = p.matcher(inviteLink);

        if (m.find()) {
            return m.group(1);
        } else {
            return null;
        }
    }

}
