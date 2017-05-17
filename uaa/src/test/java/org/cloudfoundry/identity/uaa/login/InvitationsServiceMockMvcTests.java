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

import org.cloudfoundry.identity.uaa.codestore.InMemoryExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.message.EmailService;
import org.cloudfoundry.identity.uaa.message.util.FakeJavaMailSender;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.IdentityZoneCreationResult;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.ZoneScimInviteData;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapterFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.SQLServerLimitSqlAdapter;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.util.OAuth2Utils;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import java.net.URL;
import java.util.Arrays;
import java.util.Collections;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.utils;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.endsWith;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

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

    public ZoneScimInviteData createZoneForInvites() throws Exception {
        return utils().createZoneForInvites(getMockMvc(), getWebApplicationContext(), clientId, REDIRECT_URI);
    }

    @Before
    public void setUp() throws Exception {
        adminToken = MockMvcUtils.utils().getClientCredentialsOAuthAccessToken(getMockMvc(), "admin", "adminsecret", "clients.admin clients.read clients.write clients.secret scim.read scim.write", null);
        clientId = generator.generate().toLowerCase();
        clientSecret = generator.generate().toLowerCase();
        authorities = "scim.read,scim.invite";
        MockMvcUtils.utils().createClient(this.getMockMvc(), adminToken, clientId, clientSecret, Collections.singleton("oauth"), Arrays.asList("scim.read","scim.invite"), Arrays.asList(new String[]{"client_credentials", "password"}), authorities, Collections.singleton(REDIRECT_URI), IdentityZone.getUaa());
        userInviteToken = MockMvcUtils.utils().getScimInviteUserToken(getMockMvc(), clientId, clientSecret, null);
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
    public void clearOutCodeTable() throws Exception {
        getWebApplicationContext().getBean(JdbcTemplate.class).update("DELETE FROM expiring_code_store");
        fakeJavaMailSender.clearMessage();
    }

    @Test
    public void inviteUser_Correct_Origin_Set() throws Exception {
        String email = new RandomValueStringGenerator().generate().toLowerCase()+"@test.org";
        inviteUser(email, userInviteToken, null, clientId, OriginKeys.UAA);
    }

    protected <T> T queryUserForField(String email, String field, Class<T> type) throws Exception {
        return getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("SELECT "+field+" FROM users WHERE email=?",type, email);
    }


    @Test
    public void test_authorize_with_invitation_login() throws Exception {
        String email = new RandomValueStringGenerator().generate().toLowerCase()+"@test.org";
        URL inviteLink = inviteUser(email, userInviteToken, null, clientId, OriginKeys.UAA);
        assertEquals(OriginKeys.UAA, getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select origin from users where username=?", new Object[]{email}, String.class));

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
        URL inviteLink = inviteUser(email, userInviteToken, null, clientId, OriginKeys.UAA);
        assertEquals(OriginKeys.UAA, getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select origin from users where username=?", new Object[]{email}, String.class));

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
        URL inviteLink = inviteUser(email, userInviteToken, null, clientId, OriginKeys.UAA);

        String dbTrueString = LimitSqlAdapterFactory.getLimitSqlAdapter().getClass().equals(SQLServerLimitSqlAdapter.class) ? "1" : "true";
        getWebApplicationContext().getBean(JdbcTemplate.class).update("UPDATE users SET verified="+dbTrueString+" WHERE email=?",email);
        assertTrue("User should not be verified", queryUserForField(email, "verified", Boolean.class));
        assertEquals(OriginKeys.UAA, queryUserForField(email, OriginKeys.ORIGIN, String.class));

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
    public void accept_invitation_for_uaa_user_should_expire_invitelink() throws Exception {
        String email = new RandomValueStringGenerator().generate().toLowerCase() + "@test.org";
        URL inviteLink = inviteUser(email, userInviteToken, null, clientId, OriginKeys.UAA);
        assertEquals(OriginKeys.UAA, queryUserForField(email, OriginKeys.ORIGIN, String.class));

        String code = extractInvitationCode(inviteLink.toString());
        MockHttpServletRequestBuilder get = get("/invitations/accept")
            .param("code", code)
            .accept(MediaType.TEXT_HTML);
        getMockMvc().perform(get)
            .andExpect(status().isOk());

        getMockMvc().perform(get)
            .andExpect(status().isUnprocessableEntity());
    }

    @Test
    public void invalid_code() throws Exception {
        String email = new RandomValueStringGenerator().generate().toLowerCase()+"@test.org";
        String invalid = new RandomValueStringGenerator().generate().toLowerCase()+"@test.org";
        URL inviteLink = inviteUser(email, userInviteToken, null, clientId, OriginKeys.UAA);
        URL invalidLink = inviteUser(invalid, userInviteToken, null, clientId, OriginKeys.UAA);

        assertFalse("User should not be verified", queryUserForField(email, "verified", Boolean.class));
        assertEquals(OriginKeys.UAA, queryUserForField(email, OriginKeys.ORIGIN, String.class));

        String code = extractInvitationCode(inviteLink.toString());
        String invalidCode = extractInvitationCode(invalidLink.toString());

        MvcResult result = getMockMvc().perform(get("/invitations/accept")
            .param("code", code)
            .accept(MediaType.TEXT_HTML)
        )
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Email: " + email)))
            .andReturn();

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        result = getMockMvc().perform(
            post("/invitations/accept.do")
                .session(session)
                .param("password", "s3cret")
                .param("password_confirmation", "s3cret")
                .param("code",invalidCode)
                .with(csrf())
        )
            .andExpect(status().isUnprocessableEntity())
            .andExpect(model().attribute("error_message_code", "code_expired"))
            .andExpect(view().name("invitations/accept_invite"))
            .andReturn();

        assertFalse("User should be not yet be verified", queryUserForField(email, "verified", Boolean.class));
        assertNull(session.getAttribute("SPRING_SECURITY_CONTEXT"));

        session = (MockHttpSession) result.getRequest().getSession(false);
        //not logged in anymore
        getMockMvc().perform(
            get("/profile")
                .session(session)
                .accept(MediaType.TEXT_HTML)
        )
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    public void accept_invitation_sets_your_password() throws Exception {
        String email = new RandomValueStringGenerator().generate().toLowerCase()+"@test.org";
        URL inviteLink = inviteUser(email, userInviteToken, null, clientId, OriginKeys.UAA);

        assertFalse("User should not be verified", queryUserForField(email, "verified", Boolean.class));
        assertEquals(OriginKeys.UAA, queryUserForField(email, OriginKeys.ORIGIN, String.class));

        String code = extractInvitationCode(inviteLink.toString());
        MvcResult result = getMockMvc().perform(get("/invitations/accept")
                .param("code", code)
                .accept(MediaType.TEXT_HTML)
        )
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Email: " + email)))
            .andReturn();

        code = getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select code from expiring_code_store", String.class);
        code = new InMemoryExpiringCodeStore().extractCode(code);
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
        IdentityProvider provider = createIdentityProvider(zone.getZone(), OriginKeys.LDAP, definition);
        String email = new RandomValueStringGenerator().generate().toLowerCase()+"@"+domain;
        URL inviteLink = inviteUser(email, zone.getAdminToken(), zone.getZone().getIdentityZone().getSubdomain(), zone.getScimInviteClient().getClientId(), provider.getOriginKey());
        String code = extractInvitationCode(inviteLink.toString());

        assertFalse("User should not be verified", queryUserForField(email, "verified", Boolean.class));
        assertEquals(OriginKeys.LDAP, queryUserForField(email, OriginKeys.ORIGIN, String.class));

        ResultActions actions = getMockMvc().perform(get("/invitations/accept")
                .param("code", code)
                .accept(MediaType.TEXT_HTML)
                .header("Host", zone.getZone().getIdentityZone().getSubdomain() + ".localhost")
        );
        actions
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Email: "+email)));

        assertFalse("LDAP user should not be verified after accepting invite until logging in", queryUserForField(email, "verified", Boolean.class));
    }

    @Test
    public void invite_saml_user_will_redirect_upon_accept() throws Exception {
        ZoneScimInviteData zone = createZoneForInvites();
        String entityID = generator.generate();
        String originKey = "invite1-"+generator.generate().toLowerCase();
        String domain = generator.generate().toLowerCase()+".com";
        SamlIdentityProviderDefinition definition = getSamlIdentityProviderDefinition(zone.getZone(), entityID);
        definition.setEmailDomain(Arrays.asList(domain));
        definition.setIdpEntityAlias(originKey);
        IdentityProvider provider = createIdentityProvider(zone.getZone(), originKey, definition);

        String email = new RandomValueStringGenerator().generate().toLowerCase()+"@"+domain;
        URL inviteLink = inviteUser(email,zone.getAdminToken(), zone.getZone().getIdentityZone().getSubdomain(), zone.getScimInviteClient().getClientId(), provider.getOriginKey());
        String code = extractInvitationCode(inviteLink.toString());

        assertFalse("User should not be verified", queryUserForField(email, "verified", Boolean.class));
        assertEquals(originKey, queryUserForField(email, OriginKeys.ORIGIN, String.class));

        //should redirect to saml provider
        getMockMvc().perform(
            get("/invitations/accept")
                .param("code", code)
                .accept(MediaType.TEXT_HTML)
                .header("Host", zone.getZone().getIdentityZone().getSubdomain() + ".localhost")
        )
            .andExpect(status().is3xxRedirection())
            .andExpect(
                redirectedUrl(
                    String.format("/saml/discovery?returnIDParam=idp&entityID=%s.cloudfoundry-saml-login&idp=%s&isPassive=true",
                                  zone.getZone().getIdentityZone().getId(),
                                  originKey)
                )
            );


        assertEquals(provider.getOriginKey(), queryUserForField(email, OriginKeys.ORIGIN, String.class));
        assertFalse("Saml user should not yet be verified after clicking on the accept link", queryUserForField(email, "verified", Boolean.class));
    }

    protected IdentityProvider createIdentityProvider(IdentityZoneCreationResult zone, String nameAndOriginKey, AbstractIdentityProviderDefinition definition) throws Exception {
        return utils().createIdentityProvider(getMockMvc(), zone, nameAndOriginKey, definition);
    }

    protected SamlIdentityProviderDefinition getSamlIdentityProviderDefinition(IdentityZoneCreationResult zone, String entityID) {
        return new SamlIdentityProviderDefinition()
            .setMetaDataLocation(String.format(utils.IDP_META_DATA, entityID))
            .setIdpEntityAlias(entityID)
            .setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
            .setLinkText("Test Saml Provider")
            .setZoneId(zone.getIdentityZone().getId());
    }

    public URL inviteUser(String email, String userInviteToken, String subdomain, String clientId, String expectedOrigin) throws Exception {
        return utils().inviteUser(getWebApplicationContext(), getMockMvc(), email, userInviteToken, subdomain, clientId, expectedOrigin,REDIRECT_URI);
    }

    private String extractInvitationCode(String inviteLink) throws Exception {
        return utils().extractInvitationCode(inviteLink);
    }

}
