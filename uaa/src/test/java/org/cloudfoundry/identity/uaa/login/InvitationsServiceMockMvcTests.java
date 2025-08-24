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

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.message.EmailService;
import org.cloudfoundry.identity.uaa.message.util.FakeJavaMailSender;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.IdentityZoneCreationResult;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.ZoneScimInviteData;
import org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils;
import org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.AlphanumericRandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.context.WebApplicationContext;

import java.net.URL;
import java.util.Arrays;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.hamcrest.Matchers.containsString;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrlPattern;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

@DefaultTestContext
public class InvitationsServiceMockMvcTests {
    @Autowired
    MockMvc mockMvc;

    @Autowired
    WebApplicationContext webApplicationContext;

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @Autowired
    JdbcTemplate jdbcTemplate;

    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @Autowired
    EmailService emailService;

    public static final String REDIRECT_URI = "http://invitation.redirect.test";
    private JavaMailSender originalSender;
    private final FakeJavaMailSender fakeJavaMailSender = new FakeJavaMailSender();
    private final AlphanumericRandomValueStringGenerator generator = new AlphanumericRandomValueStringGenerator();
    private String clientId;
    private String userInviteToken;

    @BeforeEach
    void setUp() throws Exception {
        String adminToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", "clients.admin clients.read clients.write clients.secret scim.read scim.write", null);
        clientId = generator.generate().toLowerCase();
        String clientSecret = generator.generate().toLowerCase();
        String authorities = "scim.read,scim.invite";
        MockMvcUtils.createClient(this.mockMvc, adminToken, clientId, clientSecret, Collections.singleton("oauth"), Arrays.asList("scim.read", "scim.invite"), Arrays.asList("client_credentials", "password"), authorities, Collections.singleton(REDIRECT_URI), IdentityZone.getUaa());
        userInviteToken = MockMvcUtils.getScimInviteUserToken(mockMvc, clientId, clientSecret, null, "admin", "adminsecret");
        jdbcTemplate.update("DELETE FROM expiring_code_store");
    }

    @BeforeEach
    void setUpFakeMailServer() {
        originalSender = emailService.getMailSender();
        emailService.setMailSender(fakeJavaMailSender);
    }

    @AfterEach
    void restoreMailServer() {
        emailService.setMailSender(originalSender);
    }

    @BeforeEach
    @AfterEach
    void clearOutCodeTable() {
        jdbcTemplate.update("DELETE FROM expiring_code_store");
        fakeJavaMailSender.clearMessage();
    }

    @Test
    void inviteUserCorrectOriginSet() throws Exception {
        String email = new AlphanumericRandomValueStringGenerator().generate().toLowerCase() + "@test.org";
        inviteUser(webApplicationContext, mockMvc, email, userInviteToken, null, clientId, OriginKeys.UAA);
    }

    @Test
    void authorizeWithInvitationLogin() throws Exception {
        String email = new AlphanumericRandomValueStringGenerator().generate().toLowerCase() + "@test.org";
        URL inviteLink = inviteUser(webApplicationContext, mockMvc, email, userInviteToken, null, clientId, OriginKeys.UAA);
        assertThat(jdbcTemplate.queryForObject("SELECT origin FROM users WHERE username=?", String.class, new Object[]{email})).isEqualTo(OriginKeys.UAA);

        String code = extractInvitationCode(inviteLink.toString());
        MvcResult result = mockMvc.perform(
                        get("/invitations/accept")
                                .param("code", code)
                                .accept(MediaType.TEXT_HTML)
                )
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Email: " + email)))
                .andReturn();
        MockHttpSession inviteSession = (MockHttpSession) result.getRequest().getSession(false);
        assertThat(inviteSession).isNotNull();
        assertThat(inviteSession.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY)).isNotNull();
        String redirectUri = "https://example.com/dashboard/?appGuid=app-guid";
        String clientId = "authclient-" + new AlphanumericRandomValueStringGenerator().generate();
        UaaClientDetails client = new UaaClientDetails(clientId, "", "openid", GRANT_TYPE_AUTHORIZATION_CODE, "", redirectUri);
        client.setClientSecret("secret");
        String adminToken = MockMvcUtils.getClientCredentialsOAuthAccessToken(mockMvc, "admin", "adminsecret", "", null);
        MockMvcUtils.createClient(mockMvc, adminToken, client);

        String state = new AlphanumericRandomValueStringGenerator().generate();
        MockHttpServletRequestBuilder authRequest = get("/oauth/authorize")
                .session(inviteSession)
                .param(OAuth2Utils.RESPONSE_TYPE, "code")
                .param(OAuth2Utils.SCOPE, "openid")
                .param(OAuth2Utils.STATE, state)
                .param(OAuth2Utils.CLIENT_ID, clientId)
                .param(OAuth2Utils.REDIRECT_URI, redirectUri);

        result = mockMvc
                .perform(authRequest)
                .andExpect(status().is3xxRedirection())
                .andReturn();
        String location = result.getResponse().getHeader("Location");
        assertThat(location).endsWith("/login")
                .doesNotContain("code");
    }

    @Test
    void acceptInvitationShouldNotLogYouIn() throws Exception {
        String email = new AlphanumericRandomValueStringGenerator().generate().toLowerCase() + "@test.org";
        URL inviteLink = inviteUser(webApplicationContext, mockMvc, email, userInviteToken, null, clientId, OriginKeys.UAA);
        assertThat(jdbcTemplate.queryForObject("SELECT origin FROM users WHERE username=?", String.class, new Object[]{email})).isEqualTo(OriginKeys.UAA);

        String code = extractInvitationCode(inviteLink.toString());
        MvcResult result = mockMvc.perform(get("/invitations/accept")
                        .param("code", code)
                        .accept(MediaType.TEXT_HTML)
                )
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Email: " + email)))
                .andReturn();

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        mockMvc.perform(
                        get("/profile")
                                .session(session)
                                .accept(MediaType.TEXT_HTML)
                )
                .andExpect(status().isFound())
                .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    void acceptInvitationForVerifiedUserSendsRedirect() throws Exception {
        String email = new AlphanumericRandomValueStringGenerator().generate().toLowerCase() + "@test.org";
        URL inviteLink = inviteUser(webApplicationContext, mockMvc, email, userInviteToken, null, clientId, OriginKeys.UAA);

        jdbcTemplate.update("UPDATE users SET verified=true WHERE email=?", email);
        assertThat(queryUserForField(jdbcTemplate, email, "verified", Boolean.class)).as("User should not be verified").isTrue();
        assertThat(queryUserForField(jdbcTemplate, email, OriginKeys.ORIGIN, String.class)).isEqualTo(OriginKeys.UAA);

        String code = extractInvitationCode(inviteLink.toString());
        mockMvc.perform(
                        get("/invitations/accept")
                                .param("code", code)
                                .accept(MediaType.TEXT_HTML)
                )
                .andExpect(status().isFound())
                .andExpect(redirectedUrl(REDIRECT_URI));
    }

    @Test
    void acceptInvitationForUaaUserShouldNotExpireInvitelink() throws Exception {
        String email = new AlphanumericRandomValueStringGenerator().generate().toLowerCase() + "@test.org";
        URL inviteLink = inviteUser(webApplicationContext, mockMvc, email, userInviteToken, null, clientId, OriginKeys.UAA);
        assertThat(queryUserForField(jdbcTemplate, email, OriginKeys.ORIGIN, String.class)).isEqualTo(OriginKeys.UAA);

        String code = extractInvitationCode(inviteLink.toString());
        MockHttpServletRequestBuilder get = get("/invitations/accept")
                .param("code", code)
                .accept(MediaType.TEXT_HTML);
        mockMvc.perform(get)
                .andExpect(status().isOk());
        mockMvc.perform(get)
                .andExpect(status().isOk());
        mockMvc.perform(get)
                .andExpect(status().isOk());
    }

    @Test
    void invalid_code() throws Exception {
        String email = new AlphanumericRandomValueStringGenerator().generate().toLowerCase() + "@test.org";
        String invalid = new AlphanumericRandomValueStringGenerator().generate().toLowerCase() + "@test.org";
        URL inviteLink = inviteUser(webApplicationContext, mockMvc, email, userInviteToken, null, clientId, OriginKeys.UAA);
        URL invalidLink = inviteUser(webApplicationContext, mockMvc, invalid, userInviteToken, null, clientId, OriginKeys.UAA);

        assertThat(queryUserForField(jdbcTemplate, email, "verified", Boolean.class)).as("User should not be verified").isFalse();
        assertThat(queryUserForField(jdbcTemplate, email, OriginKeys.ORIGIN, String.class)).isEqualTo(OriginKeys.UAA);

        String code = extractInvitationCode(inviteLink.toString());
        String invalidCode = extractInvitationCode(invalidLink.toString());

        MvcResult result = mockMvc.perform(get("/invitations/accept")
                        .param("code", code)
                        .accept(MediaType.TEXT_HTML)
                )
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Email: " + email)))
                .andReturn();

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        result = mockMvc.perform(
                        post("/invitations/accept.do")
                                .session(session)
                                .param("password", "s3cret")
                                .param("password_confirmation", "s3cret")
                                .param("code", invalidCode)
                                .with(cookieCsrf())
                )
                .andExpect(status().isUnprocessableEntity())
                .andExpect(model().attribute("error_message_code", "code_expired"))
                .andExpect(view().name("invitations/accept_invite"))
                .andReturn();

        assertThat(queryUserForField(jdbcTemplate, email, "verified", Boolean.class)).as("User should be not yet be verified").isFalse();
        assertThat(session.getAttribute("SPRING_SECURITY_CONTEXT")).isNull();

        session = (MockHttpSession) result.getRequest().getSession(false);
        //not logged in anymore
        mockMvc.perform(
                        get("/profile")
                                .session(session)
                                .accept(MediaType.TEXT_HTML)
                )
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    void acceptInvitationSetsYourPassword() throws Exception {
        String email = new AlphanumericRandomValueStringGenerator().generate().toLowerCase() + "@test.org";
        URL inviteLink = inviteUser(webApplicationContext, mockMvc, email, userInviteToken, null, clientId, OriginKeys.UAA);

        assertThat(queryUserForField(jdbcTemplate, email, "verified", Boolean.class)).as("User should not be verified").isFalse();
        assertThat(queryUserForField(jdbcTemplate, email, OriginKeys.ORIGIN, String.class)).isEqualTo(OriginKeys.UAA);

        String code = extractInvitationCode(inviteLink.toString());
        MvcResult result = mockMvc.perform(get("/invitations/accept")
                        .param("code", code)
                        .accept(MediaType.TEXT_HTML)
                )
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Email: " + email)))
                .andReturn();

        code = jdbcTemplate.queryForObject("SELECT code FROM expiring_code_store", String.class);
        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        MockHttpServletRequestBuilder post = post("/invitations/accept.do")
                .param("password", "s3cret")
                .param("password_confirmation", "s3cret")
                .param("code", code)
                .with(cookieCsrf());
        if (session!=null) {
            post = post.session(session);
        }
        result = mockMvc.perform(
                        post
                )
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("/login?success=invite_accepted&form_redirect_uri=" + REDIRECT_URI))
                .andReturn();

        assertThat(queryUserForField(jdbcTemplate, email, "verified", Boolean.class)).as("User should be verified after password reset").isTrue();

        session = (MockHttpSession) result.getRequest().getSession(false);
        mockMvc.perform(
                        get("/profile")
                                .session(session)
                                .accept(MediaType.TEXT_HTML)
                )
                .andExpect(status().isFound())
                .andExpect(redirectedUrlPattern("**/login"));
    }

    @Test
    void inviteLdapUsersVerifiesAndRedirects() throws Exception {
        ZoneScimInviteData zone = createZoneForInvites(mockMvc, webApplicationContext, clientId);
        LdapIdentityProviderDefinition definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes("", "", "", "", "", "", "", "", "", false, false, false, 1, true);

        String domain = generator.generate().toLowerCase() + ".com";
        definition.setEmailDomain(Collections.singletonList(domain));
        IdentityProvider provider = createIdentityProvider(mockMvc, zone.getZone(), OriginKeys.LDAP, definition);
        String email = new AlphanumericRandomValueStringGenerator().generate().toLowerCase() + "@" + domain;
        URL inviteLink = inviteUser(webApplicationContext, mockMvc, email, zone.getAdminToken(), zone.getZone().getIdentityZone().getSubdomain(), zone.getScimInviteClient().getClientId(), provider.getOriginKey());
        String code = extractInvitationCode(inviteLink.toString());

        assertThat(queryUserForField(jdbcTemplate, email, "verified", Boolean.class)).as("User should not be verified").isFalse();
        assertThat(queryUserForField(jdbcTemplate, email, OriginKeys.ORIGIN, String.class)).isEqualTo(OriginKeys.LDAP);

        ResultActions actions = mockMvc.perform(get("/invitations/accept")
                .param("code", code)
                .accept(MediaType.TEXT_HTML)
                .header("Host", zone.getZone().getIdentityZone().getSubdomain() + ".localhost")
        );
        actions
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Email: " + email)));

        assertThat(queryUserForField(jdbcTemplate, email, "verified", Boolean.class)).as("LDAP user should not be verified after accepting invite until logging in").isFalse();
    }

    @Test
    void inviteSamlUserWillRedirectUponAccept() throws Exception {
        ZoneScimInviteData zone = createZoneForInvites(mockMvc, webApplicationContext, clientId);
        String entityID = generator.generate();
        String originKey = "invite1-" + generator.generate().toLowerCase();
        String domain = generator.generate().toLowerCase() + ".com";
        SamlIdentityProviderDefinition definition = getSamlIdentityProviderDefinition(zone.getZone(), entityID);
        definition.setEmailDomain(Collections.singletonList(domain));
        definition.setIdpEntityAlias(originKey);
        IdentityProvider<SamlIdentityProviderDefinition> provider = createIdentityProvider(mockMvc, zone.getZone(), originKey, definition);

        String email = new AlphanumericRandomValueStringGenerator().generate().toLowerCase() + "@" + domain;
        URL inviteLink = inviteUser(webApplicationContext, mockMvc, email, zone.getAdminToken(), zone.getZone().getIdentityZone().getSubdomain(), zone.getScimInviteClient().getClientId(), provider.getOriginKey());
        String code = extractInvitationCode(inviteLink.toString());

        assertThat(queryUserForField(jdbcTemplate, email, "verified", Boolean.class)).as("User should not be verified").isFalse();
        assertThat(queryUserForField(jdbcTemplate, email, OriginKeys.ORIGIN, String.class)).isEqualTo(originKey);

        //should redirect to saml provider
        mockMvc.perform(
                        get("/invitations/accept")
                                .param("code", code)
                                .accept(MediaType.TEXT_HTML)
                                .header("Host", zone.getZone().getIdentityZone().getSubdomain() + ".localhost")
                )
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/saml2/authenticate/%s".formatted(originKey)));

        assertThat(queryUserForField(jdbcTemplate, email, OriginKeys.ORIGIN, String.class)).isEqualTo(provider.getOriginKey());
        assertThat(queryUserForField(jdbcTemplate, email, "verified", Boolean.class)).as("Saml user should not yet be verified after clicking on the accept link").isFalse();
    }

    private static <T> T queryUserForField(JdbcTemplate jdbcTemplate, String email, String field, Class<T> type) {
        return jdbcTemplate.queryForObject("SELECT " + field + " FROM users WHERE email=?", type, email);
    }

    private static ZoneScimInviteData createZoneForInvites(MockMvc mockMvc, WebApplicationContext webApplicationContext, String clientId) throws Exception {
        return MockMvcUtils.createZoneForInvites(mockMvc, webApplicationContext, clientId, REDIRECT_URI, IdentityZoneHolder.getCurrentZoneId());
    }

    private static <T extends AbstractIdentityProviderDefinition> IdentityProvider<T> createIdentityProvider(MockMvc mockMvc, IdentityZoneCreationResult zone, String nameAndOriginKey, T definition) throws Exception {
        return MockMvcUtils.createIdentityProvider(mockMvc, zone, nameAndOriginKey, definition);
    }

    private static SamlIdentityProviderDefinition getSamlIdentityProviderDefinition(IdentityZoneCreationResult zone, String entityID) {
        return new SamlIdentityProviderDefinition()
                .setMetaDataLocation(MockMvcUtils.IDP_META_DATA.formatted(entityID))
                .setIdpEntityAlias(entityID)
                .setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
                .setLinkText("Test Saml Provider")
                .setZoneId(zone.getIdentityZone().getId());
    }

    private static URL inviteUser(WebApplicationContext webApplicationContext, MockMvc mockMvc, String email, String userInviteToken, String subdomain, String clientId, String expectedOrigin) throws Exception {
        return MockMvcUtils.inviteUser(webApplicationContext, mockMvc, email, userInviteToken, subdomain, clientId, expectedOrigin, REDIRECT_URI);
    }

    private static String extractInvitationCode(String inviteLink) {
        return MockMvcUtils.extractInvitationCode(inviteLink);
    }
}
