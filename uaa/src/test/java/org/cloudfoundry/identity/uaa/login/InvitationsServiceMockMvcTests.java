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
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.saml.LoginSamlAuthenticationProvider;
import org.cloudfoundry.identity.uaa.login.saml.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.util.FakeJavaMailSender;
import org.cloudfoundry.identity.uaa.login.util.FakeJavaMailSender.MimeMessageWrapper;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.IdentityZoneCreationResult;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.UaaIdentityProviderDefinition;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.providers.ExpiringUsernameAuthenticationToken;
import org.springframework.security.saml.SAMLAuthenticationToken;
import org.springframework.security.saml.SAMLConstants;
import org.springframework.security.saml.context.SAMLMessageContext;
import org.springframework.security.saml.metadata.ExtendedMetadata;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.util.StringUtils;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.securityContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class InvitationsServiceMockMvcTests extends InjectedMockContextTest {

    private JavaMailSender originalSender;
    private FakeJavaMailSender fakeJavaMailSender = new FakeJavaMailSender();
    private RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private MockMvcUtils utils = MockMvcUtils.utils();

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
    public void ensure_that_newly_created_user_has_origin_UNKNOWN() throws Exception {
        String username = new RandomValueStringGenerator().generate()+"@test.org";
        AccountCreationService svc = getWebApplicationContext().getBean(AccountCreationService.class);
        ScimUser user = svc.createUser(username, "password", Origin.UNKNOWN);
        assertEquals(Origin.UNKNOWN, user.getOrigin());
        assertFalse(user.isVerified());
    }

    @Test
    public void inviteUser_Correct_Origin_Set() throws Exception {
        String email = new RandomValueStringGenerator().generate()+"@test.org";
        inviteUser(email, null);
    }

    @Test
    public void accept_invitation_origin_reset() throws Exception {
        String email = new RandomValueStringGenerator().generate()+"@test.org";
        MimeMessageWrapper message = inviteUser(email, null);
        String code = extractInvitationCode(message.getContentString());
        MvcResult result = getMockMvc().perform(get("/invitations/accept")
                .param("code", code)
                .accept(MediaType.TEXT_HTML)
        )
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("Email: " + email)))
            .andReturn();

        assertEquals(Origin.UNKNOWN, getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select origin from users where username=?", new Object[]{email}, String.class));

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        getMockMvc().perform(post("/invitations/accept.do")
            .session(session)
            .param("password", "s3cret")
            .param("password_confirmation", "s3cret")
            .with(csrf()))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/home"))
            .andReturn();

        assertEquals(Origin.UAA, getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select origin from users where username=?", new Object[]{email}, String.class));
    }


    @Test
    public void invite_user_show_correct_saml_and_uaa_idp_for_acceptance() throws Exception {
        invite_user_and_check_UI(false, false);
        invite_user_and_check_UI(false, true);
        invite_user_and_check_UI(true, false);
        invite_user_and_check_UI(true, true);
    }

    @Test
    public void invite_user_show_correct_ldap_idp_for_acceptance() throws Exception {
        IdentityZoneCreationResult zone = utils.createOtherIdentityZoneAndReturnResult(generator.generate(), getMockMvc(), getWebApplicationContext(), null);
        LdapIdentityProviderDefinition definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes("","","","","","","","","",false,false,false,1,true);
        createIdentityProvider(zone, generator.generate(), definition);
        String email = new RandomValueStringGenerator().generate()+"@test.org";
        MimeMessageWrapper message = inviteUser(email, zone.getIdentityZone().getSubdomain());
        String code = extractInvitationCode(message.getContentString());
        ResultActions actions = getMockMvc().perform(get("/invitations/accept")
                .param("code", code)
                .accept(MediaType.TEXT_HTML)
                .header("Host", zone.getIdentityZone().getSubdomain() + ".localhost")
        );
        actions.andExpect(status().isOk())
            .andExpect(content().string(containsString("Email: " + email)))
            .andExpect(content().string(containsString("Sign in with enterprise credentials:")))
            .andExpect(content().string(containsString("username")));
    }

    @Test
    public void invite_user_show_sets_correct_ldap_origin_for_acceptance() throws Exception {
        Assume.assumeTrue(java.util.Arrays.asList(getWebApplicationContext().getEnvironment().getActiveProfiles()).contains(Origin.LDAP));
        String email = "marissa2@test.com";
        getWebApplicationContext().getBean(JdbcTemplate.class).update("DELETE FROM users WHERE email=?", email);
        IdentityZoneCreationResult zone = utils.createOtherIdentityZoneAndReturnResult(generator.generate(), getMockMvc(), getWebApplicationContext(), null);
        LdapIdentityProviderDefinition definition = LdapIdentityProviderDefinition.searchAndBindMapGroupToScopes(
            "ldap://localhost:389/",
            "cn=admin,dc=test,dc=com",
            "password",
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
            true);
        createIdentityProvider(zone, Origin.LDAP, definition);

        MimeMessageWrapper message = inviteUser(email, zone.getIdentityZone().getSubdomain());
        String code = extractInvitationCode(message.getContentString());

        List<Map<String,Object>> userInfo = getWebApplicationContext().getBean(JdbcTemplate.class).queryForList("select * from users where email=? and identity_zone_id=?", email, zone.getIdentityZone().getId());
        assertEquals(1, userInfo.size());
        assertEquals(Origin.UNKNOWN, userInfo.get(0).get(Origin.ORIGIN));

        ResultActions actions = getMockMvc().perform(get("/invitations/accept")
                .param("code", code)
                .accept(MediaType.TEXT_HTML)
                .header("Host", zone.getIdentityZone().getSubdomain() + ".localhost")
        );
        MvcResult result = actions.andExpect(status().isOk())
            .andExpect(content().string(containsString("Email: " + email)))
            .andExpect(content().string(containsString("Sign in with enterprise credentials:")))
            .andExpect(content().string(containsString("username")))
            .andReturn();

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        getMockMvc().perform(post("/invitations/accept_enterprise.do")
            .session(session)
            .param("username", "marissa2")
            .param("password", "ldap")
            .header("Host", zone.getIdentityZone().getSubdomain() + ".localhost")
            .with(csrf()))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/home"))
            .andReturn();

        List<Map<String,Object>> newUserInfo = getWebApplicationContext().getBean(JdbcTemplate.class).queryForList("select * from users where email=? and identity_zone_id=?", email, zone.getIdentityZone().getId());
        assertEquals(1, newUserInfo.size());
        assertEquals(Origin.LDAP, newUserInfo.get(0).get(Origin.ORIGIN));
        //ensure that a new user wasn't created
        assertEquals(userInfo.get(0).get("id"), newUserInfo.get(0).get("id"));
    }


    public void invite_user_and_check_UI(boolean disableUAA, boolean disableSaml) throws Exception {
        IdentityZoneCreationResult zone = utils.createOtherIdentityZoneAndReturnResult(generator.generate(), getMockMvc(), getWebApplicationContext(), null);
        String entityID = generator.generate();

        SamlIdentityProviderDefinition definition = getSamlIdentityProviderDefinition(zone, entityID);
        IdentityProvider samlProvider = createIdentityProvider(zone, entityID, definition);
        IdentityProviderProvisioning provisioning = getWebApplicationContext().getBean(IdentityProviderProvisioning.class);
        if (disableSaml) {
            samlProvider.setActive(false);
            provisioning.update(samlProvider);
        }
        if (disableUAA) {
            IdentityProvider uaaProvider = provisioning.retrieveByOrigin(Origin.UAA, zone.getIdentityZone().getId());
            uaaProvider.setActive(false);
            provisioning.update(uaaProvider);
        }

        String email = new RandomValueStringGenerator().generate()+"@test.org";
        MimeMessageWrapper message = inviteUser(email, zone.getIdentityZone().getSubdomain());
        String code = extractInvitationCode(message.getContentString());

        ResultActions actions = getMockMvc().perform(get("/invitations/accept")
                .param("code", code)
                .accept(MediaType.TEXT_HTML)
                .header("Host", zone.getIdentityZone().getSubdomain() + ".localhost")
        );

        if (disableUAA && (!disableSaml)) {
            //redirect to SAML provider
            actions.andExpect(status().isFound());
            actions.andExpect(redirectedUrl("saml/discovery?returnIDParam=idp&entityID="+zone.getIdentityZone().getSubdomain()+".cloudfoundry-saml-login&idp="+entityID+"&isPassive=true"));
        } else {
            if (disableSaml && disableUAA) {
                actions.andExpect(status().isUnprocessableEntity());
                actions.andExpect(content().string(containsString("Your invitation does not match any suitable authentication provider.")));
                actions.andExpect(content().string(not(containsString("Test Saml Provider"))));
                actions.andExpect(content().string(not(containsString("password_confirmation"))));
            } else {
                actions.andExpect(status().isOk());
                actions.andExpect(content().string(containsString("Email: " + email)));
                if (!disableUAA){
                    actions.andExpect(content().string(containsString("password_confirmation")));
                } else if (!disableSaml){
                    actions.andExpect(content().string(containsString("Test Saml Provider")));
                }
            }
        }
        assertEquals(Origin.UNKNOWN, getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select origin from users where username=?", new Object[]{email}, String.class));
    }

    @Test
    public void invite_saml_user_with_different_email_after_login() throws Exception {
        IdentityZoneCreationResult zone = utils.createOtherIdentityZoneAndReturnResult(generator.generate(), getMockMvc(), getWebApplicationContext(), null);
        String entityID = generator.generate();

        SamlIdentityProviderDefinition definition = getSamlIdentityProviderDefinition(zone, entityID);
        createIdentityProvider(zone, entityID, definition);


        String email = new RandomValueStringGenerator().generate()+"@test.org";
        MimeMessageWrapper message = inviteUser(email, zone.getIdentityZone().getSubdomain());
        String code = extractInvitationCode(message.getContentString());
        MvcResult result =
            getMockMvc().perform(get("/invitations/accept")
                    .param("code", code)
                    .accept(MediaType.TEXT_HTML)
                    .header("Host", zone.getIdentityZone().getSubdomain()+".localhost")
            )
                .andExpect(status().isOk())
                .andExpect(content().string(containsString("Email: " + email)))
                .andExpect(content().string(containsString("Test Saml Provider")))
                .andReturn();


        assertEquals(Origin.UNKNOWN, getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select origin from users where username=?", new Object[]{email}, String.class));

        MockHttpSession session = (MockHttpSession) result.getRequest().getSession(false);
        assertNotNull(session);
        try {
            mockSamlAuthentication(zone, entityID, email, generator.generate()+"@test.org");
            fail();
        } catch (BadCredentialsException x) {}

        //validate that we did not change the invitation
        assertEquals(Origin.UNKNOWN, getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select origin from users where username=?", new Object[]{email}, String.class));
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

    protected void mockSamlAuthentication(IdentityZoneCreationResult zone, String entityID, final String invitedEmail, final String authenticatedEmail) {
        try {
            //perform SAML Login
            //setup the existing token
            IdentityZoneHolder.set(zone.getIdentityZone());
            UaaPrincipal invited = new UaaPrincipal(getWebApplicationContext().getBean(UaaUserDatabase.class).retrieveUserByName(invitedEmail, Origin.UNKNOWN));
            UaaAuthentication invitedAuthentication = new UaaAuthentication(invited, Collections.EMPTY_LIST, mock(UaaAuthenticationDetails.class));

            ExtendedMetadata metadata = mock(ExtendedMetadata.class);
            when(metadata.getAlias()).thenReturn(entityID);
            SAMLMessageContext contxt = mock(SAMLMessageContext.class);
            when(contxt.getPeerExtendedMetadata()).thenReturn(metadata);
            when(contxt.getCommunicationProfileId()).thenReturn(SAMLConstants.SAML2_WEBSSO_PROFILE_URI);
            SAMLAuthenticationToken token = new SAMLAuthenticationToken(contxt);

            SecurityContextHolder.getContext().setAuthentication(invitedAuthentication);
            LoginSamlAuthenticationProvider authprovider = new LoginSamlAuthenticationProvider() {
                @Override
                protected ExpiringUsernameAuthenticationToken getExpiringUsernameAuthenticationToken(Authentication authentication) {
                    return new ExpiringUsernameAuthenticationToken(authenticatedEmail, "");
                }
            };
            authprovider.setUserDatabase(getWebApplicationContext().getBean(UaaUserDatabase.class));
            authprovider.setIdentityProviderProvisioning(getWebApplicationContext().getBean(IdentityProviderProvisioning.class));
            authprovider.setApplicationEventPublisher(getWebApplicationContext().getBean(LoginSamlAuthenticationProvider.class).getApplicationEventPublisher());

            authprovider.authenticate(token);
        } finally {
            IdentityZoneHolder.clear();
            SecurityContextHolder.clearContext();
        }
    }

    @Test
    public void invite_user_show_correct_saml_idp_for_acceptance() throws Exception {}

    @Test
    public void accept_invite_for_uaa_changes_correct_origin() throws Exception {}

    @Test
    public void accept_invite_for_saml_changes_correct_origin() throws Exception {}

    @Test
    public void accept_invite_for_ldap_changes_correct_origin() throws Exception {}

    @Test
    public void accept_invite_for_existing_user_deletes_invite() throws Exception {}

    public MimeMessageWrapper inviteUser(String email, String subdomain) throws Exception {
        SecurityContext marissa = MockMvcUtils.utils().getMarissaSecurityContext(getWebApplicationContext());
        MockHttpServletRequestBuilder post = post("/invitations/new.do")
            .accept(MediaType.TEXT_HTML)
            .param("email", email)
            .with(securityContext(marissa))
            .with(csrf());
        if (StringUtils.hasText(subdomain)) {
            post.header("Host", subdomain+".localhost");
        }
        getMockMvc().perform(post)
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("sent"));

        assertEquals(Origin.UNKNOWN, getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("SELECT origin FROM users WHERE username='" + email + "'", String.class));

        assertEquals(1, fakeJavaMailSender.getSentMessages().size());
        MimeMessageWrapper message = fakeJavaMailSender.getSentMessages().get(0);
        fakeJavaMailSender.clearMessage();
        return message;
    }

    public String extractInvitationCode(String email) throws Exception {
        System.out.println(email);
        Pattern p = Pattern.compile("accept\\?code\\=(.*?)\\\"\\>Accept Invite");
        Matcher m = p.matcher(email);

        if (m.find()) {
            return m.group(1);
        } else {
            return null;
        }
    }

}
