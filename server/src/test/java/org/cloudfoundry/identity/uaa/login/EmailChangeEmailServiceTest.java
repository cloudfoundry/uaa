/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.account.EmailChangeEmailService;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.test.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.message.EmailService;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.message.MessageType;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.*;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.thymeleaf.spring4.SpringTemplateEngine;

import static org.cloudfoundry.identity.uaa.account.EmailChangeEmailService.CHANGE_EMAIL_REDIRECT_URL;
import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.EMAIL;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyString;
import static org.mockito.Matchers.contains;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = ThymeleafConfig.class)
public class EmailChangeEmailServiceTest {
    private EmailChangeEmailService emailChangeEmailService;
    private ScimUserProvisioning scimUserProvisioning;
    private ExpiringCodeStore codeStore;
    private MessageService messageService;
    private MockHttpServletRequest request;
    private ClientDetailsService clientDetailsService;
    private String companyName;


    @Autowired
    @Qualifier("mailTemplateEngine")
    SpringTemplateEngine templateEngine;

    @After
    public void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        codeStore = mock(ExpiringCodeStore.class);
        clientDetailsService = mock(ClientDetailsService.class);
        messageService = mock(EmailService.class);
        emailChangeEmailService = new EmailChangeEmailService(templateEngine, messageService, scimUserProvisioning, codeStore, clientDetailsService);

        request = new MockHttpServletRequest();
        request.setProtocol("http");
        request.setContextPath("/login");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @Test
    public void beginEmailChange() throws Exception {
        setUpForBeginEmailChange();

        Mockito.verify(messageService).sendMessage(
                eq("new@example.com"),
                eq(MessageType.CHANGE_EMAIL),
                eq("Account Email change verification"),
                contains("<a href=\"http://localhost/login/verify_email?code=the_secret_code\">Verify your email</a>")
        );
    }

    @Test(expected = UaaException.class)
    public void beginEmailChangeWithUsernameConflict() throws Exception {
        ScimUser user = new ScimUser("user-001", "user@example.com", "test-name", "test-name");
        user.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.retrieve(anyString())).thenReturn(user);
        when(scimUserProvisioning.query(anyString())).thenReturn(Collections.singletonList(new ScimUser()));

        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", null, null);
    }

    @Test
    public void testBeginEmailChangeWithCompanyNameConfigured() throws Exception {
        IdentityZoneConfiguration defaultConfig = IdentityZoneHolder.get().getConfig();
        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName("Best Company");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setBranding(branding);
        IdentityZoneHolder.get().setConfig(config);
        try {
            emailChangeEmailService = new EmailChangeEmailService(templateEngine, messageService, scimUserProvisioning, codeStore, clientDetailsService);

            setUpForBeginEmailChange();

            ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
            Mockito.verify(messageService).sendMessage(
              eq("new@example.com"),
              eq(MessageType.CHANGE_EMAIL),
              eq("Best Company Email change verification"),
              emailBodyArgument.capture()
            );

            String emailBody = emailBodyArgument.getValue();

            assertThat(emailBody, containsString("<a href=\"http://localhost/login/verify_email?code=the_secret_code\">Verify your email</a>"));
            assertThat(emailBody, containsString("a Best Company account"));
        } finally {
            IdentityZoneHolder.get().setConfig(defaultConfig);
        }
    }

    @Test
    public void testBeginEmailChangeInOtherZone() throws Exception {
        String zoneName = "The Twiglet Zone 2";
        testBeginEmailChangeInOtherZone(zoneName);
    }

    @Test
    public void testBeginEmailChangeInOtherZone_UTF_8_ZoneName() throws Exception {
        String zoneName = "\u7433\u8D3A";
        testBeginEmailChangeInOtherZone(zoneName);
    }

    public void testBeginEmailChangeInOtherZone(String zoneName) throws Exception {

        IdentityZone zone = MultitenancyFixture.identityZone("test-zone-id", "test");
        zone.setName(zoneName);
        IdentityZoneHolder.set(zone);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("test.localhost");
        request.setContextPath("/login");
        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);

        setUpForBeginEmailChange();

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        Mockito.verify(messageService).sendMessage(
                eq("new@example.com"),
                eq(MessageType.CHANGE_EMAIL),
                eq(zoneName+" Email change verification"),
                emailBodyArgument.capture()
        );

        String emailBody = emailBodyArgument.getValue();

        assertThat(emailBody, containsString(String.format("A request has been made to change the email for %s from %s to %s", zoneName, "user@example.com", "new@example.com")));
        assertThat(emailBody, containsString("<a href=\"http://test.localhost/login/verify_email?code=the_secret_code\">Verify your email</a>"));
        //assertThat(emailBody, containsString("Thank you,<br />\n    "+zoneName));
        assertThat(emailBody, containsString("Thank you"));
        assertThat(emailBody, containsString(zoneName));
    }

    @Test
    public void testCompleteVerification() throws Exception {
        Map<String, String> response = setUpCompleteActivation("user-name", "app", "http://app.com/redirect");
        Assert.assertEquals("user-001", response.get("userId"));
        Assert.assertEquals("user-name", response.get("username"));
        Assert.assertEquals("new@example.com", response.get("email"));
        Assert.assertEquals("http://app.com/redirect", response.get("redirect_url"));
    }

    @Test
    public void testCompleteVerificationWhereUsernameEqualsEmail() throws Exception {
        Map<String, String> response = setUpCompleteActivation("user@example.com", "app", "http://app.com/redirect");
        Assert.assertEquals("user-001", response.get("userId"));
        Assert.assertEquals("new@example.com", response.get("username"));
        Assert.assertEquals("new@example.com", response.get("email"));
        Assert.assertEquals("http://app.com/redirect", response.get("redirect_url"));
    }

    @Test(expected = UaaException.class)
    public void testCompleteVerificationWithInvalidCode() throws Exception {
        when(codeStore.retrieveCode("invalid_code")).thenReturn(null);
        emailChangeEmailService.completeVerification("invalid_code");
    }

    @Test(expected = UaaException.class)
    public void testCompleteVerificationWithInvalidIntent() throws Exception {
        when(codeStore.retrieveCode("invalid_code")).thenReturn(new ExpiringCode("invalid_code", new Timestamp(System.currentTimeMillis()), null, "invalid-intent"));
        emailChangeEmailService.completeVerification("invalid_code");
    }

    @Test
    public void testCompleteActivationWithInvalidClientId() {
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "user-001");
        codeData.put("client_id", "invalid-client");
        codeData.put("email", "new@example.com");

        when(codeStore.retrieveCode("the_secret_code")).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        ScimUser user = new ScimUser("user-001", "user@example.com", "", "");
        user.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.retrieve("user-001")).thenReturn(user);

        doThrow(new NoSuchClientException("no such client")).when(clientDetailsService).loadClientByClientId("invalid-client");
        Map<String, String> response = null;
        try {
            response = emailChangeEmailService.completeVerification("the_secret_code");
        } catch (NoSuchClientException e) {
            assertNull(response.get("redirect_url"));
        }
    }

    @Test
    public void testCompleteActivationWithNoClientId() {
        Map<String, String> response = setUpCompleteActivation("user@example.com", null, null);
        Assert.assertEquals(null, response.get("redirect_url"));
    }

    @Test
    public void testCompleteActivationWhereWildcardsDoNotMatch() {
        Map<String, String> response = setUpCompleteActivation("user@example.com", "app", "http://blah.app.com/redirect");
        Assert.assertEquals("http://fallback.url/redirect", response.get("redirect_url"));
    }

    @Test
    public void testCompleteActivationWithNoRedirectUri() {
        Map<String, String> response = setUpCompleteActivation("user@example.com", "app", null);
        Assert.assertEquals("http://fallback.url/redirect", response.get("redirect_url"));
    }

    private Map<String, String> setUpCompleteActivation(String username, String clientId, String redirectUri) {
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "user-001");
        codeData.put("client_id", clientId);
        codeData.put("redirect_uri", redirectUri);
        codeData.put("email", "new@example.com");
        BaseClientDetails clientDetails = new BaseClientDetails("client-id", null, null, "authorization_grant", null, "http://app.com/*");
        clientDetails.addAdditionalInformation(CHANGE_EMAIL_REDIRECT_URL, "http://fallback.url/redirect");

        when(codeStore.retrieveCode("the_secret_code")).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        ScimUser user = new ScimUser("user-001", username, "", "");
        user.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.retrieve("user-001")).thenReturn(user);

        when(clientDetailsService.loadClientByClientId(clientId)).thenReturn(clientDetails);

        Map<String, String> response = emailChangeEmailService.completeVerification("the_secret_code");

        ScimUser updatedUser = new ScimUser("user-001", "new@example.com", "", "");
        user.setPrimaryEmail("new@example.com");

        verify(scimUserProvisioning).update("user-001", updatedUser);
        return response;
    }

    private void setUpForBeginEmailChange() {
        ScimUser user = new ScimUser("user-001", "user-name", "test-name", "test-name");
        user.setPrimaryEmail("user@example.com");
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "user-001");
        codeData.put("client_id", "app");
        codeData.put("redirect_uri", "http://app.com");
        codeData.put("email", "new@example.com");

        when(scimUserProvisioning.retrieve("user-001")).thenReturn(user);
        when(scimUserProvisioning.query(anyString())).thenReturn(Collections.singletonList(new ScimUser()));
        String data = JsonUtils.writeValueAsString(codeData);
        when(codeStore.generateCode(eq(data), any(Timestamp.class), eq(EMAIL.name()))).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), data, EMAIL.name()));

        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", "app", "http://app.com");

        verify(codeStore).generateCode(eq(JsonUtils.writeValueAsString(codeData)), any(Timestamp.class), eq(EMAIL.name()));
    }

}
