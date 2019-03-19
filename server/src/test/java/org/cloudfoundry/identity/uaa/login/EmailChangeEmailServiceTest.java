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

import org.apache.commons.lang3.RandomStringUtils;
import org.cloudfoundry.identity.uaa.account.EmailChangeEmailService;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.message.EmailService;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.message.MessageType;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.*;
import org.junit.Assert;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.thymeleaf.spring4.SpringTemplateEngine;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.account.EmailChangeEmailService.CHANGE_EMAIL_REDIRECT_URL;
import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.EMAIL;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@ExtendWith(SpringExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
@ContextConfiguration(classes = {ThymeleafAdditional.class,ThymeleafConfig.class})
public class EmailChangeEmailServiceTest {
    public static final String IDENTITY_ZONE_NAME = "IZ Inc";
    private EmailChangeEmailService emailChangeEmailService;
    private ScimUserProvisioning scimUserProvisioning;
    private ExpiringCodeStore codeStore;
    private MessageService messageService;
    private MockHttpServletRequest request;
    private ClientServicesExtension clientDetailsService;
    private String companyName;


    @Autowired
    @Qualifier("mailTemplateEngine")
    SpringTemplateEngine templateEngine;

    @AfterEach
    public void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @BeforeEach
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        codeStore = mock(ExpiringCodeStore.class);
        clientDetailsService = mock(ClientServicesExtension.class);
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
                eq(String.format("%s Email change verification", IDENTITY_ZONE_NAME)),
                contains("<a href=\"http://localhost/login/verify_email?code=the_secret_code\">Verify your email</a>")
        );
    }

    @Test
    public void beginEmailChangeWithUsernameConflict() throws Exception {
        ScimUser user = new ScimUser("user-001", "user@example.com", "test-name", "test-name");
        user.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.retrieve(anyString(), anyString())).thenReturn(user);
        String zoneId = IdentityZoneHolder.get().getId();
        when(scimUserProvisioning.query(anyString(), eq(zoneId))).thenReturn(Collections.singletonList(new ScimUser()));

        Assertions.assertThrows(UaaException.class,
                () -> emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", null, null));
    }

    @Test
    public void testBeginEmailChangeWithCompanyNameConfigured() throws Exception {

        emailChangeEmailService = new EmailChangeEmailService(templateEngine, messageService, scimUserProvisioning, codeStore, clientDetailsService);

        ScimUser user = new ScimUser("user-001", "user-name", "test-name", "test-name");
        user.setPrimaryEmail("user@example.com");
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "user-001");
        codeData.put("client_id", "app");
        codeData.put("redirect_uri", "http://app.com");
        codeData.put("email", "new@example.com");

        IdentityZone identityZone = IdentityZoneHolder.get();
        String zoneId = identityZone.getId();

        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName("Best Company");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setBranding(branding);

        identityZone.setConfig(config);

        IdentityZoneHolder.set(identityZone);

        when(scimUserProvisioning.retrieve("user-001", zoneId)).thenReturn(user);
        when(scimUserProvisioning.query(anyString(), eq(zoneId))).thenReturn(Collections.singletonList(new ScimUser()));
        String data = JsonUtils.writeValueAsString(codeData);
        when(codeStore.generateCode(eq(data), any(Timestamp.class), eq(EMAIL.name()), anyString())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), data, EMAIL.name()));

        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", "app", "http://app.com");

        verify(codeStore).generateCode(eq(JsonUtils.writeValueAsString(codeData)), any(Timestamp.class), eq(EMAIL.name()), eq(zoneId));

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

        ScimUser user = new ScimUser("user-001", "user-name", "test-name", "test-name");
        user.setPrimaryEmail("user@example.com");
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "user-001");
        codeData.put("client_id", "app");
        codeData.put("redirect_uri", "http://app.com");
        codeData.put("email", "new@example.com");

        String zoneId = IdentityZoneHolder.get().getId();

        when(scimUserProvisioning.retrieve("user-001", zoneId)).thenReturn(user);
        when(scimUserProvisioning.query(anyString(), eq(zoneId))).thenReturn(Collections.singletonList(new ScimUser()));
        String data = JsonUtils.writeValueAsString(codeData);
        when(codeStore.generateCode(eq(data), any(Timestamp.class), eq(EMAIL.name()), anyString())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), data, EMAIL.name()));

        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", "app", "http://app.com");

        verify(codeStore).generateCode(eq(JsonUtils.writeValueAsString(codeData)), any(Timestamp.class), eq(EMAIL.name()), eq(zoneId));

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
        assertThat(emailBody, containsString("Thank you,<br />\n    "+zoneName));
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

    @Test
    public void testCompleteVerificationWithInvalidCode() throws Exception {
        when(codeStore.retrieveCode("invalid_code", IdentityZoneHolder.get().getId())).thenReturn(null);

        Assertions.assertThrows(UaaException.class,
                () -> emailChangeEmailService.completeVerification("invalid_code"));

    }

    @Test
    public void testCompleteVerificationWithInvalidIntent() throws Exception {
        when(codeStore.retrieveCode("invalid_code", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("invalid_code", new Timestamp(System.currentTimeMillis()), null, "invalid-intent"));

        Assertions.assertThrows(UaaException.class,
                () -> emailChangeEmailService.completeVerification("invalid_code"));
    }

    @Test
    public void testCompleteActivationWithInvalidClientId() {
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "user-001");
        codeData.put("client_id", "invalid-client");
        codeData.put("email", "new@example.com");

        when(codeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        ScimUser user = new ScimUser("user-001", "user@example.com", "", "");
        user.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.retrieve("user-001", IdentityZoneHolder.get().getId())).thenReturn(user);

        doThrow(new NoSuchClientException("no such client")).when(clientDetailsService).loadClientByClientId("invalid-client", "uaa");
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

        when(codeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        ScimUser user = new ScimUser("user-001", username, "", "");
        user.setPrimaryEmail("user@example.com");
        when(scimUserProvisioning.retrieve("user-001", IdentityZoneHolder.get().getId())).thenReturn(user);

        when(clientDetailsService.loadClientByClientId(clientId, "uaa")).thenReturn(clientDetails);

        Map<String, String> response = emailChangeEmailService.completeVerification("the_secret_code");

        ScimUser updatedUser = new ScimUser("user-001", "new@example.com", "", "");
        user.setPrimaryEmail("new@example.com");

        verify(scimUserProvisioning).update("user-001", updatedUser, IdentityZoneHolder.get().getId());
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

        IdentityZone identityZone = new IdentityZone();
        String zoneId = RandomStringUtils.random(10);
        identityZone.setId(zoneId);
        identityZone.setName(IDENTITY_ZONE_NAME);

        IdentityZoneHolder.set(identityZone);

        when(scimUserProvisioning.retrieve("user-001", zoneId)).thenReturn(user);
        when(scimUserProvisioning.query(anyString(), eq(zoneId))).thenReturn(Collections.singletonList(new ScimUser()));
        String data = JsonUtils.writeValueAsString(codeData);
        when(codeStore.generateCode(eq(data), any(Timestamp.class), eq(EMAIL.name()), anyString())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), data, EMAIL.name()));

        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", "app", "http://app.com");

        verify(codeStore).generateCode(eq(JsonUtils.writeValueAsString(codeData)), any(Timestamp.class), eq(EMAIL.name()), eq(zoneId));
    }

}
