package org.cloudfoundry.identity.uaa.account;

import org.apache.commons.lang3.RandomStringUtils;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.ThymeleafAdditional;
import org.cloudfoundry.identity.uaa.login.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.message.EmailService;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.message.MessageType;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.security.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.*;
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
import org.thymeleaf.spring5.SpringTemplateEngine;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.account.EmailChangeEmailService.CHANGE_EMAIL_REDIRECT_URL;
import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.EMAIL;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(SpringExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
@ContextConfiguration(classes = {
        ThymeleafAdditional.class,
        ThymeleafConfig.class
})
class EmailChangeEmailServiceTest {
    private static final String IDENTITY_ZONE_NAME = "IZ Inc";
    private EmailChangeEmailService emailChangeEmailService;
    private ScimUserProvisioning mockScimUserProvisioning;
    private ExpiringCodeStore mockExpiringCodeStore;
    private MessageService mockEmailService;
    private MultitenantClientServices mockMultitenantClientServices;

    @Autowired
    @Qualifier("mailTemplateEngine")
    private SpringTemplateEngine templateEngine;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        mockScimUserProvisioning = mock(ScimUserProvisioning.class);
        mockExpiringCodeStore = mock(ExpiringCodeStore.class);
        mockMultitenantClientServices = mock(MultitenantClientServices.class);
        mockEmailService = mock(EmailService.class);
        emailChangeEmailService = new EmailChangeEmailService(
                templateEngine,
                mockEmailService,
                mockScimUserProvisioning,
                mockExpiringCodeStore,
                mockMultitenantClientServices);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setProtocol("http");
        request.setContextPath("/login");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    void beginEmailChange() {
        setUpForBeginEmailChange();

        Mockito.verify(mockEmailService).sendMessage(
                eq("new@example.com"),
                eq(MessageType.CHANGE_EMAIL),
                eq(String.format("%s Email change verification", IDENTITY_ZONE_NAME)),
                contains("<a href=\"http://localhost/login/verify_email?code=the_secret_code\">Verify your email</a>")
        );
    }

    @Test
    void beginEmailChangeWithUsernameConflict() {
        ScimUser user = new ScimUser("user-001", "user@example.com", "test-name", "test-name");
        user.setPrimaryEmail("user@example.com");
        when(mockScimUserProvisioning.retrieve(anyString(), anyString())).thenReturn(user);
        String zoneId = IdentityZoneHolder.get().getId();
        when(mockScimUserProvisioning.query(anyString(), eq(zoneId))).thenReturn(Collections.singletonList(new ScimUser()));

        Assertions.assertThrows(UaaException.class,
                () -> emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", null, null));
    }

    @Test
    void beginEmailChangeWithCompanyNameConfigured() {

        emailChangeEmailService = new EmailChangeEmailService(templateEngine, mockEmailService, mockScimUserProvisioning, mockExpiringCodeStore, mockMultitenantClientServices);

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

        when(mockScimUserProvisioning.retrieve("user-001", zoneId)).thenReturn(user);
        when(mockScimUserProvisioning.query(anyString(), eq(zoneId))).thenReturn(Collections.singletonList(new ScimUser()));
        String data = JsonUtils.writeValueAsString(codeData);
        when(mockExpiringCodeStore.generateCode(eq(data), any(Timestamp.class), eq(EMAIL.name()), anyString())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), data, EMAIL.name()));

        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", "app", "http://app.com");

        verify(mockExpiringCodeStore).generateCode(eq(JsonUtils.writeValueAsString(codeData)), any(Timestamp.class), eq(EMAIL.name()), eq(zoneId));

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        Mockito.verify(mockEmailService).sendMessage(
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
    void beginEmailChangeInOtherZone() {
        String zoneName = "The Twiglet Zone 2";
        beginEmailChangeInOtherZone(zoneName);
    }

    @Test
    void beginEmailChangeInOtherZone_UTF_8_ZoneName() {
        String zoneName = "\u7433\u8D3A";
        beginEmailChangeInOtherZone(zoneName);
    }

    @Test
    void completeVerification() {
        Map<String, String> response = setUpCompleteActivation("user-name", "app", "http://app.com/redirect");
        assertEquals("user-001", response.get("userId"));
        assertEquals("user-name", response.get("username"));
        assertEquals("new@example.com", response.get("email"));
        assertEquals("http://app.com/redirect", response.get("redirect_url"));
    }

    @Test
    void completeVerificationWhereUsernameEqualsEmail() {
        Map<String, String> response = setUpCompleteActivation("user@example.com", "app", "http://app.com/redirect");
        assertEquals("user-001", response.get("userId"));
        assertEquals("new@example.com", response.get("username"));
        assertEquals("new@example.com", response.get("email"));
        assertEquals("http://app.com/redirect", response.get("redirect_url"));
    }

    @Test
    void completeVerificationWithInvalidCode() {
        when(mockExpiringCodeStore.retrieveCode("invalid_code", IdentityZoneHolder.get().getId())).thenReturn(null);

        Assertions.assertThrows(UaaException.class,
                () -> emailChangeEmailService.completeVerification("invalid_code"));

    }

    @Test
    void completeVerificationWithInvalidIntent() {
        when(mockExpiringCodeStore.retrieveCode("invalid_code", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("invalid_code", new Timestamp(System.currentTimeMillis()), null, "invalid-intent"));

        Assertions.assertThrows(UaaException.class,
                () -> emailChangeEmailService.completeVerification("invalid_code"));
    }

    @Test
    void completeActivationWithInvalidClientId() {
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "user-001");
        codeData.put("client_id", "invalid-client");
        codeData.put("email", "new@example.com");

        when(mockExpiringCodeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        ScimUser user = new ScimUser("user-001", "user@example.com", "", "");
        user.setPrimaryEmail("user@example.com");
        when(mockScimUserProvisioning.retrieve("user-001", IdentityZoneHolder.get().getId())).thenReturn(user);

        doThrow(new NoSuchClientException("no such client")).when(mockMultitenantClientServices).loadClientByClientId("invalid-client", "uaa");
        Map<String, String> response = null;
        try {
            response = emailChangeEmailService.completeVerification("the_secret_code");
        } catch (NoSuchClientException e) {
            assertNull(response.get("redirect_url"));
        }
    }

    @Test
    void completeActivationWithNoClientId() {
        Map<String, String> response = setUpCompleteActivation("user@example.com", null, null);
        assertNull(response.get("redirect_url"));
    }

    @Test
    void completeActivationWhereWildcardsDoNotMatch() {
        Map<String, String> response = setUpCompleteActivation("user@example.com", "app", "http://blah.app.com/redirect");
        assertEquals("http://fallback.url/redirect", response.get("redirect_url"));
    }

    @Test
    void completeActivationWithNoRedirectUri() {
        Map<String, String> response = setUpCompleteActivation("user@example.com", "app", null);
        assertEquals("http://fallback.url/redirect", response.get("redirect_url"));
    }

    private Map<String, String> setUpCompleteActivation(String username, String clientId, String redirectUri) {
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "user-001");
        codeData.put("client_id", clientId);
        codeData.put("redirect_uri", redirectUri);
        codeData.put("email", "new@example.com");
        BaseClientDetails clientDetails = new BaseClientDetails("client-id", null, null, "authorization_grant", null, "http://app.com/*");
        clientDetails.addAdditionalInformation(CHANGE_EMAIL_REDIRECT_URL, "http://fallback.url/redirect");

        when(mockExpiringCodeStore.retrieveCode("the_secret_code", IdentityZoneHolder.get().getId())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        ScimUser user = new ScimUser("user-001", username, "", "");
        user.setPrimaryEmail("user@example.com");
        when(mockScimUserProvisioning.retrieve("user-001", IdentityZoneHolder.get().getId())).thenReturn(user);

        when(mockMultitenantClientServices.loadClientByClientId(clientId, "uaa")).thenReturn(clientDetails);

        Map<String, String> response = emailChangeEmailService.completeVerification("the_secret_code");

        ScimUser updatedUser = new ScimUser("user-001", "new@example.com", "", "");
        user.setPrimaryEmail("new@example.com");

        verify(mockScimUserProvisioning).update("user-001", updatedUser, IdentityZoneHolder.get().getId());
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

        when(mockScimUserProvisioning.retrieve("user-001", zoneId)).thenReturn(user);
        when(mockScimUserProvisioning.query(anyString(), eq(zoneId))).thenReturn(Collections.singletonList(new ScimUser()));
        String data = JsonUtils.writeValueAsString(codeData);
        when(mockExpiringCodeStore.generateCode(eq(data), any(Timestamp.class), eq(EMAIL.name()), anyString())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), data, EMAIL.name()));

        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", "app", "http://app.com");

        verify(mockExpiringCodeStore).generateCode(eq(JsonUtils.writeValueAsString(codeData)), any(Timestamp.class), eq(EMAIL.name()), eq(zoneId));
    }

    void beginEmailChangeInOtherZone(String zoneName) {

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

        when(mockScimUserProvisioning.retrieve("user-001", zoneId)).thenReturn(user);
        when(mockScimUserProvisioning.query(anyString(), eq(zoneId))).thenReturn(Collections.singletonList(new ScimUser()));
        String data = JsonUtils.writeValueAsString(codeData);
        when(mockExpiringCodeStore.generateCode(eq(data), any(Timestamp.class), eq(EMAIL.name()), anyString())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), data, EMAIL.name()));

        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", "app", "http://app.com");

        verify(mockExpiringCodeStore).generateCode(eq(JsonUtils.writeValueAsString(codeData)), any(Timestamp.class), eq(EMAIL.name()), eq(zoneId));

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        Mockito.verify(mockEmailService).sendMessage(
                eq("new@example.com"),
                eq(MessageType.CHANGE_EMAIL),
                eq(zoneName + " Email change verification"),
                emailBodyArgument.capture()
        );

        String emailBody = emailBodyArgument.getValue();

        assertThat(emailBody, containsString(String.format("A request has been made to change the email for %s from %s to %s", zoneName, "user@example.com", "new@example.com")));
        assertThat(emailBody, containsString("<a href=\"http://test.localhost/login/verify_email?code=the_secret_code\">Verify your email</a>"));
        assertThat(emailBody, containsString("Thank you,<br />\n    " + zoneName));
    }

}
