package org.cloudfoundry.identity.uaa.account;

import org.apache.commons.lang3.RandomStringUtils;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.login.ThymeleafAdditional;
import org.cloudfoundry.identity.uaa.login.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.message.EmailService;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.message.MessageType;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MergedZoneBrandingInformation;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.account.EmailChangeEmailService.CHANGE_EMAIL_REDIRECT_URL;
import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.EMAIL;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.contains;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
@SpringJUnitConfig(classes = {
        ThymeleafAdditional.class,
        ThymeleafConfig.class
})
class EmailChangeEmailServiceTest {
    private EmailChangeEmailService emailChangeEmailService;
    private ScimUserProvisioning mockScimUserProvisioning;
    private ExpiringCodeStore mockExpiringCodeStore;
    private MessageService mockEmailService;
    private MultitenantClientServices mockMultitenantClientServices;
    private IdentityZoneManager mockIdentityZoneManager;

    @Autowired
    @Qualifier("mailTemplateEngine")
    private SpringTemplateEngine templateEngine;

    private IdentityZone identityZone;
    private String zoneId;
    private String zoneName;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        mockScimUserProvisioning = mock(ScimUserProvisioning.class);
        mockExpiringCodeStore = mock(ExpiringCodeStore.class);
        mockMultitenantClientServices = mock(MultitenantClientServices.class);
        mockEmailService = mock(EmailService.class);
        mockIdentityZoneManager = mock(IdentityZoneManager.class);
        emailChangeEmailService = new EmailChangeEmailService(
                templateEngine,
                mockEmailService,
                mockScimUserProvisioning,
                mockExpiringCodeStore,
                mockMultitenantClientServices,
                mockIdentityZoneManager);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setProtocol("http");
        request.setContextPath("/login");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        identityZone = new IdentityZone();
        zoneId = "zoneId-" + RandomStringUtils.random(10);
        zoneName = "zoneName-" + RandomStringUtils.random(10);
        identityZone.setId(zoneId);
        identityZone.setName(zoneName);

        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(identityZone);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(zoneId);
        when(mockIdentityZoneManager.isCurrentZoneUaa()).thenReturn(false);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void beginEmailChange() {
        ScimUser user = new ScimUser("user-001", "user-name", "test-name", "test-name");
        user.setPrimaryEmail("user@example.com");
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "user-001");
        codeData.put("client_id", "app");
        codeData.put("redirect_uri", "http://app.com");
        codeData.put("email", "new@example.com");

        when(mockScimUserProvisioning.retrieve("user-001", zoneId)).thenReturn(user);
        when(mockScimUserProvisioning.query(anyString(), eq(zoneId))).thenReturn(Collections.singletonList(new ScimUser()));
        String data = JsonUtils.writeValueAsString(codeData);
        when(mockExpiringCodeStore.generateCode(eq(data), any(Timestamp.class), eq(EMAIL.name()), anyString())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), data, EMAIL.name()));

        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", "app", "http://app.com");

        verify(mockExpiringCodeStore).generateCode(eq(JsonUtils.writeValueAsString(codeData)), any(Timestamp.class), eq(EMAIL.name()), eq(zoneId));

        verify(mockEmailService).sendMessage(
                eq("new@example.com"),
                eq(MessageType.CHANGE_EMAIL),
                eq("%s Email change verification".formatted(zoneName)),
                contains("<a href=\"http://localhost/login/verify_email?code=the_secret_code\">Verify your email</a>")
        );
    }

    @Test
    void beginEmailChangeWithUsernameConflict() {
        ScimUser user = new ScimUser("user-001", "user@example.com", "test-name", "test-name");
        user.setPrimaryEmail("user@example.com");
        when(mockScimUserProvisioning.retrieve(anyString(), anyString())).thenReturn(user);
        when(mockScimUserProvisioning.retrieveByUsernameAndOriginAndZone(
                anyString(),
                anyString(),
                eq(zoneId))
        ).thenReturn(Collections.singletonList(new ScimUser()));

        assertThatExceptionOfType(UaaException.class).isThrownBy(() -> emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", null, null));
    }

    @Test
    void beginEmailChangeWithCompanyNameConfigured() {

        emailChangeEmailService = new EmailChangeEmailService(
                templateEngine,
                mockEmailService,
                mockScimUserProvisioning,
                mockExpiringCodeStore,
                mockMultitenantClientServices,
                mockIdentityZoneManager);

        ScimUser user = new ScimUser("user-001", "user-name", "test-name", "test-name");
        user.setPrimaryEmail("user@example.com");
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "user-001");
        codeData.put("client_id", "app");
        codeData.put("redirect_uri", "http://app.com");
        codeData.put("email", "new@example.com");

        identityZone = IdentityZone.getUaa();
        zoneId = identityZone.getId();
        when(mockIdentityZoneManager.isCurrentZoneUaa()).thenReturn(true);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(identityZone.getId());

        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName("Best Company");
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setBranding(branding);

        identityZone.setConfig(config);

        when(mockScimUserProvisioning.retrieve("user-001", zoneId)).thenReturn(user);
        when(mockScimUserProvisioning.query(anyString(), eq(zoneId))).thenReturn(Collections.singletonList(new ScimUser()));
        String data = JsonUtils.writeValueAsString(codeData);
        when(mockExpiringCodeStore.generateCode(eq(data), any(Timestamp.class), eq(EMAIL.name()), anyString())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), data, EMAIL.name()));

        setIdentityZoneHolder(identityZone);

        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", "app", "http://app.com");

        verify(mockExpiringCodeStore).generateCode(eq(JsonUtils.writeValueAsString(codeData)), any(Timestamp.class), eq(EMAIL.name()), eq(zoneId));

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        verify(mockEmailService).sendMessage(
                eq("new@example.com"),
                eq(MessageType.CHANGE_EMAIL),
                eq("Best Company Email change verification"),
                emailBodyArgument.capture()
        );

        String emailBody = emailBodyArgument.getValue();

        assertThat(emailBody).contains("<a href=\"http://localhost/login/verify_email?code=the_secret_code\">Verify your email</a>")
                .contains("a Best Company account");
    }

    /**
     * @deprecated We need this because {@link MergedZoneBrandingInformation#getProductLogo} calls {@link IdentityZoneHolder#get}
     */
    @Deprecated
    private void setIdentityZoneHolder(IdentityZone identityZone) {
        IdentityZoneHolder.set(identityZone);
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
        assertThat(response)
                .containsEntry("userId", "user-001")
                .containsEntry("username", "user-name")
                .containsEntry("email", "new@example.com")
                .containsEntry("redirect_url", "http://app.com/redirect");
    }

    @Test
    void completeVerificationWhereUsernameEqualsEmail() {
        Map<String, String> response = setUpCompleteActivation("user@example.com", "app", "http://app.com/redirect");
        assertThat(response)
                .containsEntry("userId", "user-001")
                .containsEntry("username", "new@example.com")
                .containsEntry("email", "new@example.com")
                .containsEntry("redirect_url", "http://app.com/redirect");
    }

    @Test
    void completeVerificationWithInvalidCode() {
        when(mockExpiringCodeStore.retrieveCode("invalid_code", zoneId)).thenReturn(null);

        assertThatExceptionOfType(UaaException.class).isThrownBy(() -> emailChangeEmailService.completeVerification("invalid_code"));
    }

    @Test
    void completeVerificationWithInvalidIntent() {
        when(mockExpiringCodeStore.retrieveCode("invalid_code", zoneId)).thenReturn(new ExpiringCode("invalid_code", new Timestamp(System.currentTimeMillis()), null, "invalid-intent"));

        assertThatExceptionOfType(UaaException.class).isThrownBy(() -> emailChangeEmailService.completeVerification("invalid_code"));
    }

    @Test
    void completeActivationWithInvalidClientId() {
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "user-001");
        codeData.put("client_id", "invalid-client");
        codeData.put("email", "new@example.com");

        when(mockExpiringCodeStore.retrieveCode("the_secret_code", zoneId)).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        ScimUser user = new ScimUser("user-001", "user@example.com", "", "");
        user.setPrimaryEmail("user@example.com");
        when(mockScimUserProvisioning.retrieve("user-001", zoneId)).thenReturn(user);

        doThrow(new NoSuchClientException("no such client")).when(mockMultitenantClientServices).loadClientByClientId("invalid-client", zoneId);
        Map<String, String> response = null;
        try {
            response = emailChangeEmailService.completeVerification("the_secret_code");
        } catch (NoSuchClientException e) {
            assertThat(response).doesNotContainKey("redirect_url");
        }
    }

    @Test
    void completeActivationWithNoClientId() {
        Map<String, String> response = setUpCompleteActivation("user@example.com", null, null);
        assertThat(response).doesNotContainValue("redirect_url");
    }

    @Test
    void completeActivationWhereWildcardsDoNotMatch() {
        Map<String, String> response = setUpCompleteActivation("user@example.com", "app", "http://blah.app.com/redirect");
        assertThat(response).containsEntry("redirect_url", "http://fallback.url/redirect");
    }

    @Test
    void completeActivationWithNoRedirectUri() {
        Map<String, String> response = setUpCompleteActivation("user@example.com", "app", null);
        assertThat(response).containsEntry("redirect_url", "http://fallback.url/redirect");
    }

    private Map<String, String> setUpCompleteActivation(String username, String clientId, String redirectUri) {
        Map<String, String> codeData = new HashMap<>();
        codeData.put("user_id", "user-001");
        codeData.put("client_id", clientId);
        codeData.put("redirect_uri", redirectUri);
        codeData.put("email", "new@example.com");
        UaaClientDetails clientDetails = new UaaClientDetails("client-id", null, null, "authorization_grant", null, "http://app.com/*");
        clientDetails.addAdditionalInformation(CHANGE_EMAIL_REDIRECT_URL, "http://fallback.url/redirect");

        when(mockExpiringCodeStore.retrieveCode("the_secret_code", zoneId)).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), JsonUtils.writeValueAsString(codeData), null));
        ScimUser user = new ScimUser("user-001", username, "", "");
        user.setPrimaryEmail("user@example.com");
        when(mockScimUserProvisioning.retrieve("user-001", zoneId)).thenReturn(user);

        when(mockMultitenantClientServices.loadClientByClientId(clientId, zoneId)).thenReturn(clientDetails);

        Map<String, String> response = emailChangeEmailService.completeVerification("the_secret_code");

        ScimUser updatedUser = new ScimUser("user-001", "new@example.com", "", "");
        user.setPrimaryEmail("new@example.com");

        verify(mockScimUserProvisioning).update("user-001", updatedUser, zoneId);
        return response;
    }

    void beginEmailChangeInOtherZone(String zoneName) {

        identityZone.setName(zoneName);

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

        when(mockScimUserProvisioning.retrieve("user-001", zoneId)).thenReturn(user);
        when(mockScimUserProvisioning.query(anyString(), eq(zoneId))).thenReturn(Collections.singletonList(new ScimUser()));
        String data = JsonUtils.writeValueAsString(codeData);
        when(mockExpiringCodeStore.generateCode(eq(data), any(Timestamp.class), eq(EMAIL.name()), anyString())).thenReturn(new ExpiringCode("the_secret_code", new Timestamp(System.currentTimeMillis()), data, EMAIL.name()));

        emailChangeEmailService.beginEmailChange("user-001", "user@example.com", "new@example.com", "app", "http://app.com");

        verify(mockExpiringCodeStore).generateCode(eq(JsonUtils.writeValueAsString(codeData)), any(Timestamp.class), eq(EMAIL.name()), eq(zoneId));

        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        verify(mockEmailService).sendMessage(
                eq("new@example.com"),
                eq(MessageType.CHANGE_EMAIL),
                eq(zoneName + " Email change verification"),
                emailBodyArgument.capture()
        );

        String emailBody = emailBodyArgument.getValue();

        assertThat(emailBody).contains("A request has been made to change the email for %s from %s to %s".formatted(zoneName, "user@example.com", "new@example.com"))
                .contains("<a href=\"http://test.localhost/login/verify_email?code=the_secret_code\">Verify your email</a>")
                .contains("Thank you,<br />\n    " + zoneName);
    }
}
