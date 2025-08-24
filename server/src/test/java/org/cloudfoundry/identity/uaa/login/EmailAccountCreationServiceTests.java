package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.account.AccountCreationService;
import org.cloudfoundry.identity.uaa.account.EmailAccountCreationService;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.message.MessageType;
import org.cloudfoundry.identity.uaa.oauth.common.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.oauth.provider.ClientDetails;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.junit.jupiter.SpringJUnitConfig;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.thymeleaf.spring6.SpringTemplateEngine;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;
import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.REGISTRATION;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.anyString;
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
class EmailAccountCreationServiceTests {

    private EmailAccountCreationService emailAccountCreationService;
    private MessageService mockMessageService;
    private ExpiringCodeStore mockCodeStore;
    private ScimUserProvisioning mockScimUserProvisioning;
    private MultitenantClientServices mockClientDetailsService;
    private ClientDetails mockClientDetails;
    private PasswordValidator mockPasswordValidator;
    private IdentityZoneManager mockIdentityZoneManager;
    private ScimUser user;
    private ExpiringCode code;
    private String currentIdentityZoneId;
    private RandomValueStringGenerator randomValueStringGenerator;

    @Autowired
    @Qualifier("mailTemplateEngine")
    SpringTemplateEngine templateEngine;

    @BeforeEach
    void setUp() {
        SecurityContextHolder.clearContext();
        mockMessageService = mock(MessageService.class);
        mockCodeStore = mock(ExpiringCodeStore.class);
        mockScimUserProvisioning = mock(ScimUserProvisioning.class);
        mockClientDetailsService = mock(MultitenantClientServices.class);
        mockClientDetails = mock(ClientDetails.class);
        mockPasswordValidator = mock(PasswordValidator.class);
        mockIdentityZoneManager = mock(IdentityZoneManager.class);
        emailAccountCreationService = initEmailAccountCreationService();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("uaa.example.com");
        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);

        randomValueStringGenerator = new RandomValueStringGenerator();
        currentIdentityZoneId = "zoneId" + randomValueStringGenerator.generate();

        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(currentIdentityZoneId);
    }

    private EmailAccountCreationService initEmailAccountCreationService() {
        return new EmailAccountCreationService(
                templateEngine,
                mockMessageService,
                mockCodeStore,
                mockScimUserProvisioning,
                mockClientDetailsService,
                mockPasswordValidator,
                mockIdentityZoneManager
        );
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void beginActivation() {
        String redirectUri = "";
        String data = setUpForSuccess(redirectUri);

        String zoneId = "BeginActivationZone";
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(zoneId);
        IdentityZone mockIdentityZone = mock(IdentityZone.class);
        when(mockIdentityZone.getName()).thenReturn("something");
        when(mockIdentityZone.getSubdomain()).thenReturn("uaa");
        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(mockIdentityZone);

        when(mockScimUserProvisioning.createUser(any(ScimUser.class), anyString(), eq(zoneId))).thenReturn(user);
        when(mockCodeStore.generateCode(eq(data), any(Timestamp.class), eq(REGISTRATION.name()), anyString())).thenReturn(code);

        emailAccountCreationService.beginActivation("user@example.com", "password", "login", redirectUri);

        String emailBody = captorEmailBody("Activate your account");

        assertThat(emailBody).contains("an account")
                .contains("<a href=\"http://uaa.example.com/verify_user?code=the_secret_code\">Activate your account</a>");
        verify(mockIdentityZoneManager).getCurrentIdentityZone();
    }

    @Test
    void beginActivationInOtherZone() {
        String redirectUri = "http://login.example.com/redirect/";
        String data = setUpForSuccess(redirectUri);

        IdentityZone mockIdentityZone = mock(IdentityZone.class);
        final String zoneName = "zoneName" + randomValueStringGenerator.generate();
        when(mockIdentityZone.isUaa()).thenReturn(false);
        when(mockIdentityZone.getName()).thenReturn(zoneName);
        when(mockIdentityZone.getSubdomain()).thenReturn("test");
        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(mockIdentityZone);
        when(mockIdentityZoneManager.isCurrentZoneUaa()).thenReturn(false);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("test.uaa.example.com");
        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);

        when(mockScimUserProvisioning.createUser(any(ScimUser.class), anyString(), eq(currentIdentityZoneId))).thenReturn(user);
        when(mockCodeStore.generateCode(eq(data), any(Timestamp.class), eq(REGISTRATION.name()), eq(currentIdentityZoneId))).thenReturn(code);

        emailAccountCreationService.beginActivation("user@example.com", "password", "login", redirectUri);

        String emailBody = captorEmailBody("Activate your account");
        assertThat(emailBody).contains("A request has been made to activate an account for:")
                .contains("<a href=\"http://test.uaa.example.com/verify_user?code=the_secret_code\">Activate your account</a>")
                .contains("Thank you,<br />\n    " + zoneName)
                .doesNotContain("Cloud Foundry");
    }

    @Test
    void beginActivationWithCompanyNameConfigured() {
        beginActivationWithCompanyNameConfigured("Best Company");
    }

    @Test
    void beginActivationWithCompanyNameConfigured_With_UTF8() {
        String utf8String = "琳贺";
        beginActivationWithCompanyNameConfigured(utf8String);
    }

    @Test
    void beginActivationWithExistingUser() {
        setUpForSuccess(null);
        user.setVerified(true);
        when(mockScimUserProvisioning.retrieveByUsernameAndOriginAndZone(
                eq("user@example.com"),
                eq(OriginKeys.UAA),
                eq(currentIdentityZoneId))
        ).thenReturn(Collections.singletonList(user));
        when(mockScimUserProvisioning.createUser(any(ScimUser.class), anyString(), eq(currentIdentityZoneId))).thenThrow(new ScimResourceAlreadyExistsException("duplicate"));

        assertThatExceptionOfType(UaaException.class).isThrownBy(() -> emailAccountCreationService.beginActivation("user@example.com", "password", "login", null));
    }

    @Test
    void beginActivationWithUnverifiedExistingUser() {
        String data = setUpForSuccess("existing-user-id", null);
        user.setId("existing-user-id");
        user.setVerified(false);
        when(mockScimUserProvisioning.createUser(any(ScimUser.class), anyString(), eq(currentIdentityZoneId))).thenThrow(new ScimResourceAlreadyExistsException("duplicate"));
        when(mockScimUserProvisioning.retrieveByUsernameAndOriginAndZone(
                eq("user@example.com"),
                eq(OriginKeys.UAA),
                eq(currentIdentityZoneId))
        ).thenReturn(Collections.singletonList(user));
        when(mockCodeStore.generateCode(eq(data), any(Timestamp.class), eq(REGISTRATION.name()), anyString())).thenReturn(code);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setProtocol("http");
        request.setContextPath("/login");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        IdentityZone mockIdentityZone = mock(IdentityZone.class);
        when(mockIdentityZone.getName()).thenReturn("something");
        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(mockIdentityZone);

        emailAccountCreationService.beginActivation("user@example.com", "password", "login", null);

        verify(mockMessageService).sendMessage(
                eq("user@example.com"),
                eq(MessageType.CREATE_ACCOUNT_CONFIRMATION),
                anyString(),
                anyString()
        );
    }

    @Test
    void completeActivation() {
        setUpForSuccess("");
        when(mockScimUserProvisioning.createUser(any(ScimUser.class), anyString(), eq(currentIdentityZoneId))).thenReturn(user);
        when(mockCodeStore.retrieveCode("the_secret_code", currentIdentityZoneId)).thenReturn(code);
        when(mockScimUserProvisioning.retrieve(anyString(), eq(currentIdentityZoneId))).thenReturn(user);
        when(mockScimUserProvisioning.verifyUser(anyString(), anyInt(), eq(currentIdentityZoneId))).thenReturn(user);

        ClientDetails client = mock(ClientDetails.class);
        when(mockClientDetailsService.loadClientByClientId(anyString(), anyString())).thenReturn(client);
        when(client.getRegisteredRedirectUri()).thenReturn(Collections.emptySet());
        Map<String, Object> map = new HashMap<>();
        map.put(EmailAccountCreationService.SIGNUP_REDIRECT_URL, "http://fallback.url/redirect");
        when(client.getAdditionalInformation()).thenReturn(map);

        AccountCreationService.AccountCreationResponse accountCreation = emailAccountCreationService.completeActivation("the_secret_code");

        assertThat(accountCreation.getUsername()).isEqualTo("user@example.com");
        assertThat(accountCreation.getUserId()).isEqualTo("newly-created-user-id");

        assertThat(accountCreation.getUserId()).isNotNull();
    }

    @Test
    void completeActivation_usesAntPathMatching() {
        setUpForSuccess("http://redirect.uri/");
        when(mockScimUserProvisioning.createUser(any(ScimUser.class), anyString(), eq(currentIdentityZoneId))).thenReturn(user);
        when(mockCodeStore.retrieveCode("the_secret_code", currentIdentityZoneId)).thenReturn(code);
        when(mockScimUserProvisioning.retrieve(anyString(), eq(currentIdentityZoneId))).thenReturn(user);
        when(mockScimUserProvisioning.verifyUser(anyString(), anyInt(), eq(currentIdentityZoneId))).thenReturn(user);

        ClientDetails client = mock(ClientDetails.class);
        when(mockClientDetailsService.loadClientByClientId(anyString(), eq(currentIdentityZoneId))).thenReturn(client);
        when(client.getRegisteredRedirectUri()).thenReturn(Collections.singleton("http://redirect.uri/*"));

        AccountCreationService.AccountCreationResponse accountCreation = emailAccountCreationService.completeActivation("the_secret_code");
        assertThat(accountCreation.getRedirectLocation()).isEqualTo("http://redirect.uri/");
    }

    @Test
    void completeActivitionWithClientNotFound() {
        setUpForSuccess("");

        when(mockCodeStore.retrieveCode("the_secret_code", currentIdentityZoneId)).thenReturn(code);
        when(mockScimUserProvisioning.verifyUser(anyString(), anyInt(), eq(currentIdentityZoneId))).thenReturn(user);
        when(mockScimUserProvisioning.retrieve(anyString(), eq(currentIdentityZoneId))).thenReturn(user);
        doThrow(new NoSuchClientException("Client not found")).when(mockClientDetailsService).loadClientByClientId(anyString(), anyString());

        AccountCreationService.AccountCreationResponse accountCreation = emailAccountCreationService.completeActivation("the_secret_code");
        assertThat(accountCreation.getRedirectLocation()).isEqualTo("home");
    }

    @Test
    void completeActivationWithInvalidClientRedirect() {
        setUpForSuccess("http://redirect_not_found.example.com/");
        when(mockScimUserProvisioning.createUser(any(ScimUser.class), anyString(), eq(currentIdentityZoneId))).thenReturn(user);
        when(mockCodeStore.retrieveCode("the_secret_code", currentIdentityZoneId)).thenReturn(code);
        when(mockScimUserProvisioning.verifyUser(anyString(), anyInt(), eq(currentIdentityZoneId))).thenReturn(user);
        when(mockScimUserProvisioning.retrieve(anyString(), eq(currentIdentityZoneId))).thenReturn(user);
        when(mockClientDetailsService.loadClientByClientId(anyString(), anyString())).thenReturn(mockClientDetails);

        AccountCreationService.AccountCreationResponse accountCreation = emailAccountCreationService.completeActivation("the_secret_code");

        assertThat(accountCreation.getUsername()).isEqualTo("user@example.com");
        assertThat(accountCreation.getUserId()).isEqualTo("newly-created-user-id");
        assertThat(accountCreation.getRedirectLocation()).isEqualTo("home");
    }

    @Test
    void completeActivationWithValidClientRedirect() {
        setUpForSuccess("http://example.com/redirect");
        when(mockScimUserProvisioning.createUser(any(ScimUser.class), anyString(), eq(currentIdentityZoneId))).thenReturn(user);
        when(mockCodeStore.retrieveCode("the_secret_code", currentIdentityZoneId)).thenReturn(code);
        when(mockScimUserProvisioning.verifyUser(anyString(), anyInt(), eq(currentIdentityZoneId))).thenReturn(user);
        when(mockScimUserProvisioning.retrieve(anyString(), eq(currentIdentityZoneId))).thenReturn(user);
        when(mockClientDetailsService.loadClientByClientId(anyString(), anyString())).thenReturn(mockClientDetails);

        AccountCreationService.AccountCreationResponse accountCreation = emailAccountCreationService.completeActivation("the_secret_code");

        assertThat(accountCreation.getRedirectLocation()).isEqualTo("http://example.com/redirect");
    }

    @Test
    void completeActivationWithExpiredCode() {
        when(mockCodeStore.retrieveCode(eq("expiring_code"), anyString())).thenReturn(null);

        assertThatThrownBy(() -> emailAccountCreationService.completeActivation("expiring_code"))
                .isInstanceOf(HttpClientErrorException.class)
                .satisfies(e -> assertThat(((HttpClientErrorException) e).getStatusCode()).isEqualTo(HttpStatus.BAD_REQUEST));
    }

    @Test
    void beginActivation_throwsException_ifPasswordViolatesPolicy() {
        doThrow(new InvalidPasswordException("Oh hell no")).when(mockPasswordValidator).validate(anyString());

        assertThatExceptionOfType(InvalidPasswordException.class).isThrownBy(() -> emailAccountCreationService.beginActivation("user@example.com", "some password", null, null));

        verify(mockPasswordValidator).validate("some password");
    }

    @Test
    void nonMatchingCodeTypeDisallowsActivation() {
        Timestamp ts = new Timestamp(System.currentTimeMillis() + (60 * 60 * 1000));
        Map<String, Object> data = new HashMap<>();
        data.put("user_id", "user-id");
        data.put("email", "user@example.com");
        data.put("client_id", "login");

        code = new ExpiringCode("the_secret_code", ts, JsonUtils.writeValueAsString(data), "incorrect-intent-type");

        when(mockCodeStore.retrieveCode(eq("the_secret_code"), anyString())).thenReturn(code);

        assertThatThrownBy(() -> emailAccountCreationService.completeActivation("the_secret_code"))
                .isInstanceOf(HttpClientErrorException.class)
                .hasMessageContaining("400 BAD_REQUEST");
    }

    private String setUpForSuccess(String redirectUri) {
        return setUpForSuccess("newly-created-user-id", redirectUri);
    }

    private String setUpForSuccess(String userId, String redirectUri) {
        user = new ScimUser(
                userId,
                "user@example.com",
                "givenName",
                "familyName");
        user.setPrimaryEmail("user@example.com");
        user.setPassword("password");
        user.setOrigin(OriginKeys.UAA);
        user.setActive(true);
        user.setVerified(false);

        Timestamp ts = new Timestamp(System.currentTimeMillis() + (60 * 60 * 1000)); // 1 hour
        Map<String, Object> data = new HashMap<>();
        data.put("user_id", userId);
        data.put("email", "user@example.com");
        data.put("client_id", "login");
        if (redirectUri != null) {
            data.put("redirect_uri", redirectUri);
        }

        code = new ExpiringCode("the_secret_code", ts, JsonUtils.writeValueAsString(data), REGISTRATION.name());

        when(mockClientDetails.getClientId()).thenReturn("login");
        when(mockClientDetails.getRegisteredRedirectUri()).thenReturn(Collections.singleton("http://example.com/*"));
        return JsonUtils.writeValueAsString(data);
    }

    private String captorEmailBody(String subject) {
        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        verify(mockMessageService).sendMessage(
                eq("user@example.com"),
                eq(MessageType.CREATE_ACCOUNT_CONFIRMATION),
                eq(subject),
                emailBodyArgument.capture()
        );
        return emailBodyArgument.getValue();
    }

    private void beginActivationWithCompanyNameConfigured(String companyName) {

        BrandingInformation mockBrandingInformation = mock(BrandingInformation.class);
        when(mockBrandingInformation.getCompanyName()).thenReturn(companyName);

        IdentityZoneConfiguration mockIdentityZoneConfiguration = mock(IdentityZoneConfiguration.class);
        when(mockIdentityZoneConfiguration.getBranding()).thenReturn(mockBrandingInformation);

        IdentityZone mockIdentityZone = mock(IdentityZone.class);
        when(mockIdentityZone.getSubdomain()).thenReturn("uaa");
        when(mockIdentityZone.isUaa()).thenReturn(true);
        when(mockIdentityZone.getConfig()).thenReturn(mockIdentityZoneConfiguration);
        when(mockIdentityZoneManager.getCurrentIdentityZone()).thenReturn(mockIdentityZone);
        when(mockIdentityZoneManager.isCurrentZoneUaa()).thenReturn(true);
        IdentityZoneHolder.set(mockIdentityZone);

        emailAccountCreationService = initEmailAccountCreationService();
        String data = setUpForSuccess(null);
        when(mockScimUserProvisioning.createUser(any(ScimUser.class), anyString(), eq(currentIdentityZoneId))).thenReturn(user);
        when(mockCodeStore.generateCode(eq(data), any(Timestamp.class), eq(REGISTRATION.name()), eq(currentIdentityZoneId))).thenReturn(code);

        emailAccountCreationService.beginActivation("user@example.com", "password", "login", null);

        String emailBody = captorEmailBody("Activate your " + companyName + " account");

        assertThat(emailBody).contains(companyName + " account");
        assertThat(emailBody).contains("<a href=\"http://uaa.example.com/verify_user?code=the_secret_code\">Activate your account</a>");
    }

}
