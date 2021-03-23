package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.account.AccountCreationService;
import org.cloudfoundry.identity.uaa.account.EmailAccountCreationService;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.message.MessageType;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.*;
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
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.thymeleaf.spring5.SpringTemplateEngine;

import java.sql.Timestamp;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.REGISTRATION;
import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.Matchers.*;
import static org.junit.Assert.*;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

@ExtendWith(SpringExtension.class)
@ExtendWith(PollutionPreventionExtension.class)
@ContextConfiguration(classes = {
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

        assertThat(emailBody, containsString("an account"));
        assertThat(emailBody, containsString("<a href=\"http://uaa.example.com/verify_user?code=the_secret_code\">Activate your account</a>"));
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
        assertThat(emailBody, containsString("A request has been made to activate an account for:"));
        assertThat(emailBody, containsString("<a href=\"http://test.uaa.example.com/verify_user?code=the_secret_code\">Activate your account</a>"));
        assertThat(emailBody, containsString("Thank you"));
        assertThat(emailBody, containsString(zoneName));
        assertThat(emailBody, not(containsString("Cloud Foundry")));
    }

    @Test
    void beginActivationWithCompanyNameConfigured() {
        beginActivationWithCompanyNameConfigured("Best Company");
    }

    @Test
    void beginActivationWithCompanyNameConfigured_With_UTF8() {
        String utf8String = "\u7433\u8D3A";
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

        assertThrows(UaaException.class,
                () -> emailAccountCreationService.beginActivation("user@example.com", "password", "login", null));
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

        assertEquals("user@example.com", accountCreation.getUsername());
        assertEquals("newly-created-user-id", accountCreation.getUserId());

        assertNotNull(accountCreation.getUserId());
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
        assertThat(accountCreation.getRedirectLocation(), equalTo("http://redirect.uri/"));
    }

    @Test
    void completeActivitionWithClientNotFound() {
        setUpForSuccess("");

        when(mockCodeStore.retrieveCode("the_secret_code", currentIdentityZoneId)).thenReturn(code);
        when(mockScimUserProvisioning.verifyUser(anyString(), anyInt(), eq(currentIdentityZoneId))).thenReturn(user);
        when(mockScimUserProvisioning.retrieve(anyString(), eq(currentIdentityZoneId))).thenReturn(user);
        doThrow(new NoSuchClientException("Client not found")).when(mockClientDetailsService).loadClientByClientId(anyString(), anyString());

        AccountCreationService.AccountCreationResponse accountCreation = emailAccountCreationService.completeActivation("the_secret_code");
        assertEquals("home", accountCreation.getRedirectLocation());
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

        assertEquals("user@example.com", accountCreation.getUsername());
        assertEquals("newly-created-user-id", accountCreation.getUserId());
        assertEquals("home", accountCreation.getRedirectLocation());
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

        assertEquals("http://example.com/redirect", accountCreation.getRedirectLocation());
    }

    @Test
    void completeActivationWithExpiredCode() {
        when(mockCodeStore.retrieveCode(eq("expiring_code"), anyString())).thenReturn(null);

        HttpClientErrorException httpClientErrorException = assertThrows(HttpClientErrorException.class,
                () -> emailAccountCreationService.completeActivation("expiring_code"));

        assertThat(httpClientErrorException.getStatusCode(), equalTo(BAD_REQUEST));
    }

    @Test
    void beginActivation_throwsException_ifPasswordViolatesPolicy() {
        doThrow(new InvalidPasswordException("Oh hell no")).when(mockPasswordValidator).validate(anyString());

        assertThrows(InvalidPasswordException.class,
                () -> emailAccountCreationService.beginActivation("user@example.com", "some password", null, null));

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

        assertThrowsWithMessageThat(HttpClientErrorException.class,
                () -> emailAccountCreationService.completeActivation("the_secret_code"), containsString("400 BAD_REQUEST"));
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

        assertThat(emailBody, containsString(companyName + " account"));
        assertThat(emailBody, containsString("<a href=\"http://uaa.example.com/verify_user?code=the_secret_code\">Activate your account</a>"));
    }

}
