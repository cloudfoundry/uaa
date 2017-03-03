package org.cloudfoundry.identity.uaa.login;

import java.sql.Timestamp;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.account.AccountCreationService;
import org.cloudfoundry.identity.uaa.account.EmailAccountCreationService;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCode;
import org.cloudfoundry.identity.uaa.codestore.ExpiringCodeStore;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.error.UaaException;
import org.cloudfoundry.identity.uaa.login.test.ThymeleafConfig;
import org.cloudfoundry.identity.uaa.message.MessageService;
import org.cloudfoundry.identity.uaa.message.MessageType;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.*;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.thymeleaf.spring4.SpringTemplateEngine;

import static org.cloudfoundry.identity.uaa.codestore.ExpiringCodeType.REGISTRATION;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.anyInt;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpStatus.BAD_REQUEST;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration(classes = ThymeleafConfig.class)
public class EmailAccountCreationServiceTests {

    private EmailAccountCreationService emailAccountCreationService;
    private MessageService messageService;
    private ExpiringCodeStore codeStore;
    private ScimUserProvisioning scimUserProvisioning;
    private ClientDetailsService clientDetailsService;
    private ScimUser user = null;
    private ExpiringCode code = null;
    private ClientDetails details = null;
    private PasswordValidator passwordValidator;

    @Autowired
    @Qualifier("mailTemplateEngine")
    SpringTemplateEngine templateEngine;

    @Rule
    public ExpectedException expectedEx = ExpectedException.none();

    @Before
    public void setUp() throws Exception {
        SecurityContextHolder.clearContext();
        messageService = mock(MessageService.class);
        codeStore = mock(ExpiringCodeStore.class);
        scimUserProvisioning = mock(ScimUserProvisioning.class);
        clientDetailsService = mock(ClientDetailsService.class);
        details = mock(ClientDetails.class);
        passwordValidator = mock(PasswordValidator.class);
        emailAccountCreationService = initEmailAccountCreationService();

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("uaa.example.com");
        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);
    }

    private EmailAccountCreationService initEmailAccountCreationService() {
        return new EmailAccountCreationService(templateEngine, messageService, codeStore,
            scimUserProvisioning, clientDetailsService, passwordValidator);
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    public void testBeginActivation() throws Exception {
        String redirectUri = "";
        String data = setUpForSuccess(redirectUri);
        when(scimUserProvisioning.createUser(any(ScimUser.class), anyString())).thenReturn(user);
        when(codeStore.generateCode(eq(data), any(Timestamp.class), eq(REGISTRATION.name()))).thenReturn(code);

        emailAccountCreationService.beginActivation("user@example.com", "password", "login", redirectUri);

        String emailBody = captorEmailBody("Activate your account");

        assertThat(emailBody, containsString("an account"));
        assertThat(emailBody, containsString("<a href=\"http://uaa.example.com/verify_user?code=the_secret_code\">Activate your account</a>"));
    }

    @Test
    public void testBeginActivationInOtherZone() throws Exception {
        String redirectUri = "http://login.example.com/redirect/";
        String data = setUpForSuccess(redirectUri);

        IdentityZone zone = MultitenancyFixture.identityZone("test-zone-id", "test");
        IdentityZoneHolder.set(zone);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setScheme("http");
        request.setServerName("test.uaa.example.com");
        ServletRequestAttributes attrs = new ServletRequestAttributes(request);
        RequestContextHolder.setRequestAttributes(attrs);

        when(scimUserProvisioning.createUser(any(ScimUser.class), anyString())).thenReturn(user);
        when(codeStore.generateCode(eq(data), any(Timestamp.class), eq(REGISTRATION.name()))).thenReturn(code);
        emailAccountCreationService.beginActivation("user@example.com", "password", "login", redirectUri);

        String emailBody = captorEmailBody("Activate your account");
        assertThat(emailBody, containsString("A request has been made to activate an account for:"));
        assertThat(emailBody, containsString("<a href=\"http://test.uaa.example.com/verify_user?code=the_secret_code\">Activate your account</a>"));
        assertThat(emailBody, containsString("Thank you"));
        assertThat(emailBody, containsString(zone.getName()));
        assertThat(emailBody, not(containsString("Cloud Foundry")));
    }

    @Test
    public void testBeginActivationWithCompanyNameConfigured() throws Exception {
        testBeginActivationWithCompanyNameConfigured("Best Company");
    }
    public void testBeginActivationWithCompanyNameConfigured(String companyName) throws Exception {
        IdentityZoneConfiguration defaultConfig = IdentityZoneHolder.get().getConfig();
        BrandingInformation branding = new BrandingInformation();
        branding.setCompanyName(companyName);
        IdentityZoneConfiguration config = new IdentityZoneConfiguration();
        config.setBranding(branding);
        IdentityZoneHolder.get().setConfig(config);
        try {
            emailAccountCreationService = initEmailAccountCreationService();
            String data = setUpForSuccess(null);
            when(scimUserProvisioning.createUser(any(ScimUser.class), anyString())).thenReturn(user);
            when(codeStore.generateCode(eq(data), any(Timestamp.class), eq(REGISTRATION.name()))).thenReturn(code);

            emailAccountCreationService.beginActivation("user@example.com", "password", "login", null);

            String emailBody = captorEmailBody("Activate your " + companyName + " account");

            assertThat(emailBody, containsString(companyName + " account"));
            assertThat(emailBody, containsString("<a href=\"http://uaa.example.com/verify_user?code=the_secret_code\">Activate your account</a>"));
        } finally {
            IdentityZoneHolder.get().setConfig(defaultConfig);
        }
    }

    @Test
    public void testBeginActivationWithCompanyNameConfigured_With_UTF8() throws Exception {
        String utf8String = "\u7433\u8D3A";
        testBeginActivationWithCompanyNameConfigured(utf8String);
    }

    @Test(expected = UaaException.class)
    public void testBeginActivationWithExistingUser() throws Exception {
        setUpForSuccess(null);
        user.setVerified(true);
        when(scimUserProvisioning.query(anyString())).thenReturn(Arrays.asList(new ScimUser[]{user}));
        when(scimUserProvisioning.createUser(any(ScimUser.class), anyString())).thenThrow(new ScimResourceAlreadyExistsException("duplicate"));
        emailAccountCreationService.beginActivation("user@example.com", "password", "login", null);
    }

    @Test
    public void testBeginActivationWithUnverifiedExistingUser() throws Exception {
        String data = setUpForSuccess("existing-user-id", null);
        user.setId("existing-user-id");
        user.setVerified(false);
        when(scimUserProvisioning.createUser(any(ScimUser.class), anyString())).thenThrow(new ScimResourceAlreadyExistsException("duplicate"));
        when(scimUserProvisioning.query(anyString())).thenReturn(Arrays.asList(new ScimUser[]{user}));
        when(codeStore.generateCode(eq(data), any(Timestamp.class), eq(REGISTRATION.name()))).thenReturn(code);

        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setProtocol("http");
        request.setContextPath("/login");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));

        emailAccountCreationService.beginActivation("user@example.com", "password", "login", null);

        verify(messageService).sendMessage(
                eq("user@example.com"),
                eq(MessageType.CREATE_ACCOUNT_CONFIRMATION),
                anyString(),
                anyString()
        );
    }

    @Test
    public void testCompleteActivation() throws Exception {
        setUpForSuccess("");
        when(scimUserProvisioning.createUser(any(ScimUser.class), anyString())).thenReturn(user);
        when(codeStore.retrieveCode("the_secret_code")).thenReturn(code);
        when(scimUserProvisioning.retrieve(anyString())).thenReturn(user);
        when(scimUserProvisioning.verifyUser(anyString(), anyInt())).thenReturn(user);

        ClientDetails client = mock(ClientDetails.class);
        when(clientDetailsService.loadClientByClientId(anyString())).thenReturn(client);
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
    public void completeActivation_usesAntPathMatching() throws Exception {
        setUpForSuccess("http://redirect.uri/");
        when(scimUserProvisioning.createUser(any(ScimUser.class), anyString())).thenReturn(user);
        when(codeStore.retrieveCode("the_secret_code")).thenReturn(code);
        when(scimUserProvisioning.retrieve(anyString())).thenReturn(user);
        when(scimUserProvisioning.verifyUser(anyString(), anyInt())).thenReturn(user);

        ClientDetails client = mock(ClientDetails.class);
        when(clientDetailsService.loadClientByClientId(anyString())).thenReturn(client);
        when(client.getRegisteredRedirectUri()).thenReturn(Collections.singleton("http://redirect.uri/*"));

        AccountCreationService.AccountCreationResponse accountCreation = emailAccountCreationService.completeActivation("the_secret_code");
        assertThat(accountCreation.getRedirectLocation(), equalTo("http://redirect.uri/"));
    }

    @Test
    public void completeActivitionWithClientNotFound() throws Exception {
        setUpForSuccess("");

        when(codeStore.retrieveCode("the_secret_code")).thenReturn(code);
        when(scimUserProvisioning.verifyUser(anyString(), anyInt())).thenReturn(user);
        when(scimUserProvisioning.retrieve(anyString())).thenReturn(user);
        doThrow(new NoSuchClientException("Client not found")).when(clientDetailsService).loadClientByClientId(anyString());

        AccountCreationService.AccountCreationResponse accountCreation = emailAccountCreationService.completeActivation("the_secret_code");
        assertEquals("home", accountCreation.getRedirectLocation());
    }

    @Test
    public void completeActivationWithInvalidClientRedirect() throws Exception {
        setUpForSuccess("http://redirect_not_found.example.com/");
        when(scimUserProvisioning.createUser(any(ScimUser.class), anyString())).thenReturn(user);
        when(codeStore.retrieveCode("the_secret_code")).thenReturn(code);
        when(scimUserProvisioning.verifyUser(anyString(), anyInt())).thenReturn(user);
        when(scimUserProvisioning.retrieve(anyString())).thenReturn(user);
        when(clientDetailsService.loadClientByClientId(anyString())).thenReturn(details);

        AccountCreationService.AccountCreationResponse accountCreation = emailAccountCreationService.completeActivation("the_secret_code");

        assertEquals("user@example.com", accountCreation.getUsername());
        assertEquals("newly-created-user-id", accountCreation.getUserId());
        assertEquals("home", accountCreation.getRedirectLocation());
    }

    @Test
    public void completeActivationWithValidClientRedirect() throws Exception {
        setUpForSuccess("http://example.com/redirect");
        when(scimUserProvisioning.createUser(any(ScimUser.class), anyString())).thenReturn(user);
        when(codeStore.retrieveCode("the_secret_code")).thenReturn(code);
        when(scimUserProvisioning.verifyUser(anyString(), anyInt())).thenReturn(user);
        when(scimUserProvisioning.retrieve(anyString())).thenReturn(user);
        when(clientDetailsService.loadClientByClientId(anyString())).thenReturn(details);

        AccountCreationService.AccountCreationResponse accountCreation = emailAccountCreationService.completeActivation("the_secret_code");

        assertEquals("http://example.com/redirect", accountCreation.getRedirectLocation());
    }

    @Test
    public void testCompleteActivationWithExpiredCode() throws Exception {
        when(codeStore.retrieveCode("expiring_code")).thenReturn(null);
        try {
            emailAccountCreationService.completeActivation("expiring_code");
            fail();
        } catch (HttpClientErrorException e) {
            assertThat(e.getStatusCode(), equalTo(BAD_REQUEST));
        }
    }

    @Test(expected = InvalidPasswordException.class)
    public void beginActivation_throwsException_ifPasswordViolatesPolicy() throws Exception {
        doThrow(new InvalidPasswordException("Oh hell no")).when(passwordValidator).validate(anyString());

        emailAccountCreationService.beginActivation("user@example.com", "some password", null, null);
        verify(passwordValidator).validate("some password");
    }

    @Test
    public void nonMatchingCodeTypeDisallowsActivation() throws Exception {
        expectedEx.expect(HttpClientErrorException.class);
        expectedEx.expectMessage("400 BAD_REQUEST");

        Timestamp ts = new Timestamp(System.currentTimeMillis() + (60 * 60 * 1000));
        Map<String, Object> data = new HashMap<>();
        data.put("user_id", "user-id");
        data.put("email", "user@example.com");
        data.put("client_id", "login");

        code = new ExpiringCode("the_secret_code", ts, JsonUtils.writeValueAsString(data), "incorrect-intent-type");

        when(codeStore.retrieveCode("the_secret_code")).thenReturn(code);

        emailAccountCreationService.completeActivation("the_secret_code");
    }

    private String setUpForSuccess(String redirectUri) throws Exception {
        return setUpForSuccess("newly-created-user-id", redirectUri);
    }
    private String setUpForSuccess(String userId, String redirectUri) throws Exception {
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

        when(details.getClientId()).thenReturn("login");
        when(details.getRegisteredRedirectUri()).thenReturn(Collections.singleton("http://example.com/*"));
        return JsonUtils.writeValueAsString(data);
    }

    private String captorEmailBody(String subject) {
        ArgumentCaptor<String> emailBodyArgument = ArgumentCaptor.forClass(String.class);
        verify(messageService).sendMessage(
            eq("user@example.com"),
            eq(MessageType.CREATE_ACCOUNT_CONFIRMATION),
            eq(subject),
            emailBodyArgument.capture()
        );
        return emailBodyArgument.getValue();
    }
}
