package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.mfa.JdbcUserGoogleMfaCredentialsProvisioning;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mfa.UserGoogleMfaCredentials;
import org.cloudfoundry.identity.uaa.mfa.UserGoogleMfaCredentialsProvisioning;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestClient;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.web.context.WebApplicationContext;

import java.security.Security;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createMfaProvider;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_AUTHORIZATION_CODE;
import static org.hamcrest.CoreMatchers.containsString;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.*;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@DefaultTestContext
class TotpMfaEndpointMockMvcTests {

    private String adminToken;
    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @Autowired
    private JdbcUserGoogleMfaCredentialsProvisioning jdbcUserGoogleMfaCredentialsProvisioning;
    private IdentityZoneConfiguration uaaZoneConfig;
    private MfaProvider mfaProvider;
    private MfaProvider otherMfaProvider;
    private String password;
    @SuppressWarnings("SpringJavaInjectionPointsAutowiringInspection")
    @Autowired
    private UserGoogleMfaCredentialsProvisioning userGoogleMfaCredentialsProvisioning;
    private ScimUser scimUser;
    private MockHttpSession mockHttpSession;
    private ApplicationListener<AbstractUaaEvent> applicationListener;

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private WebApplicationContext webApplicationContext;

    @BeforeAll
    static void key() {
        Security.setProperty("crypto.policy", "unlimited");
    }

    @BeforeEach
    void setup(
            @Autowired TestClient testClient,
            @Autowired ConfigurableApplicationContext configurableApplicationContext,
            @Autowired ScimUserProvisioning scimUserProvisioning
    ) throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
                "admin",
                "adminsecret",
                "clients.read clients.write clients.secret clients.admin uaa.admin"
        );

        mfaProvider = createMfaProvider(webApplicationContext, IdentityZone.getUaa());
        otherMfaProvider = createMfaProvider(webApplicationContext, IdentityZone.getUaa());

        uaaZoneConfig = MockMvcUtils.getZoneConfiguration(webApplicationContext, IdentityZone.getUaaZoneId());
        uaaZoneConfig.getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        MockMvcUtils.setZoneConfiguration(webApplicationContext, IdentityZone.getUaaZoneId(), uaaZoneConfig);

        //noinspection unchecked
        applicationListener = (ApplicationListener<AbstractUaaEvent>) mock(ApplicationListener.class);
        configurableApplicationContext.addApplicationListener(applicationListener);

        password = "sec3Tas";
        scimUser = createUser(scimUserProvisioning, password);
        mockHttpSession = new MockHttpSession();
    }

    @AfterEach
    void cleanup() {
        uaaZoneConfig.getMfaConfig().setEnabled(false).setProviderName(null);
        MockMvcUtils.setZoneConfiguration(webApplicationContext, "uaa", uaaZoneConfig);
        MockMvcUtils.removeEventListener(webApplicationContext, applicationListener);
    }

    @Test
    void testRedirectToMfaAfterLogin() throws Exception {
        redirectToMFARegistration(mockMvc, mockHttpSession, scimUser, password);

        MockHttpServletResponse response = mockMvc.perform(get("/profile")
                .session(mockHttpSession)).andReturn().getResponse();
        assertTrue(response.getRedirectedUrl().contains("/login"));
    }

    @Test
    void testRedirectToLoginPageAfterClickingBackFromMfaRegistrationPage() throws Exception {
        redirectToMFARegistration(mockMvc, mockHttpSession, scimUser, password);

        MockHttpServletResponse response = mockMvc.perform(get("/logout.do")
                .session(mockHttpSession)).andReturn().getResponse();

        assertTrue(response.getRedirectedUrl().endsWith("/login"));
    }

    @Test
    void testGoogleAuthenticatorLoginFlow() throws Exception {
        redirectToMFARegistration(mockMvc, mockHttpSession, scimUser, password);

        performGetMfaRegister(mockMvc, mockHttpSession)
                .andDo(print())
                .andExpect(view().name("mfa/qr_code"));

        assertFalse(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(scimUser.getId(), mfaProvider.getId()));

        int code = MockMvcUtils.getMFACodeFromSession(mockHttpSession);

        String location = MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, mockHttpSession);

        ArgumentCaptor<AbstractUaaEvent> eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(applicationListener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(9, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(7), instanceOf(MfaAuthenticationSuccessEvent.class));

        mockMvc.perform(get(location)
                .session(mockHttpSession))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/"));

        mockHttpSession = new MockHttpSession();
        performLoginWithSession(mockMvc, mockHttpSession, scimUser, password);
        MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, mockHttpSession);

        eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(applicationListener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(15, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(13), instanceOf(MfaAuthenticationSuccessEvent.class));
    }

    @Test
    void testLockedOutAfterExceededMfaAttempts() throws Exception {
        redirectToMFARegistration(mockMvc, mockHttpSession, scimUser, password);
        performGetMfaRegister(mockMvc, mockHttpSession)
                .andDo(print())
                .andExpect(view().name("mfa/qr_code"));

        assertFalse(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(scimUser.getId(), mfaProvider.getId()));
        int code = MockMvcUtils.getMFACodeFromSession(mockHttpSession);

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/login/mfa/verify.do")
                    .param("code", Integer.toString(-1))
                    .header("Host", "localhost")
                    .session(mockHttpSession)
                    .with(cookieCsrf()))
                    .andExpect(status().isOk());
        }


        String location = mockMvc.perform(post("/login/mfa/verify.do")
                .param("code", Integer.toString(code))
                .header("Host", "localhost")
                .session(mockHttpSession)
                .with(cookieCsrf()))
                .andExpect(status().is3xxRedirection())
                .andReturn().getResponse().getRedirectedUrl();

        assertThat(location, is(containsString("login?error=account_locked")));
    }

    @Test
    void testMFARegistrationHonorsRedirectUri() throws Exception {
        ClientDetailsModification client =
                MockMvcUtils.getClientDetailsModification(
                        "auth-client-id",
                        "secret",
                        Collections.emptyList(),
                        Collections.singletonList("openid"),
                        Collections.singletonList(GRANT_TYPE_AUTHORIZATION_CODE),
                        "uaa.resource",
                        Collections.singleton("http://example.com"));
        client.setAutoApproveScopes(Collections.singletonList("openid"));
        Map<String, String> information = new HashMap<>();
        information.put("autoapprove", "true");
        client.setAdditionalInformation(information);

        MockMvcUtils.createClient(mockMvc, adminToken, client, IdentityZone.getUaa(), status().isCreated());

        //Not using param function because params won't end up in paramsMap.
        String oauthUrl = "/oauth/authorize?client_id=auth-client-id&client_secret=secret&redirect_uri=http://example.com";
        mockMvc.perform(get(oauthUrl)
                .session(mockHttpSession)
                .with(cookieCsrf()))
                .andExpect(status().is3xxRedirection())
                .andDo(print())
                .andExpect(redirectedUrl("http://localhost/login"));

        performLoginWithSession(mockMvc, mockHttpSession, scimUser, password).andExpect(redirectedUrl("http://localhost" + oauthUrl));

        mockMvc.perform(get(oauthUrl)
                .session(mockHttpSession)
                .with(cookieCsrf()))
                .andExpect(status().is3xxRedirection())
                .andDo(print())
                .andExpect(redirectedUrl("/login/mfa/register"));

        performGetMfaRegister(mockMvc, mockHttpSession);

        int code = MockMvcUtils.getMFACodeFromSession(mockHttpSession);
        MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, mockHttpSession);

        mockMvc.perform(get("/login/mfa/completed")
                .session(mockHttpSession)
                .with(cookieCsrf()))
                .andExpect(status().is3xxRedirection())
                .andDo(print())
                .andExpect(redirectedUrl("http://localhost/oauth/authorize?client_id=auth-client-id&client_secret=secret&redirect_uri=http://example.com"));
    }

    @Test
    void testQRCodeCannotBeSubmittedWithoutLoggedInSession() throws Exception {
        mockMvc.perform(post("/login/mfa/verify.do")
                .param("code", "1234")
                .with(cookieCsrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    void testOtpValidationFails() throws Exception {
        redirectToMFARegistration(mockMvc, mockHttpSession, scimUser, password);

        assertFalse(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(scimUser.getId(), mfaProvider.getId()));

        performGetMfaManualRegister(mockMvc, mockHttpSession).andExpect((view().name("mfa/manual_registration")));

        int code = MockMvcUtils.getMFACodeFromSession(mockHttpSession);

        String location = MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, mockHttpSession);
        assertEquals("/login/mfa/completed", location);

        ArgumentCaptor<AbstractUaaEvent> eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(applicationListener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(9, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(7), instanceOf(MfaAuthenticationSuccessEvent.class));

        mockMvc.perform(get("/")
                .session(mockHttpSession))
                .andExpect(status().isOk())
                .andExpect(view().name("home"));

        mockMvc.perform(get("/logout.do")).andReturn();

        mockHttpSession = new MockHttpSession();
        performLoginWithSession(mockMvc, mockHttpSession, scimUser, password);

        mockMvc.perform(post("/login/mfa/verify.do")
                .param("code", Integer.toString(code + 1))
                .header("Host", "localhost")
                .session(mockHttpSession)
                .with(cookieCsrf()))
                .andExpect(status().is2xxSuccessful())
                .andExpect(view().name("mfa/enter_code"));

        eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(applicationListener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(15, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(13), instanceOf(MfaAuthenticationFailureEvent.class));

        mockMvc.perform(post("/login/mfa/verify.do")
                .param("code", "ABCDEF")
                .header("Host", "localhost")
                .session(mockHttpSession)
                .with(cookieCsrf()))
                .andExpect(status().is2xxSuccessful())
                .andExpect(view().name("mfa/enter_code"));

        eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(applicationListener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(17, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(15), instanceOf(MfaAuthenticationFailureEvent.class));
    }

    @Test
    void testQRCodeRedirectIfCodeValidated() throws Exception {

        redirectToMFARegistration(mockMvc, mockHttpSession, scimUser, password);

        performGetMfaRegister(mockMvc, mockHttpSession).andExpect(view().name("mfa/qr_code"));

        int code = MockMvcUtils.getMFACodeFromSession(mockHttpSession);

        MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, mockHttpSession);

        UserGoogleMfaCredentials activeCreds = jdbcUserGoogleMfaCredentialsProvisioning.retrieve(scimUser.getId(), mfaProvider.getId());
        assertNotNull(activeCreds);
        assertEquals(mfaProvider.getId(), activeCreds.getMfaProviderId());
        mockMvc.perform(get("/logout.do")).andReturn();

        mockHttpSession = new MockHttpSession();
        performLoginWithSession(mockMvc, mockHttpSession, scimUser, password);

        performGetMfaRegister(mockMvc, mockHttpSession).andExpect(redirectedUrl("/login/mfa/verify"));
    }

    @Test
    void testRegisterFlowWithMfaProviderSwitch() throws Exception {

        redirectToMFARegistration(mockMvc, mockHttpSession, scimUser, password);

        performGetMfaRegister(mockMvc, mockHttpSession).andExpect(view().name("mfa/qr_code"));

        int code = MockMvcUtils.getMFACodeFromSession(mockHttpSession);

        String location = MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, mockHttpSession);

        location = mockMvc.perform(
                get(location)
                        .session(mockHttpSession)
        )
                .andExpect(status().isFound())
                .andReturn().getResponse().getRedirectedUrl();

        mockMvc.perform(
                get(location)
                        .session(mockHttpSession)
        )
                .andExpect(status().isOk())
                .andExpect(view().name("home"));


        UserGoogleMfaCredentials activeCreds = jdbcUserGoogleMfaCredentialsProvisioning.retrieve(scimUser.getId(), mfaProvider.getId());
        assertNotNull(activeCreds);
        assertEquals(mfaProvider.getId(), activeCreds.getMfaProviderId());
        mockMvc.perform(get("/logout.do")).andReturn();

        uaaZoneConfig = MockMvcUtils.getZoneConfiguration(webApplicationContext, "uaa");
        uaaZoneConfig.getMfaConfig().setProviderName(otherMfaProvider.getName());
        MockMvcUtils.setZoneConfiguration(webApplicationContext, "uaa", uaaZoneConfig);

        mockHttpSession = new MockHttpSession();
        performLoginWithSession(mockMvc, mockHttpSession, scimUser, password);

        performGetMfaRegister(mockMvc, mockHttpSession).andExpect(view().name("mfa/qr_code"));

        code = MockMvcUtils.getMFACodeFromSession(mockHttpSession);

        location = MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, mockHttpSession);

        location = mockMvc.perform(
                get(location)
                        .session(mockHttpSession)
        )
                .andExpect(status().isFound())
                .andReturn().getResponse().getRedirectedUrl();

        mockMvc.perform(
                get(location)
                        .session(mockHttpSession)
        )
                .andExpect(status().isOk())
                .andExpect(view().name("home"));
    }

    @Test
    void testQRCodeRedirectIfCodeNotValidated() throws Exception {
        redirectToMFARegistration(mockMvc, mockHttpSession, scimUser, password);

        performGetMfaRegister(mockMvc, mockHttpSession).andExpect(view().name("mfa/qr_code"));

        UserGoogleMfaCredentials inActiveCreds = (UserGoogleMfaCredentials) mockHttpSession.getAttribute("uaaMfaCredentials");
        assertNotNull(inActiveCreds);

        performGetMfaRegister(mockMvc, mockHttpSession).andExpect(view().name("mfa/qr_code"));
    }

    @Test
    void testManualRegistrationFlow() throws Exception {
        redirectToMFARegistration(mockMvc, mockHttpSession, scimUser, password);

        assertFalse(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(scimUser.getId(), mfaProvider.getId()));

        performGetMfaManualRegister(mockMvc, mockHttpSession).andExpect((view().name("mfa/manual_registration")));

        int code = MockMvcUtils.getMFACodeFromSession(mockHttpSession);

        String location = MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, mockHttpSession);
        assertEquals("/login/mfa/completed", location);

        ArgumentCaptor<AbstractUaaEvent> eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(applicationListener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(9, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(7), instanceOf(MfaAuthenticationSuccessEvent.class));

        mockMvc.perform(get("/")
                .session(mockHttpSession))
                .andExpect(status().isOk())
                .andExpect(view().name("home"));

        mockMvc.perform(get("/logout.do")).andReturn();

        mockHttpSession = new MockHttpSession();
        performLoginWithSession(mockMvc, mockHttpSession, scimUser, password);
        MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, mockHttpSession);

        eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(applicationListener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(16, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(14), instanceOf(MfaAuthenticationSuccessEvent.class));
    }

    @Test
    void testQRDoesNotChangeDuringOneSession() throws Exception {
        redirectToMFARegistration(mockMvc, mockHttpSession, scimUser, password);
        assertFalse(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(scimUser.getId(), mfaProvider.getId()));

        MvcResult res = performGetMfaRegister(mockMvc, mockHttpSession).andExpect(view().name("mfa/qr_code")).andReturn();
        String qrUrl = (String) res.getModelAndView().getModel().get("qrurl");

        performGetMfaRegister(mockMvc, mockHttpSession)
                .andExpect(view().name("mfa/qr_code"))
                .andExpect(model().attribute("qrurl", qrUrl));
    }

    private static ScimUser createUser(ScimUserProvisioning scimUserProvisioning, String password) {
        ScimUser user = new ScimUser(null, new RandomValueStringGenerator(5).generate(), "first", "last");

        user.setPrimaryEmail(user.getUserName());
        user.setPassword(password);
        user = scimUserProvisioning.createUser(user, user.getPassword(), IdentityZoneHolder.getUaaZone().getId());
        return user;
    }

    private static ResultActions performLoginWithSession(MockMvc mockMvc, MockHttpSession session, ScimUser user, String password) throws Exception {
        return mockMvc.perform(post("/login.do")
                .session(session)
                .param("username", user.getUserName())
                .param("password", password)
                .with(cookieCsrf()))
                .andDo(print())
                .andExpect(status().isFound());
    }

    private static ResultActions performGetMfaRegister(MockMvc mockMvc, MockHttpSession session) throws Exception {
        return mockMvc.perform(get("/login/mfa/register")
                .session(session));
    }

    private static ResultActions performGetMfaManualRegister(MockMvc mockMvc, MockHttpSession session) throws Exception {
        return mockMvc.perform(get("/login/mfa/manual")
                .session(session)
        );
    }

    private static void redirectToMFARegistration(MockMvc mockMvc, MockHttpSession session, ScimUser user, String password) throws Exception {
        String location = performLoginWithSession(mockMvc, session, user, password).andReturn().getResponse().getHeader("Location");
        mockMvc.perform(get(location)
                .session(session))
                .andExpect(redirectedUrl("/login/mfa/register"));
    }
}
