/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.TestSpringContext;
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
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationListener;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.GenericWebApplicationContext;

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

@RunWith(SpringJUnit4ClassRunner.class)
@ActiveProfiles("default")
@WebAppConfiguration
@ContextConfiguration(classes = TestSpringContext.class)
public class TotpMfaEndpointMockMvcTests {

    private String adminToken;
    private JdbcUserGoogleMfaCredentialsProvisioning jdbcUserGoogleMfaCredentialsProvisioning;
    private IdentityZoneConfiguration uaaZoneConfig;
    private MfaProvider mfaProvider;
    private MfaProvider otherMfaProvider;
    private String password;
    private UserGoogleMfaCredentialsProvisioning userGoogleMfaCredentialsProvisioning;
    private ScimUser user;
    private MockHttpSession session;
    private ApplicationListener listener;

    @Autowired
    public GenericWebApplicationContext webApplicationContext;
    private MockMvc mockMvc;
    private TestClient testClient;

    @BeforeClass
    public static void key() {
        Security.setProperty("crypto.policy", "unlimited");
    }

    @Before
    public void setup() throws Exception {
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
                .addFilter(springSecurityFilterChain)
                .build();

        testClient = new TestClient(mockMvc);
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
          "admin",
          "adminsecret",
          "clients.read clients.write clients.secret clients.admin uaa.admin"
        );
        jdbcUserGoogleMfaCredentialsProvisioning = (JdbcUserGoogleMfaCredentialsProvisioning) webApplicationContext.getBean("jdbcUserGoogleMfaCredentialsProvisioning");
        userGoogleMfaCredentialsProvisioning = (UserGoogleMfaCredentialsProvisioning) webApplicationContext.getBean("userGoogleMfaCredentialsProvisioning");

        mfaProvider = createMfaProvider(webApplicationContext, IdentityZone.getUaa());
        otherMfaProvider = createMfaProvider(webApplicationContext, IdentityZone.getUaa());


        uaaZoneConfig = MockMvcUtils.getZoneConfiguration(webApplicationContext, IdentityZone.getUaa().getId());
        uaaZoneConfig.getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        MockMvcUtils.setZoneConfiguration(webApplicationContext, IdentityZone.getUaa().getId(), uaaZoneConfig);

        listener = mock(ApplicationListener.class);
        webApplicationContext.addApplicationListener(listener);

        user = createUser();
        session = new MockHttpSession();
    }

    @After
    public void cleanup() {
        uaaZoneConfig.getMfaConfig().setEnabled(false).setProviderName(null);
        MockMvcUtils.setZoneConfiguration(webApplicationContext, "uaa", uaaZoneConfig);
        MockMvcUtils.removeEventListener(webApplicationContext, listener);
    }

    @Test
    public void testRedirectToMfaAfterLogin() throws Exception {
        redirectToMFARegistration();

        MockHttpServletResponse response = mockMvc.perform(get("/profile")
          .session(session)).andReturn().getResponse();
        assertTrue(response.getRedirectedUrl().contains("/login"));
    }

    @Test
    public void testRedirectToLoginPageAfterClickingBackFromMfaRegistrationPage() throws Exception {
        redirectToMFARegistration();

        MockHttpServletResponse response = mockMvc.perform(get("/logout.do")
          .session(session)).andReturn().getResponse();

        assertTrue(response.getRedirectedUrl().endsWith("/login"));
    }

    @Test
    public void testGoogleAuthenticatorLoginFlow() throws Exception {
        redirectToMFARegistration();

        performGetMfaRegister()
          .andDo(print())
          .andExpect(view().name("mfa/qr_code"));

        assertFalse(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(user.getId(), mfaProvider.getId()));

        int code = MockMvcUtils.getMFACodeFromSession(session);

        String location = MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, session);

        ArgumentCaptor<AbstractUaaEvent> eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(8, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(6), instanceOf(MfaAuthenticationSuccessEvent.class));

        mockMvc.perform(get(location)
          .session(session))
          .andExpect(status().isFound())
          .andExpect(redirectedUrl("http://localhost/"));

        session = new MockHttpSession();
        performLoginWithSession();
        MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, session);

        eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(14, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(12), instanceOf(MfaAuthenticationSuccessEvent.class));
    }

    @Test
    public void testLockedOutAfterExceededMfaAttempts() throws Exception {
        redirectToMFARegistration();
        performGetMfaRegister()
          .andDo(print())
          .andExpect(view().name("mfa/qr_code"));

        assertFalse(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(user.getId(), mfaProvider.getId()));
        int code = MockMvcUtils.getMFACodeFromSession(session);

        for (int i = 0; i < 5; i++) {
            mockMvc.perform(post("/login/mfa/verify.do")
              .param("code", Integer.toString(-1))
              .header("Host", "localhost")
              .session(session)
              .with(cookieCsrf()))
              .andExpect(status().isOk());
        }


        String location = mockMvc.perform(post("/login/mfa/verify.do")
          .param("code", Integer.toString(code))
          .header("Host", "localhost")
          .session(session)
          .with(cookieCsrf()))
          .andExpect(status().is3xxRedirection())
          .andReturn().getResponse().getRedirectedUrl();

        assertThat(location, is(containsString("login?error=account_locked")));
    }


    @Test
    public void testMFARegistrationHonorsRedirectUri() throws Exception {
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
          .session(session)
          .with(cookieCsrf()))
          .andExpect(status().is3xxRedirection())
          .andDo(print())
          .andExpect(redirectedUrl("http://localhost/login"));

        performLoginWithSession().andExpect(redirectedUrl("http://localhost" + oauthUrl));

        mockMvc.perform(get(oauthUrl)
          .session(session)
          .with(cookieCsrf()))
          .andExpect(status().is3xxRedirection())
          .andDo(print())
          .andExpect(redirectedUrl("/login/mfa/register"));

        performGetMfaRegister();

        int code = MockMvcUtils.getMFACodeFromSession(session);
        MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, session);

        mockMvc.perform(get("/login/mfa/completed")
          .session(session)
          .with(cookieCsrf()))
          .andExpect(status().is3xxRedirection())
          .andDo(print())
          .andExpect(redirectedUrl("http://localhost/oauth/authorize?client_id=auth-client-id&client_secret=secret&redirect_uri=http://example.com"));
    }

    @Test
    public void testQRCodeCannotBeSubmittedWithoutLoggedInSession() throws Exception {
        mockMvc.perform(post("/login/mfa/verify.do")
          .param("code", "1234")
          .with(cookieCsrf()))
          .andExpect(status().is3xxRedirection())
          .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    public void testOtpValidationFails() throws Exception {
        redirectToMFARegistration();

        assertFalse(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(user.getId(), mfaProvider.getId()));

        performGetMfaManualRegister().andExpect((view().name("mfa/manual_registration")));

        int code = MockMvcUtils.getMFACodeFromSession(session);

        String location = MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, session);
        assertEquals("/login/mfa/completed", location);

        ArgumentCaptor<AbstractUaaEvent> eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(8, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(6), instanceOf(MfaAuthenticationSuccessEvent.class));

        mockMvc.perform(get("/")
          .session(session))
          .andExpect(status().isOk())
          .andExpect(view().name("home"));

        mockMvc.perform(get("/logout.do")).andReturn();

        session = new MockHttpSession();
        performLoginWithSession();

        mockMvc.perform(post("/login/mfa/verify.do")
          .param("code", Integer.toString(code + 1))
          .header("Host", "localhost")
          .session(session)
          .with(cookieCsrf()))
          .andExpect(status().is2xxSuccessful())
          .andExpect(view().name("mfa/enter_code"));

        eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(14, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(12), instanceOf(MfaAuthenticationFailureEvent.class));

        mockMvc.perform(post("/login/mfa/verify.do")
          .param("code", "ABCDEF")
          .header("Host", "localhost")
          .session(session)
          .with(cookieCsrf()))
          .andExpect(status().is2xxSuccessful())
          .andExpect(view().name("mfa/enter_code"));

        eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(16, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(14), instanceOf(MfaAuthenticationFailureEvent.class));
    }

    @Test
    public void testQRCodeRedirectIfCodeValidated() throws Exception {

        redirectToMFARegistration();

        performGetMfaRegister().andExpect(view().name("mfa/qr_code"));

        int code = MockMvcUtils.getMFACodeFromSession(session);

        MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, session);

        UserGoogleMfaCredentials activeCreds = jdbcUserGoogleMfaCredentialsProvisioning.retrieve(user.getId(), mfaProvider.getId());
        assertNotNull(activeCreds);
        assertEquals(mfaProvider.getId(), activeCreds.getMfaProviderId());
        mockMvc.perform(get("/logout.do")).andReturn();

        session = new MockHttpSession();
        performLoginWithSession();

        performGetMfaRegister().andExpect(redirectedUrl("/login/mfa/verify"));
    }

    @Test
    public void testRegisterFlowWithMfaProviderSwitch() throws Exception {

        redirectToMFARegistration();

        performGetMfaRegister().andExpect(view().name("mfa/qr_code"));

        int code = MockMvcUtils.getMFACodeFromSession(session);

        String location = MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, session);


        location = mockMvc.perform(
          get(location)
            .session(session)
        )
          .andExpect(status().isFound())
          .andReturn().getResponse().getRedirectedUrl();

        mockMvc.perform(
          get(location)
            .session(session)
        )
          .andExpect(status().isOk())
          .andExpect(view().name("home"));


        UserGoogleMfaCredentials activeCreds = jdbcUserGoogleMfaCredentialsProvisioning.retrieve(user.getId(), mfaProvider.getId());
        assertNotNull(activeCreds);
        assertEquals(mfaProvider.getId(), activeCreds.getMfaProviderId());
        mockMvc.perform(get("/logout.do")).andReturn();

        uaaZoneConfig = MockMvcUtils.getZoneConfiguration(webApplicationContext, "uaa");
        uaaZoneConfig.getMfaConfig().setProviderName(otherMfaProvider.getName());
        MockMvcUtils.setZoneConfiguration(webApplicationContext, "uaa", uaaZoneConfig);

        session = new MockHttpSession();
        performLoginWithSession();

        performGetMfaRegister().andExpect(view().name("mfa/qr_code"));

        code = MockMvcUtils.getMFACodeFromSession(session);

        location = MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, session);

        location = mockMvc.perform(
          get(location)
            .session(session)
        )
          .andExpect(status().isFound())
          .andReturn().getResponse().getRedirectedUrl();

        mockMvc.perform(
          get(location)
            .session(session)
        )
          .andExpect(status().isOk())
          .andExpect(view().name("home"));
    }

    @Test
    public void testQRCodeRedirectIfCodeNotValidated() throws Exception {
        redirectToMFARegistration();

        performGetMfaRegister().andExpect(view().name("mfa/qr_code"));

        UserGoogleMfaCredentials inActiveCreds = (UserGoogleMfaCredentials) session.getAttribute("uaaMfaCredentials");
        assertNotNull(inActiveCreds);

        performGetMfaRegister().andExpect(view().name("mfa/qr_code"));
    }

    @Test
    public void testManualRegistrationFlow() throws Exception {
        redirectToMFARegistration();

        assertFalse(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(user.getId(), mfaProvider.getId()));

        performGetMfaManualRegister().andExpect((view().name("mfa/manual_registration")));

        int code = MockMvcUtils.getMFACodeFromSession(session);

        String location = MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, session);
        assertEquals("/login/mfa/completed", location);

        ArgumentCaptor<AbstractUaaEvent> eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(8, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(6), instanceOf(MfaAuthenticationSuccessEvent.class));

        mockMvc.perform(get("/")
          .session(session))
          .andExpect(status().isOk())
          .andExpect(view().name("home"));

        mockMvc.perform(get("/logout.do")).andReturn();

        session = new MockHttpSession();
        performLoginWithSession();
        MockMvcUtils.performMfaPostVerifyWithCode(code, mockMvc, session);

        eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(15, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(13), instanceOf(MfaAuthenticationSuccessEvent.class));
    }

    @Test
    public void testQRDoesNotChangeDuringOneSession() throws Exception {
        redirectToMFARegistration();
        assertFalse(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(user.getId(), mfaProvider.getId()));

        MvcResult res = performGetMfaRegister().andExpect(view().name("mfa/qr_code")).andReturn();
        String qrUrl = (String) res.getModelAndView().getModel().get("qrurl");

        performGetMfaRegister()
          .andExpect(view().name("mfa/qr_code"))
          .andExpect(model().attribute("qrurl", qrUrl));
    }

    private ScimUser createUser() {
        ScimUser user = new ScimUser(null, new RandomValueStringGenerator(5).generate(), "first", "last");

        password = "sec3Tas";
        user.setPrimaryEmail(user.getUserName());
        user.setPassword(password);
        user = webApplicationContext.getBean(ScimUserProvisioning.class).createUser(user, user.getPassword(), IdentityZoneHolder.getUaaZone().getId());
        return user;
    }

    private ResultActions performLoginWithSession() throws Exception {
        return mockMvc.perform(post("/login.do")
          .session(session)
          .param("username", user.getUserName())
          .param("password", password)
          .with(cookieCsrf()))
          .andDo(print())
          .andExpect(status().isFound());
    }


    private ResultActions performGetMfaRegister() throws Exception {
        return mockMvc.perform(get("/login/mfa/register")
          .session(session));
    }

    private ResultActions performGetMfaManualRegister() throws Exception {
        return mockMvc.perform(get("/login/mfa/manual")
          .session(session)
        );
    }

    private void redirectToMFARegistration() throws Exception {
        String location = performLoginWithSession().andReturn().getResponse().getHeader("Location");
        mockMvc.perform(get(location)
          .session(session))
          .andExpect(redirectedUrl("/login/mfa/register"));
    }


}
