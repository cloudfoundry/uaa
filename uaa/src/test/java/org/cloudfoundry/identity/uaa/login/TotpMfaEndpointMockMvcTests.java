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

import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.mfa.JdbcUserGoogleMfaCredentialsProvisioning;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mfa.UserGoogleMfaCredentials;
import org.cloudfoundry.identity.uaa.mfa.UserGoogleMfaCredentialsProvisioning;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.oauth.client.ClientDetailsModification;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationListener;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

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

public class TotpMfaEndpointMockMvcTests extends InjectedMockContextTest {

    private String adminToken;
    private JdbcUserGoogleMfaCredentialsProvisioning jdbcUserGoogleMfaCredentialsProvisioning;
    private IdentityZoneConfiguration uaaZoneConfig;
    private MfaProvider mfaProvider;
    private MfaProvider otherMfaProvider;
    private String password;
    private UserGoogleMfaCredentialsProvisioning userGoogleMfaCredentialsProvisioning;
    private ScimUser user;
    private MockHttpSession session;
    private ApplicationListener<AbstractUaaEvent> listener;

    @BeforeClass
    public static void key() {
        Security.setProperty("crypto.policy", "unlimited");
    }

    @Before
    public void setup() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
                "admin",
                "adminsecret",
                "clients.read clients.write clients.secret clients.admin uaa.admin"
        );
        jdbcUserGoogleMfaCredentialsProvisioning = (JdbcUserGoogleMfaCredentialsProvisioning) getWebApplicationContext().getBean("jdbcUserGoogleMfaCredentialsProvisioning");
        userGoogleMfaCredentialsProvisioning = (UserGoogleMfaCredentialsProvisioning) getWebApplicationContext().getBean("userGoogleMfaCredentialsProvisioning");

        mfaProvider = createMfaProvider(getWebApplicationContext(), IdentityZone.getUaa());
        otherMfaProvider = createMfaProvider(getWebApplicationContext(), IdentityZone.getUaa());

        uaaZoneConfig = MockMvcUtils.getZoneConfiguration(getWebApplicationContext(), IdentityZone.getUaa().getId());
        uaaZoneConfig.getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        MockMvcUtils.setZoneConfiguration(getWebApplicationContext(), IdentityZone.getUaa().getId(), uaaZoneConfig);

        //noinspection unchecked
        listener = (ApplicationListener<AbstractUaaEvent>) mock(ApplicationListener.class);
        getWebApplicationContext().addApplicationListener(listener);

        password = "sec3Tas";
        user = createUser(password);
        session = new MockHttpSession();
    }

    @After
    public void cleanup() {
        uaaZoneConfig.getMfaConfig().setEnabled(false).setProviderName(null);
        MockMvcUtils.setZoneConfiguration(getWebApplicationContext(), "uaa", uaaZoneConfig);
        MockMvcUtils.removeEventListener(getWebApplicationContext(), listener);
    }

    @Test
    public void testRedirectToMfaAfterLogin() throws Exception {
        redirectToMFARegistration(getMockMvc(), session, user, password);

        MockHttpServletResponse response = getMockMvc().perform(get("/profile")
                .session(session)).andReturn().getResponse();
        assertTrue(response.getRedirectedUrl().contains("/login"));
    }

    @Test
    public void testRedirectToLoginPageAfterClickingBackFromMfaRegistrationPage() throws Exception {
        redirectToMFARegistration(getMockMvc(), session, user, password);

        MockHttpServletResponse response = getMockMvc().perform(get("/logout.do")
                .session(session)).andReturn().getResponse();

        assertTrue(response.getRedirectedUrl().endsWith("/login"));
    }

    @Test
    public void testGoogleAuthenticatorLoginFlow() throws Exception {
        redirectToMFARegistration(getMockMvc(), session, user, password);

        performGetMfaRegister(getMockMvc(), session)
                .andDo(print())
                .andExpect(view().name("mfa/qr_code"));

        assertFalse(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(user.getId(), mfaProvider.getId()));

        int code = MockMvcUtils.getMFACodeFromSession(session);

        String location = MockMvcUtils.performMfaPostVerifyWithCode(code, getMockMvc(), session);

        ArgumentCaptor<AbstractUaaEvent> eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(8, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(6), instanceOf(MfaAuthenticationSuccessEvent.class));

        getMockMvc().perform(get(location)
                .session(session))
                .andExpect(status().isFound())
                .andExpect(redirectedUrl("http://localhost/"));

        session = new MockHttpSession();
        performLoginWithSession(getMockMvc(), session, user, password);
        MockMvcUtils.performMfaPostVerifyWithCode(code, getMockMvc(), session);

        eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(14, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(12), instanceOf(MfaAuthenticationSuccessEvent.class));
    }

    @Test
    public void testLockedOutAfterExceededMfaAttempts() throws Exception {
        redirectToMFARegistration(getMockMvc(), session, user, password);
        performGetMfaRegister(getMockMvc(), session)
                .andDo(print())
                .andExpect(view().name("mfa/qr_code"));

        assertFalse(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(user.getId(), mfaProvider.getId()));
        int code = MockMvcUtils.getMFACodeFromSession(session);

        for (int i = 0; i < 5; i++) {
            getMockMvc().perform(post("/login/mfa/verify.do")
                    .param("code", Integer.toString(-1))
                    .header("Host", "localhost")
                    .session(session)
                    .with(cookieCsrf()))
                    .andExpect(status().isOk());
        }


        String location = getMockMvc().perform(post("/login/mfa/verify.do")
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

        MockMvcUtils.createClient(getMockMvc(), adminToken, client, IdentityZone.getUaa(), status().isCreated());

        //Not using param function because params won't end up in paramsMap.
        String oauthUrl = "/oauth/authorize?client_id=auth-client-id&client_secret=secret&redirect_uri=http://example.com";
        getMockMvc().perform(get(oauthUrl)
                .session(session)
                .with(cookieCsrf()))
                .andExpect(status().is3xxRedirection())
                .andDo(print())
                .andExpect(redirectedUrl("http://localhost/login"));

        performLoginWithSession(getMockMvc(), session, user, password).andExpect(redirectedUrl("http://localhost" + oauthUrl));

        getMockMvc().perform(get(oauthUrl)
                .session(session)
                .with(cookieCsrf()))
                .andExpect(status().is3xxRedirection())
                .andDo(print())
                .andExpect(redirectedUrl("/login/mfa/register"));

        performGetMfaRegister(getMockMvc(), session);

        int code = MockMvcUtils.getMFACodeFromSession(session);
        MockMvcUtils.performMfaPostVerifyWithCode(code, getMockMvc(), session);

        getMockMvc().perform(get("/login/mfa/completed")
                .session(session)
                .with(cookieCsrf()))
                .andExpect(status().is3xxRedirection())
                .andDo(print())
                .andExpect(redirectedUrl("http://localhost/oauth/authorize?client_id=auth-client-id&client_secret=secret&redirect_uri=http://example.com"));
    }

    @Test
    public void testQRCodeCannotBeSubmittedWithoutLoggedInSession() throws Exception {
        getMockMvc().perform(post("/login/mfa/verify.do")
                .param("code", "1234")
                .with(cookieCsrf()))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("http://localhost/login"));
    }

    @Test
    public void testOtpValidationFails() throws Exception {
        redirectToMFARegistration(getMockMvc(), session, user, password);

        assertFalse(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(user.getId(), mfaProvider.getId()));

        performGetMfaManualRegister(getMockMvc(), session).andExpect((view().name("mfa/manual_registration")));

        int code = MockMvcUtils.getMFACodeFromSession(session);

        String location = MockMvcUtils.performMfaPostVerifyWithCode(code, getMockMvc(), session);
        assertEquals("/login/mfa/completed", location);

        ArgumentCaptor<AbstractUaaEvent> eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(8, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(6), instanceOf(MfaAuthenticationSuccessEvent.class));

        getMockMvc().perform(get("/")
                .session(session))
                .andExpect(status().isOk())
                .andExpect(view().name("home"));

        getMockMvc().perform(get("/logout.do")).andReturn();

        session = new MockHttpSession();
        performLoginWithSession(getMockMvc(), session, user, password);

        getMockMvc().perform(post("/login/mfa/verify.do")
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

        getMockMvc().perform(post("/login/mfa/verify.do")
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

        redirectToMFARegistration(getMockMvc(), session, user, password);

        performGetMfaRegister(getMockMvc(), session).andExpect(view().name("mfa/qr_code"));

        int code = MockMvcUtils.getMFACodeFromSession(session);

        MockMvcUtils.performMfaPostVerifyWithCode(code, getMockMvc(), session);

        UserGoogleMfaCredentials activeCreds = jdbcUserGoogleMfaCredentialsProvisioning.retrieve(user.getId(), mfaProvider.getId());
        assertNotNull(activeCreds);
        assertEquals(mfaProvider.getId(), activeCreds.getMfaProviderId());
        getMockMvc().perform(get("/logout.do")).andReturn();

        session = new MockHttpSession();
        performLoginWithSession(getMockMvc(), session, user, password);

        performGetMfaRegister(getMockMvc(), session).andExpect(redirectedUrl("/login/mfa/verify"));
    }

    @Test
    public void testRegisterFlowWithMfaProviderSwitch() throws Exception {

        redirectToMFARegistration(getMockMvc(), session, user, password);

        performGetMfaRegister(getMockMvc(), session).andExpect(view().name("mfa/qr_code"));

        int code = MockMvcUtils.getMFACodeFromSession(session);

        String location = MockMvcUtils.performMfaPostVerifyWithCode(code, getMockMvc(), session);


        location = getMockMvc().perform(
                get(location)
                        .session(session)
        )
                .andExpect(status().isFound())
                .andReturn().getResponse().getRedirectedUrl();

        getMockMvc().perform(
                get(location)
                        .session(session)
        )
                .andExpect(status().isOk())
                .andExpect(view().name("home"));


        UserGoogleMfaCredentials activeCreds = jdbcUserGoogleMfaCredentialsProvisioning.retrieve(user.getId(), mfaProvider.getId());
        assertNotNull(activeCreds);
        assertEquals(mfaProvider.getId(), activeCreds.getMfaProviderId());
        getMockMvc().perform(get("/logout.do")).andReturn();

        uaaZoneConfig = MockMvcUtils.getZoneConfiguration(getWebApplicationContext(), "uaa");
        uaaZoneConfig.getMfaConfig().setProviderName(otherMfaProvider.getName());
        MockMvcUtils.setZoneConfiguration(getWebApplicationContext(), "uaa", uaaZoneConfig);

        session = new MockHttpSession();
        performLoginWithSession(getMockMvc(), session, user, password);

        performGetMfaRegister(getMockMvc(), session).andExpect(view().name("mfa/qr_code"));

        code = MockMvcUtils.getMFACodeFromSession(session);

        location = MockMvcUtils.performMfaPostVerifyWithCode(code, getMockMvc(), session);

        location = getMockMvc().perform(
                get(location)
                        .session(session)
        )
                .andExpect(status().isFound())
                .andReturn().getResponse().getRedirectedUrl();

        getMockMvc().perform(
                get(location)
                        .session(session)
        )
                .andExpect(status().isOk())
                .andExpect(view().name("home"));
    }

    @Test
    public void testQRCodeRedirectIfCodeNotValidated() throws Exception {
        redirectToMFARegistration(getMockMvc(), session, user, password);

        performGetMfaRegister(getMockMvc(), session).andExpect(view().name("mfa/qr_code"));

        UserGoogleMfaCredentials inActiveCreds = (UserGoogleMfaCredentials) session.getAttribute("uaaMfaCredentials");
        assertNotNull(inActiveCreds);

        performGetMfaRegister(getMockMvc(), session).andExpect(view().name("mfa/qr_code"));
    }

    @Test
    public void testManualRegistrationFlow() throws Exception {
        redirectToMFARegistration(getMockMvc(), session, user, password);

        assertFalse(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(user.getId(), mfaProvider.getId()));

        performGetMfaManualRegister(getMockMvc(), session).andExpect((view().name("mfa/manual_registration")));

        int code = MockMvcUtils.getMFACodeFromSession(session);

        String location = MockMvcUtils.performMfaPostVerifyWithCode(code, getMockMvc(), session);
        assertEquals("/login/mfa/completed", location);

        ArgumentCaptor<AbstractUaaEvent> eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(8, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(6), instanceOf(MfaAuthenticationSuccessEvent.class));

        getMockMvc().perform(get("/")
                .session(session))
                .andExpect(status().isOk())
                .andExpect(view().name("home"));

        getMockMvc().perform(get("/logout.do")).andReturn();

        session = new MockHttpSession();
        performLoginWithSession(getMockMvc(), session, user, password);
        MockMvcUtils.performMfaPostVerifyWithCode(code, getMockMvc(), session);

        eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(15, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(13), instanceOf(MfaAuthenticationSuccessEvent.class));
    }

    @Test
    public void testQRDoesNotChangeDuringOneSession() throws Exception {
        redirectToMFARegistration(getMockMvc(), session, user, password);
        assertFalse(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(user.getId(), mfaProvider.getId()));

        MvcResult res = performGetMfaRegister(getMockMvc(), session).andExpect(view().name("mfa/qr_code")).andReturn();
        String qrUrl = (String) res.getModelAndView().getModel().get("qrurl");

        performGetMfaRegister(getMockMvc(), session)
                .andExpect(view().name("mfa/qr_code"))
                .andExpect(model().attribute("qrurl", qrUrl));
    }

    private static ScimUser createUser(String password) {
        ScimUser user = new ScimUser(null, new RandomValueStringGenerator(5).generate(), "first", "last");

        user.setPrimaryEmail(user.getUserName());
        user.setPassword(password);
        user = getWebApplicationContext().getBean(ScimUserProvisioning.class).createUser(user, user.getPassword(), IdentityZoneHolder.getUaaZone().getId());
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
