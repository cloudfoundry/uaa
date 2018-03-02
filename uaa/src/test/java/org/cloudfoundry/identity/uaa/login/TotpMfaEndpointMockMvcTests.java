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

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

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
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.context.ApplicationListener;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultActions;

import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.CookieCsrfPostProcessor.cookieCsrf;
import static org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils.createMfaProvider;
import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

public class TotpMfaEndpointMockMvcTests extends InjectedMockContextTest{

    private String adminToken;
    private JdbcUserGoogleMfaCredentialsProvisioning jdbcUserGoogleMfaCredentialsProvisioning;
    private IdentityZoneConfiguration uaaZoneConfig;
    private MfaProvider mfaProvider;
    private MfaProvider otherMfaProvider;
    private String password;
    private UserGoogleMfaCredentialsProvisioning userGoogleMfaCredentialsProvisioning;
    private ScimUser user;
    private MockHttpSession session;
    private UaaUserDatabase userDb;
    private ApplicationListener listener;

    @Before
    public void setup() throws Exception {
        adminToken = testClient.getClientCredentialsOAuthAccessToken(
            "admin",
            "adminsecret",
            "clients.read clients.write clients.secret clients.admin uaa.admin"
        );
        jdbcUserGoogleMfaCredentialsProvisioning = (JdbcUserGoogleMfaCredentialsProvisioning) getWebApplicationContext().getBean("jdbcUserGoogleMfaCredentialsProvisioning");
        userGoogleMfaCredentialsProvisioning = (UserGoogleMfaCredentialsProvisioning) getWebApplicationContext().getBean("userGoogleMfaCredentialsProvisioning");
        userDb = (UaaUserDatabase)getWebApplicationContext().getBean("userDatabase");

        mfaProvider = createMfaProvider(getWebApplicationContext(), IdentityZone.getUaa());
        otherMfaProvider = createMfaProvider(getWebApplicationContext(), IdentityZone.getUaa());


        uaaZoneConfig = MockMvcUtils.getZoneConfiguration(getWebApplicationContext(), IdentityZone.getUaa().getId());
        uaaZoneConfig.getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        MockMvcUtils.setZoneConfiguration(getWebApplicationContext(), IdentityZone.getUaa().getId(), uaaZoneConfig);

        listener = mock(ApplicationListener.class);
        getWebApplicationContext().addApplicationListener(listener);

        user = createUser();
        session = new MockHttpSession();
    }

    @After
    public void cleanup () throws Exception {
        uaaZoneConfig.getMfaConfig().setEnabled(false).setProviderName(null);
        MockMvcUtils.setZoneConfiguration(getWebApplicationContext(), "uaa", uaaZoneConfig);
        MockMvcUtils.utils().removeEventListener(getWebApplicationContext(), listener);
    }

    @Test
    public void testRedirectToMfaAfterLogin() throws Exception {
        redirectToMFARegistration();

        MockHttpServletResponse response = getMockMvc().perform(get("/profile")
                .session(session)).andReturn().getResponse();
        assertTrue(response.getRedirectedUrl().contains("/login"));
    }

    @Test
    public void testRedirectToLoginPageAfterClickingBackFromMfaRegistrationPage() throws Exception {
        redirectToMFARegistration();

        MockHttpServletResponse response = getMockMvc().perform(get("/logout.do")
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
        performLoginWithSession();
        MockMvcUtils.performMfaPostVerifyWithCode(code, getMockMvc(), session);

        eventCaptor = ArgumentCaptor.forClass(AbstractUaaEvent.class);
        verify(listener, atLeast(1)).onApplicationEvent(eventCaptor.capture());
        assertEquals(14, eventCaptor.getAllValues().size());
        assertThat(eventCaptor.getAllValues().get(12), instanceOf(MfaAuthenticationSuccessEvent.class));
    }

    @Test
    public void testMFARegistrationHonorsRedirectUri() throws Exception {
        ClientDetailsModification client = MockMvcUtils.utils()
                .getClientDetailsModification("auth-client-id", "secret",
                        Collections.emptyList(), Arrays.asList("openid"), Arrays.asList("authorization_code"), "uaa.resource",
                            Collections.singleton("http://example.com"));
        client.setAutoApproveScopes(Arrays.asList("openid"));
        Map<String, String> information = new HashMap<>();
        information.put("autoapprove", "true");
        client.setAdditionalInformation(information);

        BaseClientDetails authcodeClient = MockMvcUtils.utils().createClient(getMockMvc(),adminToken, client, IdentityZone.getUaa(), status().isCreated());

        //Not using param function because params won't end up in paramsMap.
        String oauthUrl = "/oauth/authorize?client_id=auth-client-id&client_secret=secret&redirect_uri=http://example.com";
        getMockMvc().perform(get(oauthUrl)
                                 .session(session)
                                 .with(cookieCsrf()))
            .andExpect(status().is3xxRedirection())
            .andDo(print())
            .andExpect(redirectedUrl("http://localhost/login"));

        performLoginWithSession().andExpect(redirectedUrl("http://localhost"+oauthUrl));

        getMockMvc().perform(get(oauthUrl)
                                 .session(session)
                                 .with(cookieCsrf()))
            .andExpect(status().is3xxRedirection())
            .andDo(print())
            .andExpect(redirectedUrl("/login/mfa/register"));

        performGetMfaRegister();

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
        redirectToMFARegistration();

        assertFalse(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(user.getId(), mfaProvider.getId()));

        performGetMfaManualRegister().andExpect((view().name("mfa/manual_registration")));

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
        performLoginWithSession();

        getMockMvc().perform(post("/login/mfa/verify.do")
                .param("code", Integer.toString(code+1))
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
    public void testQRCodeRedirectIfCodeValidated()  throws Exception {

        redirectToMFARegistration();

        performGetMfaRegister().andExpect(view().name("mfa/qr_code"));

        int code = MockMvcUtils.getMFACodeFromSession(session);

        MockMvcUtils.performMfaPostVerifyWithCode(code, getMockMvc(), session);

        UserGoogleMfaCredentials activeCreds = jdbcUserGoogleMfaCredentialsProvisioning.retrieve(user.getId(), mfaProvider.getId());
        assertNotNull(activeCreds);
        assertEquals(mfaProvider.getId(), activeCreds.getMfaProviderId());
        getMockMvc().perform(get("/logout.do")).andReturn();

        session = new MockHttpSession();
        performLoginWithSession();

        performGetMfaRegister().andExpect(redirectedUrl("/login/mfa/verify"));
    }

    @Test
    public void testRegisterFlowWithMfaProviderSwitch()  throws Exception {

        redirectToMFARegistration();

        performGetMfaRegister().andExpect(view().name("mfa/qr_code"));

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
        performLoginWithSession();

        performGetMfaRegister().andExpect(view().name("mfa/qr_code"));

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
    public void testQRCodeRedirectIfCodeNotValidated()  throws Exception {
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
        performLoginWithSession();
        MockMvcUtils.performMfaPostVerifyWithCode(code, getMockMvc(), session);

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

    private ScimUser createUser() throws Exception {
        ScimUser user = new ScimUser(null, new RandomValueStringGenerator(5).generate(), "first", "last");

        password = "sec3Tas";
        user.setPrimaryEmail(user.getUserName());
        user.setPassword(password);
        user = getWebApplicationContext().getBean(ScimUserProvisioning.class).createUser(user, user.getPassword(), IdentityZoneHolder.getUaaZone().getId());
        return user;
    }

    private ResultActions performLoginWithSession() throws Exception {
        return getMockMvc().perform(post("/login.do")
                                        .session(session)
                                        .param("username", user.getUserName())
                                        .param("password", password)
                                        .with(cookieCsrf()))
            .andDo(print())
            .andExpect(status().isFound());
    }


    private ResultActions performGetMfaRegister() throws Exception {
        return getMockMvc().perform(get("/login/mfa/register")
            .session(session));
    }

    private ResultActions performGetMfaManualRegister() throws Exception {
        return getMockMvc().perform(get("/login/mfa/manual")
            .session(session)
        );
    }

    private void redirectToMFARegistration() throws Exception {
        String location = performLoginWithSession().andReturn().getResponse().getHeader("Location");
        getMockMvc().perform(get(location)
                                 .session(session))
            .andExpect(redirectedUrl("/login/mfa/register"));
    }


}
