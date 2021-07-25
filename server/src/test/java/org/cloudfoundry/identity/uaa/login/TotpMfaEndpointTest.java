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


import com.warrenstrange.googleauth.GoogleAuthenticatorException;
import org.cloudfoundry.identity.uaa.audit.event.AbstractUaaEvent;
import org.cloudfoundry.identity.uaa.authentication.AuthenticationPolicyRejectionException;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.manager.CommonLoginPolicy;
import org.cloudfoundry.identity.uaa.authentication.manager.LoginPolicy;
import org.cloudfoundry.identity.uaa.login.util.RandomValueStringGenerator;
import org.cloudfoundry.identity.uaa.mfa.GoogleMfaProviderConfig;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mfa.MfaProviderProvisioning;
import org.cloudfoundry.identity.uaa.mfa.UserGoogleMfaCredentials;
import org.cloudfoundry.identity.uaa.mfa.UserGoogleMfaCredentialsProvisioning;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUserPrototype;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.ui.Model;
import org.springframework.web.bind.support.SessionStatus;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import java.util.List;

import static org.hamcrest.Matchers.instanceOf;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;

public class TotpMfaEndpointTest {
    private String userId;
    private TotpMfaEndpoint endpoint;
    private UserGoogleMfaCredentialsProvisioning userGoogleMfaCredentialsProvisioning;
    private MfaProviderProvisioning mfaProviderProvisioning;
    private UaaAuthentication uaaAuthentication;

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private MfaProvider<GoogleMfaProviderConfig> mfaProvider;
    private MfaProvider<GoogleMfaProviderConfig> otherMfaProvider;
    private SavedRequestAwareAuthenticationSuccessHandler mockSuccessHandler;
    private ApplicationEventPublisher publisher;
    private ArgumentCaptor<ApplicationEvent> eventCaptor;
    private UaaUserDatabase userDb;
    private CommonLoginPolicy mockMfaPolicy;

    @Before
    public void setup() {
        userId = new RandomValueStringGenerator(5).generate();

        userGoogleMfaCredentialsProvisioning = mock(UserGoogleMfaCredentialsProvisioning.class);
        mfaProviderProvisioning = mock(MfaProviderProvisioning.class);
        uaaAuthentication = mock(UaaAuthentication.class);

        mfaProvider = new MfaProvider();
        mfaProvider.setName("provider-name");
        mfaProvider.setId("provider_id1");
        mfaProvider.setConfig(new GoogleMfaProviderConfig());
        mfaProvider.setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR);

        otherMfaProvider = new MfaProvider();
        otherMfaProvider.setName("other-provider-name");
        otherMfaProvider.setId("provider_id2");
        otherMfaProvider.setConfig(new GoogleMfaProviderConfig());
        otherMfaProvider.setType(MfaProvider.MfaProviderType.GOOGLE_AUTHENTICATOR);

        mockSuccessHandler = mock(SavedRequestAwareAuthenticationSuccessHandler.class);

        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);

        publisher = mock(ApplicationEventPublisher.class);
        eventCaptor = ArgumentCaptor.forClass(ApplicationEvent.class);
        doNothing().when(publisher).publishEvent(eventCaptor.capture());

        userDb = mock(UaaUserDatabase.class);
        mockMfaPolicy = mock(CommonLoginPolicy.class);
        when(mockMfaPolicy.isAllowed(anyString())).thenReturn(new LoginPolicy.Result(true, 0));

        endpoint = new TotpMfaEndpoint(
                userGoogleMfaCredentialsProvisioning,
                mfaProviderProvisioning,
                "/login/mfa/completed",
                userDb,
                mockMfaPolicy);
        endpoint.setApplicationEventPublisher(publisher);
    }

    @After
    public void cleanUp() {
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(false).setProviderName(null);
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testGenerateQrUrl() throws Exception{
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);
        when(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(userId, mfaProvider.getId())).thenReturn(false);

        when(mfaProviderProvisioning.retrieveByName(mfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(mfaProvider);
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());

        String returnView = endpoint.generateQrUrl(mock(Model.class), null);

        assertEquals("mfa/qr_code", returnView);
    }

    @Test
    public void testGenerateQrUrlForNewUserRegistration() throws Exception{
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);

        when(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(userId, mfaProvider.getId())).thenReturn(true);
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        when(mfaProviderProvisioning.retrieveByName(mfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(mfaProvider);

        String returnView = endpoint.generateQrUrl(mock(Model.class), null);

        assertEquals("redirect:/login/mfa/verify", returnView);
    }

    @Test
    public void testGenerateQrUrlAfterMfaProviderSwitch() throws Exception{
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);

        when(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(userId, mfaProvider.getId())).thenReturn(true);
        when(mfaProviderProvisioning.retrieveByName(mfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(mfaProvider);
        when(mfaProviderProvisioning.retrieveByName(otherMfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(otherMfaProvider);

        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(otherMfaProvider.getName());

        String returnView = endpoint.generateQrUrl(mock(Model.class), null);

        assertEquals("mfa/qr_code", returnView);
    }

    @Test(expected = TotpMfaEndpoint.UaaPrincipalIsNotInSession.class)
    public void testTotpAuthorizePageNoAuthentication() throws Exception{
        when(uaaAuthentication.getPrincipal()).thenReturn(null);
        endpoint.totpAuthorize(mock(Model.class));
    }

    @Test
    public void testTotpAuthorizePage() throws Exception{
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);

        ModelAndView returnView = endpoint.totpAuthorize(mock(Model.class));
        assertEquals("mfa/enter_code", returnView.getViewName());
    }


    @Test
    public void testValidOTPTakesToHomePage() throws Exception{
        int code = 1234;
        when(userGoogleMfaCredentialsProvisioning.isValidCode(ArgumentMatchers.any(UserGoogleMfaCredentials.class), eq(code))).thenReturn(true);
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, "uaa", null, null), null, null);
        when(mfaProviderProvisioning.retrieveByName(mfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(mfaProvider);
        when(userDb.retrieveUserByName("Marissa", "uaa")).thenReturn(new UaaUser(new UaaUserPrototype().withUsername("Marissa").withOrigin("uaa").withId("1234").withEmail("marissa@example.com")));
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());

        SessionStatus sessionStatus = mock(SessionStatus.class);
        ModelAndView returnView = endpoint.validateCode(
            mock(Model.class),
            Integer.toString(code),
            mock(UserGoogleMfaCredentials.class),
            new MockHttpServletRequest(),
            sessionStatus);

        assertEquals("/login/mfa/completed", ((RedirectView)returnView.getView()).getUrl());
        verify(sessionStatus, times(1)).setComplete();
        verifyMfaEvent(MfaAuthenticationSuccessEvent.class);
    }

    @Test
    public void testValidOTPActivatesUser() throws Exception {
        int code = 1234;
        when(userGoogleMfaCredentialsProvisioning.isValidCode(ArgumentMatchers.any(UserGoogleMfaCredentials.class), eq(code))).thenReturn(true);
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, "uaa", null, null), null, null);
        when(mfaProviderProvisioning.retrieveByName(mfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(mfaProvider);
        when(userDb.retrieveUserByName("Marissa", "uaa")).thenReturn(new UaaUser(new UaaUserPrototype().withUsername("Marissa").withOrigin("uaa").withId("1234").withEmail("marissa@example.com")));
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());

        SessionStatus sessionStatus = mock(SessionStatus.class);
        endpoint.validateCode(mock(Model.class),
                              Integer.toString(code),
                              mock(UserGoogleMfaCredentials.class),
                              new MockHttpServletRequest(),
                              sessionStatus
        );
        verify(userGoogleMfaCredentialsProvisioning).saveUserCredentials(ArgumentMatchers.any(UserGoogleMfaCredentials.class));
        verify(sessionStatus).setComplete();
        verifyMfaEvent(MfaAuthenticationSuccessEvent.class);
    }

    @Test
    public void testInvalidOTPReturnsError() throws Exception{
        int code = 1234;
        when(userGoogleMfaCredentialsProvisioning.isValidCode(ArgumentMatchers.any(UserGoogleMfaCredentials.class), eq(code))).thenReturn(false);
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, "uaa", null, null), null, null);
        when(mfaProviderProvisioning.retrieveByName(mfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(mfaProvider);
        when(userDb.retrieveUserByName("Marissa", "uaa")).thenReturn(new UaaUser(new UaaUserPrototype().withUsername("Marissa").withOrigin("uaa").withId("1234").withEmail("marissa@example.com")));
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        SessionStatus sessionStatus = mock(SessionStatus.class);
        ModelAndView returnView = endpoint.validateCode(
            mock(Model.class),
            Integer.toString(code),
            mock(UserGoogleMfaCredentials.class),
            new MockHttpServletRequest(),
            sessionStatus
        );

        assertEquals("mfa/enter_code", returnView.getViewName());
        verifyZeroInteractions(sessionStatus);
        verifyMfaEvent(MfaAuthenticationFailureEvent.class);
    }

    @Test
    public void testValidOTPReturnsErrorWhenLockedOut() throws Exception{
        exception.expect(AuthenticationPolicyRejectionException.class);
        int code = 1234;


        when(mockMfaPolicy.isAllowed(anyString())).thenReturn(new LoginPolicy.Result(false, 0));

        when(userGoogleMfaCredentialsProvisioning.isValidCode(ArgumentMatchers.any(UserGoogleMfaCredentials.class), eq(code))).thenReturn(true);
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, "uaa", null, null), null, null);
        when(mfaProviderProvisioning.retrieveByName(mfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(mfaProvider);
        when(userDb.retrieveUserByName("Marissa", "uaa")).thenReturn(new UaaUser(new UaaUserPrototype().withUsername("Marissa").withOrigin("uaa").withId("1234").withEmail("marissa@example.com")));
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        SessionStatus sessionStatus = mock(SessionStatus.class);

        endpoint.validateCode(
          mock(Model.class),
          Integer.toString(code),
          mock(UserGoogleMfaCredentials.class),
          new MockHttpServletRequest(),
          sessionStatus
        );

        verifyZeroInteractions(sessionStatus);
        verifyMfaEvent(MfaAuthenticationFailureEvent.class);
    }

    @Test
    public void testValidateCodeThrowsException() throws Exception{
        int code = 1234;
        when(userGoogleMfaCredentialsProvisioning.isValidCode(ArgumentMatchers.any(UserGoogleMfaCredentials.class), eq(code))).thenThrow(new GoogleAuthenticatorException("Thou shall not pass"));
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, "uaa", null, null), null, null);
        when(mfaProviderProvisioning.retrieveByName(mfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(mfaProvider);
        when(userDb.retrieveUserByName("Marissa", "uaa")).thenReturn(new UaaUser(new UaaUserPrototype().withUsername("Marissa").withOrigin("uaa").withId("1234").withEmail("marissa@example.com")));
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        SessionStatus sessionStatus = mock(SessionStatus.class);
        ModelAndView returnView = endpoint.validateCode(
            mock(Model.class),
            Integer.toString(code),
            mock(UserGoogleMfaCredentials.class),
            new MockHttpServletRequest(),
            sessionStatus
        );

        assertEquals("mfa/enter_code", returnView.getViewName());
        verifyZeroInteractions(sessionStatus);
        verifyMfaEvent(MfaAuthenticationFailureEvent.class);
    }

    @Test
    public void testEmptyOTP() throws Exception{
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, "uaa", null, null), null, null);
        when(mfaProviderProvisioning.retrieveByName(mfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(mfaProvider);
        when(userDb.retrieveUserByName("Marissa", "uaa")).thenReturn(new UaaUser(new UaaUserPrototype().withUsername("Marissa").withOrigin("uaa").withId("1234").withEmail("marissa@example.com")));
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        SessionStatus sessionStatus = mock(SessionStatus.class);
        ModelAndView returnView = endpoint.validateCode(
            mock(Model.class),
            "",
            mock(UserGoogleMfaCredentials.class),
            new MockHttpServletRequest(),
            sessionStatus
        );
        assertEquals("mfa/enter_code", returnView.getViewName());
        verifyZeroInteractions(sessionStatus);
        verifyMfaEvent(MfaAuthenticationFailureEvent.class);
    }

    @Test
    public void testNonNumericOTP() throws Exception{
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, "uaa", null, null), null, null);
        when(mfaProviderProvisioning.retrieveByName(mfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(mfaProvider);
        when(userDb.retrieveUserByName("Marissa", "uaa")).thenReturn(new UaaUser(new UaaUserPrototype().withUsername("Marissa").withOrigin("uaa").withId("1234").withEmail("marissa@example.com")));
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        SessionStatus sessionStatus = mock(SessionStatus.class);
        ModelAndView returnView = endpoint.validateCode(
            mock(Model.class),
            "asdf123",
            mock(UserGoogleMfaCredentials.class),
            new MockHttpServletRequest(),
            sessionStatus
        );
        assertEquals("mfa/enter_code", returnView.getViewName());
        verifyZeroInteractions(sessionStatus);
        verifyMfaEvent(MfaAuthenticationFailureEvent.class);
    }

    @Test
    public void testManualRegistration() throws Exception {
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);
        when(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(userId, mfaProvider.getId())).thenReturn(false);
        when(mfaProviderProvisioning.retrieveByName(mfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(mfaProvider);
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        String returnValue = endpoint.manualRegistration(mock(Model.class), mock(UserGoogleMfaCredentials.class));
        assertEquals("mfa/manual_registration", returnValue);
    }

    @Test
    public void testManualRegistrationExistingCredential() throws Exception {
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);
        when(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(userId, mfaProvider.getId())).thenReturn(true);
        when(mfaProviderProvisioning.retrieveByName(mfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(mfaProvider);
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());

        String returnValue = endpoint.manualRegistration(
            mock(Model.class),
            mock(UserGoogleMfaCredentials.class)
        );

        assertEquals("redirect:/login/mfa/verify", returnValue);
    }

    private void verifyMfaEvent(Class<? extends AbstractUaaEvent> eventClass) {
        List<ApplicationEvent> values = eventCaptor.getAllValues();
        assertEquals(1, values.size());
        ApplicationEvent event = values.get(0);
        assertThat(event, instanceOf(eventClass));
        AbstractUaaEvent mfaEvent = (AbstractUaaEvent) event;
        assertEquals("google-authenticator", mfaEvent.getAuditEvent().getAuthenticationType());
    }
}