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
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.mfa.GoogleAuthenticatorAdapter;
import org.cloudfoundry.identity.uaa.mfa.GoogleMfaProviderConfig;
import org.cloudfoundry.identity.uaa.mfa.MfaProvider;
import org.cloudfoundry.identity.uaa.mfa.MfaProviderProvisioning;
import org.cloudfoundry.identity.uaa.mfa.UserGoogleMfaCredentialsProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.ui.Model;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.view.RedirectView;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class TotpMfaEndpointTest {
    private String userId;
    private TotpMfaEndpoint endpoint = new TotpMfaEndpoint();
    private UserGoogleMfaCredentialsProvisioning userGoogleMfaCredentialsProvisioning;
    private MfaProviderProvisioning mfaProviderProvisioning;
    private UaaAuthentication uaaAuthentication;

    @Rule
    public ExpectedException exception = ExpectedException.none();
    private GoogleAuthenticatorAdapter googleAuthenticatorService;
    private MfaProvider<GoogleMfaProviderConfig> mfaProvider;
    private MfaProvider<GoogleMfaProviderConfig> otherMfaProvider;
    private SavedRequestAwareAuthenticationSuccessHandler mockSuccessHandler;

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

        otherMfaProvider = new MfaProvider();
        otherMfaProvider.setName("other-provider-name");
        otherMfaProvider.setId("provider_id2");
        otherMfaProvider.setConfig(new GoogleMfaProviderConfig());


        endpoint.setUserGoogleMfaCredentialsProvisioning(userGoogleMfaCredentialsProvisioning);
        endpoint.setMfaProviderProvisioning(mfaProviderProvisioning);
        googleAuthenticatorService = mock(GoogleAuthenticatorAdapter.class);
        endpoint.setGoogleAuthenticatorService(googleAuthenticatorService);

        mockSuccessHandler = mock(SavedRequestAwareAuthenticationSuccessHandler.class);

        SecurityContextHolder.getContext().setAuthentication(uaaAuthentication);
    }

    @After
    public void cleanUp() throws Exception {
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(false);
        SecurityContextHolder.clearContext();
    }

    @Test
    public void testGenerateQrUrl() throws Exception{
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);
        when(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(userId, mfaProvider.getId())).thenReturn(false);

        when(mfaProviderProvisioning.retrieveByName(mfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(mfaProvider);
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());

        String returnView = endpoint.generateQrUrl(mock(Model.class));

        assertEquals("mfa/qr_code", returnView);
    }

    @Test
    public void testGenerateQrUrlForNewUserRegistration() throws Exception{
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);

        when(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(userId, mfaProvider.getId())).thenReturn(true);
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());
        when(mfaProviderProvisioning.retrieveByName(mfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(mfaProvider);

        String returnView = endpoint.generateQrUrl(mock(Model.class));

        assertEquals("redirect:/login/mfa/verify", returnView);
    }


    @Test
    public void testGenerateQrUrlAfterMfaProviderSwitch() throws Exception{
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);

        when(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(userId, mfaProvider.getId())).thenReturn(true);
        when(mfaProviderProvisioning.retrieveByName(mfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(mfaProvider);
        when(mfaProviderProvisioning.retrieveByName(otherMfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(otherMfaProvider);

        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(otherMfaProvider.getName());

        String returnView = endpoint.generateQrUrl(mock(Model.class));

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
        when(googleAuthenticatorService.isValidCode(userId, code)).thenReturn(true);
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);

        ModelAndView returnView = endpoint.validateCode(mock(Model.class), Integer.toString(code));

        assertEquals("/login/mfa/completed", ((RedirectView)returnView.getView()).getUrl());
    }

    @Test
    public void testValidOTPActivatesUser() throws Exception {
        int code = 1234;
        when(googleAuthenticatorService.isValidCode(userId, code)).thenReturn(true);
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);

        endpoint.validateCode(mock(Model.class), Integer.toString(code));
        verify(userGoogleMfaCredentialsProvisioning).persistCredentials();

    }

    @Test
    public void testInvalidOTPReturnsError() throws Exception{
        int code = 1234;
        when(googleAuthenticatorService.isValidCode(userId, code)).thenReturn(false);
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);
        ModelAndView returnView = endpoint.validateCode(mock(Model.class), Integer.toString(code));

        assertEquals("mfa/enter_code", returnView.getViewName());
    }

    @Test
    public void testValidateCodeThrowsException() throws Exception{
        int code = 1234;
        when(googleAuthenticatorService.isValidCode(userId, code)).thenThrow(new GoogleAuthenticatorException("Thou shall not pass"));
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);
        ModelAndView returnView = endpoint.validateCode(mock(Model.class), Integer.toString(code));

        assertEquals("mfa/enter_code", returnView.getViewName());
    }

    @Test
    public void testEmptyOTP() throws Exception{
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);
        ModelAndView returnView = endpoint.validateCode(mock(Model.class), "");
        assertEquals("mfa/enter_code", returnView.getViewName());
    }

    @Test
    public void testNonNumericOTP() throws Exception{
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);
        ModelAndView returnView = endpoint.validateCode(mock(Model.class), "asdf123");
        assertEquals("mfa/enter_code", returnView.getViewName());
    }

    @Test
    public void testManualRegistration() throws Exception {
        when(googleAuthenticatorService.getOtpSecret(anyString())).thenReturn("ABCDEFGHIJKLMNOP");
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);
        when(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(userId, mfaProvider.getId())).thenReturn(false);
        when(mfaProviderProvisioning.retrieveByName(mfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(mfaProvider);
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());

        String returnValue = endpoint.manualRegistration(mock(Model.class));

        assertEquals("mfa/manual_registration", returnValue);
    }

    @Test
    public void testManualRegistrationExistingCredential() throws Exception {
        when(uaaAuthentication.getPrincipal()).thenReturn(new UaaPrincipal(userId, "Marissa", null, null, null, null), null, null);
        when(userGoogleMfaCredentialsProvisioning.activeUserCredentialExists(userId, mfaProvider.getId())).thenReturn(true);
        when(mfaProviderProvisioning.retrieveByName(mfaProvider.getName(), IdentityZoneHolder.get().getId())).thenReturn(mfaProvider);
        IdentityZoneHolder.get().getConfig().getMfaConfig().setEnabled(true).setProviderName(mfaProvider.getName());

        String returnValue = endpoint.manualRegistration(mock(Model.class));

        assertEquals("redirect:/login/mfa/verify", returnValue);
    }
}