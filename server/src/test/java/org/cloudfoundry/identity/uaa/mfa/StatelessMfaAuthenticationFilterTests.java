/*
 *  ****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2018] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 *  ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.mfa;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mfa.exception.InvalidMfaCodeException;
import org.cloudfoundry.identity.uaa.mfa.exception.MissingMfaCodeException;
import org.cloudfoundry.identity.uaa.mfa.exception.UserMfaConfigDoesNotExistException;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenancyFixture;

import com.jayway.jsonassert.JsonAssert;
import org.junit.After;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.OAuth2Request;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;

import static org.hamcrest.Matchers.containsInAnyOrder;
import static org.hamcrest.Matchers.equalTo;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.mockito.AdditionalMatchers.not;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.GRANT_TYPE;
import static java.util.Arrays.asList;

public class StatelessMfaAuthenticationFilterTests {

    public static final String MFA_CODE = "mfaCode";

    @Rule
    public ExpectedException exception = ExpectedException.none();

    private UserGoogleMfaCredentialsProvisioning googleAuthenticator;
    private Set<String> grantTypes;
    private StatelessMfaAuthenticationFilter filter;
    private FilterChain chain;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private OAuth2Authentication authentication;
    private OAuth2Request storedOAuth2Request;
    private UaaAuthentication uaaAuthentication;
    private MfaProviderProvisioning mfaProvider;
    private IdentityZone zone;

    @After
    public void teardown() throws Exception {
        IdentityZoneHolder.clear();
    }

    @Before
    public void setup() throws Exception {
        zone = MultitenancyFixture.identityZone("id", "id");
        zone.getConfig().getMfaConfig().setEnabled(true).setProviderName("mfa-provider-name");
        IdentityZoneHolder.set(zone);

        storedOAuth2Request = mock(OAuth2Request.class);
        UaaPrincipal uaaPrincipal = new UaaPrincipal("1", "marissa", "marissa@test.org", OriginKeys.UAA, null, zone.getId());
        uaaAuthentication = new UaaAuthentication(uaaPrincipal, Collections.emptyList(), mock(UaaAuthenticationDetails.class));
        uaaAuthentication.setAuthenticationMethods(new HashSet<>(asList("pwd")));
        authentication = new OAuth2Authentication(storedOAuth2Request, uaaAuthentication);
        SecurityContextHolder.getContext().setAuthentication(authentication);

        googleAuthenticator = mock(UserGoogleMfaCredentialsProvisioning.class);
        when(googleAuthenticator.activeUserCredentialExists(anyString(), anyString())).thenReturn(true);
        when(googleAuthenticator.isValidCode(any(), eq(123456))).thenReturn(true);
        when(googleAuthenticator.isValidCode(any(), not(eq(123456)))).thenReturn(false);
        when(googleAuthenticator.getUserGoogleMfaCredentials(anyString(), anyString())).thenReturn(mock(UserGoogleMfaCredentials.class));
        grantTypes = new HashSet<>(Arrays.asList("password"));

        mfaProvider = mock(MfaProviderProvisioning.class);
        when(mfaProvider.retrieveByName(anyString(), anyString())).thenReturn(
            new MfaProvider().setName("mfa-provider-name").setId("mfa-provider-id")
        );

        filter = new StatelessMfaAuthenticationFilter(googleAuthenticator, grantTypes, mfaProvider);
        chain = mock(FilterChain.class);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();

        request.setParameter(GRANT_TYPE, "password");
        request.setParameter("client_id", "clientID");
        request.setParameter("client_secret", "secret");
        request.setParameter("username", "marissa");
        request.setParameter("password", "koala");
        request.setParameter(MFA_CODE, "123456");


    }

    @Test
    public void only_password_grant_type() throws Exception {
        assertTrue(filter.isGrantTypeSupported("password"));
        assertFalse(filter.isGrantTypeSupported("other"));
    }

    @Test
    public void non_password_grants_ignored() throws Exception {
        request.setParameter(GRANT_TYPE,"other-than-password");
        filter.doFilterInternal(request, response, chain);
        verifyZeroInteractions(googleAuthenticator);
        verify(chain).doFilter(same(request), same(response));
    }

    @Test
    public void authentication_missing() throws Exception {
        exception.expect(InsufficientAuthenticationException.class);
        exception.expectMessage("User authentication missing");
        SecurityContextHolder.clearContext();
        doFilterAndVerifyNoInteractions();
    }

    private void doFilterAndVerifyNoInteractions() throws ServletException, IOException {
        try {
            filter.checkMfaCode(request);
        } catch (Exception e) {
            verifyZeroInteractions(chain);
            verifyZeroInteractions(googleAuthenticator);
            throw e;
        }
    }

    @Test
    public void authentication_wrong_type() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(mock(UaaAuthentication.class));
        exception.expect(InsufficientAuthenticationException.class);
        exception.expectMessage("Unrecognizable authentication");
        doFilterAndVerifyNoInteractions();

    }

    @Test
    public void user_authentication_wrong_type() throws Exception {
        authentication = new OAuth2Authentication(storedOAuth2Request, mock(Authentication.class));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        exception.expect(InsufficientAuthenticationException.class);
        exception.expectMessage("Unrecognizable user authentication");
        doFilterAndVerifyNoInteractions();
    }

    @Test
    public void mfa_validation_works() throws Exception {
        filter.doFilterInternal(request, response, chain);
        verify(googleAuthenticator).isValidCode(any(), eq(123456));
        verify(chain).doFilter(same(request), same(response));
        assertThat(uaaAuthentication.getAuthenticationMethods(), containsInAnyOrder("pwd","otp","mfa"));
    }

    @Test
    public void mfa_code_missing() throws Exception {
        request.removeParameter(MFA_CODE);
        exception.expect(MissingMfaCodeException.class);
        exception.expectMessage("A multi-factor authentication code is required to complete the request");
        doFilterAndVerifyNoInteractions();
    }

    @Test
    public void mfa_code_missing_returns_json_error() throws Exception {
        request.removeParameter(MFA_CODE);
        filter.doFilterInternal(request, response, chain);
        assertThat(response.getStatus(), equalTo(400));
        JsonAssert.with(response.getContentAsString())
            .assertThat("error", equalTo("invalid_request"))
            .assertThat("error_description", equalTo("A multi-factor authentication code is required to complete the request"));
    }

    @Test
    public void invalid_mfa_code() throws Exception {
        request.setParameter(MFA_CODE, "54321");
        exception.expect(InvalidMfaCodeException.class);
        doFilterAndNoChainInteractions();
    }

    @Test
    public void invalid_mfa_code_returns_json_bad_credentials() throws Exception {
        request.setParameter(MFA_CODE, "54321");
        filter.doFilterInternal(request, response, chain);
        assertThat(response.getStatus(), equalTo(401));
        JsonAssert.with(response.getContentAsString())
            .assertThat("error", equalTo("unauthorized"))
            .assertThat("error_description", equalTo("Bad credentials"));
    }

    private void doFilterAndNoChainInteractions() throws ServletException, IOException {
        try {
            filter.checkMfaCode(request);
        } catch (Exception x) {
            verifyZeroInteractions(chain);
            throw x;
        }
    }

    @Test
    public void user_config_is_missing() throws Exception {
        when(googleAuthenticator.getUserGoogleMfaCredentials(anyString(), anyString())).thenReturn(null);
        exception.expect(UserMfaConfigDoesNotExistException.class);
        exception.expectMessage("User must register a multi-factor authentication token");
        doFilterAndNoChainInteractions();
    }

    @Test
    public void user_config_is_returning_error() throws Exception {
        when(googleAuthenticator.getUserGoogleMfaCredentials(anyString(), anyString())).thenReturn(null);
        filter.doFilterInternal(request, response, chain);
        assertThat(response.getStatus(), equalTo(400));
        assertThat(response.getHeader(HttpHeaders.CONTENT_TYPE), equalTo(MediaType.APPLICATION_JSON_VALUE));
        assertNotNull(response.getContentAsString());
        JsonAssert.with(response.getContentAsString())
            .assertThat("error", equalTo("invalid_request"))
            .assertThat("error_description", equalTo("User must register a multi-factor authentication token"));
    }

    @Test
    public void no_mfa_configured() throws Exception {
        zone.getConfig().getMfaConfig().setEnabled(false);
        filter.doFilterInternal(request, response, chain);
        verifyZeroInteractions(googleAuthenticator);
        verifyZeroInteractions(mfaProvider);
        verify(chain).doFilter(same(request),same(response));
    }












}