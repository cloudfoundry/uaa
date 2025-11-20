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

package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.oauth.TokenTestSupport;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthCodeToken;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.saml.SAMLProcessingFilter;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.FilterChain;
import java.util.Collections;

import static java.util.Optional.ofNullable;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.OPENID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class BackwardsCompatibleTokenEndpointAuthenticationFilterTest {


    private AuthenticationManager passwordAuthManager;
    private OAuth2RequestFactory requestFactory;
    private SAMLProcessingFilter samlAuthFilter;
    private ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager;
    private BackwardsCompatibleTokenEndpointAuthenticationFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain chain;
    private AuthenticationEntryPoint entryPoint;
    private TokenTestSupport support;

    @Before
    public void setUp() {

        passwordAuthManager = mock(AuthenticationManager.class);
        requestFactory = mock(OAuth2RequestFactory.class);
        samlAuthFilter = mock(SAMLProcessingFilter.class);
        externalOAuthAuthenticationManager = mock(ExternalOAuthAuthenticationManager.class);

        filter = spy(
            new BackwardsCompatibleTokenEndpointAuthenticationFilter(
                passwordAuthManager,
                requestFactory,
                samlAuthFilter,
                    externalOAuthAuthenticationManager
            )
        );

        entryPoint = mock(AuthenticationEntryPoint.class);
        filter.setAuthenticationEntryPoint(entryPoint);

        request = new MockHttpServletRequest("POST", "/oauth/token");
        response = new MockHttpServletResponse();
        chain = mock(FilterChain.class);
    }

    @After
    public void tearDown() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
        ofNullable(support).ifPresent(TokenTestSupport::clear);
    }

    @Test
    public void password_expired() throws Exception {
        UaaAuthentication uaaAuthentication = mock(UaaAuthentication.class);
        when(uaaAuthentication.isAuthenticated()).thenReturn(true);
        MockHttpSession httpSession = new MockHttpSession();
        SessionUtils.setPasswordChangeRequired(httpSession, true);
        request.setSession(httpSession);
        when(passwordAuthManager.authenticate(any())).thenReturn(uaaAuthentication);
        request.addParameter(GRANT_TYPE, "password");
        request.addParameter("username", "marissa");
        request.addParameter("password", "koala");
        filter.doFilter(request, response, chain);
        verify(entryPoint, times(1)).commence(same(request), same(response), any(PasswordChangeRequiredException.class));

    }

    @Test
    public void attempt_password_authentication() throws Exception {
        request.addParameter(GRANT_TYPE, "password");
        request.addParameter("username", "marissa");
        request.addParameter("password", "koala");
        filter.doFilter(request, response, chain);
        verify(filter, times(1)).attemptTokenAuthentication(same(request), same(response));
        verify(passwordAuthManager, times(1)).authenticate(any());
        verifyNoInteractions(samlAuthFilter);
        verifyNoInteractions(externalOAuthAuthenticationManager);
    }


    @Test
    public void attempt_saml_assertion_authentication() throws Exception {
        request.addParameter(GRANT_TYPE, GRANT_TYPE_SAML2_BEARER);
        request.addParameter("assertion", "saml-assertion-value-here");
        filter.doFilter(request, response, chain);
        verify(filter, times(1)).attemptTokenAuthentication(same(request), same(response));
        verify(samlAuthFilter, times(1)).attemptAuthentication(same(request), same(response));
        verifyNoInteractions(passwordAuthManager);
        verifyNoInteractions(externalOAuthAuthenticationManager);
    }

    @Test
    public void saml_assertion_missing() throws Exception {
        request.addParameter(GRANT_TYPE, GRANT_TYPE_SAML2_BEARER);
        filter.doFilter(request, response, chain);
        verify(filter, times(1)).attemptTokenAuthentication(same(request), same(response));
        verifyNoInteractions(externalOAuthAuthenticationManager);
        verifyNoInteractions(passwordAuthManager);
        verifyNoInteractions(externalOAuthAuthenticationManager);
        ArgumentCaptor<AuthenticationException> exceptionArgumentCaptor = ArgumentCaptor.forClass(AuthenticationException.class);
        verify(entryPoint, times(1)).commence(same(request), same(response), exceptionArgumentCaptor.capture());
        assertNotNull(exceptionArgumentCaptor.getValue());
        assertEquals("SAML Assertion is missing", exceptionArgumentCaptor.getValue().getMessage());
        assertTrue(exceptionArgumentCaptor.getValue() instanceof InsufficientAuthenticationException);
    }

    @Test
    @Ignore("GE Fork has its own JWT-bearer implementation")
    public void attempt_jwt_token_authentication() throws Exception {
        support = new TokenTestSupport(null);
        String idToken = support.getIdTokenAsString(Collections.singletonList(OPENID));
        request.addParameter(GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        request.addParameter("assertion", idToken);
        filter.doFilter(request, response, chain);
        verify(filter, times(1)).attemptTokenAuthentication(same(request), same(response));
        ArgumentCaptor<ExternalOAuthCodeToken> authenticateData = ArgumentCaptor.forClass(ExternalOAuthCodeToken.class);
        verify(externalOAuthAuthenticationManager, times(1)).authenticate(authenticateData.capture());
        verifyNoInteractions(passwordAuthManager);
        verifyNoMoreInteractions(externalOAuthAuthenticationManager);
        assertEquals(idToken, authenticateData.getValue().getIdToken());
        assertNull(authenticateData.getValue().getOrigin());
    }

    @Test
    @Ignore("GE Fork has its own JWT-bearer implementation")
    public void jwt_assertion_missing() throws Exception {
        request.addParameter(GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        filter.doFilter(request, response, chain);
        verify(filter, times(1)).attemptTokenAuthentication(same(request), same(response));
        verifyNoInteractions(externalOAuthAuthenticationManager);
        verifyNoInteractions(passwordAuthManager);
        verifyNoInteractions(externalOAuthAuthenticationManager);
        ArgumentCaptor<AuthenticationException> exceptionArgumentCaptor = ArgumentCaptor.forClass(AuthenticationException.class);
        verify(entryPoint, times(1)).commence(same(request), same(response), exceptionArgumentCaptor.capture());
        assertNotNull(exceptionArgumentCaptor.getValue());
        assertEquals("Assertion is missing", exceptionArgumentCaptor.getValue().getMessage());
        assertTrue(exceptionArgumentCaptor.getValue() instanceof InsufficientAuthenticationException);
    }

}