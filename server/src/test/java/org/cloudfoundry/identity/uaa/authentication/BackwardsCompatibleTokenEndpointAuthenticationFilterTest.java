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

import jakarta.servlet.FilterChain;
import org.cloudfoundry.identity.uaa.oauth.TokenTestSupport;
import org.cloudfoundry.identity.uaa.oauth.provider.AuthorizationRequest;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Authentication;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2Request;
import org.cloudfoundry.identity.uaa.oauth.provider.OAuth2RequestFactory;
import org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthCodeToken;
import org.cloudfoundry.identity.uaa.provider.oauth.TokenExchangeData;
import org.cloudfoundry.identity.uaa.provider.saml.Saml2BearerGrantAuthenticationConverter;
import org.cloudfoundry.identity.uaa.util.SessionUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.util.Collections;
import java.util.Map;

import static java.util.Optional.ofNullable;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.TokenTestSupport.OPENID;
import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.CLIENT_AUTH_NONE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_JWT_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_TOKEN_EXCHANGE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TOKEN_TYPE_ACCESS;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.TOKEN_TYPE_ID;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.atLeast;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BackwardsCompatibleTokenEndpointAuthenticationFilterTest {

    @Mock
    private AuthenticationManager passwordAuthManager;
    @Mock
    private OAuth2RequestFactory requestFactory;
    @Mock
    private Saml2BearerGrantAuthenticationConverter saml2BearerGrantAuthenticationConverter;
    @Mock
    private ExternalOAuthAuthenticationManager externalOAuthAuthenticationManager;

    @Mock
    private AuthenticationManager tokenExchangeAuthenticationManager;

    @Mock
    private FilterChain chain;
    @Mock
    private AuthenticationEntryPoint entryPoint;

    private BackwardsCompatibleTokenEndpointAuthenticationFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private TokenTestSupport support;

    @BeforeEach
    void setUp() {
        filter = spy(
                new BackwardsCompatibleTokenEndpointAuthenticationFilter(
                        passwordAuthManager,
                        requestFactory,
                        saml2BearerGrantAuthenticationConverter,
                        externalOAuthAuthenticationManager,
                        tokenExchangeAuthenticationManager
                )
        );

        filter.setAuthenticationEntryPoint(entryPoint);
        request = new MockHttpServletRequest("POST", "/oauth/token");
        response = new MockHttpServletResponse();
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
        ofNullable(support).ifPresent(TokenTestSupport::clear);
    }

    @Test
    void passwordExpired() throws Exception {
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
    void attemptPasswordAuthentication() throws Exception {
        request.addParameter(GRANT_TYPE, "password");
        request.addParameter("username", "marissa");
        request.addParameter("password", "koala");
        when(passwordAuthManager.authenticate(any())).thenReturn(mock(UaaAuthentication.class));
        OAuth2Authentication clientAuthentication = mock(OAuth2Authentication.class);
        OAuth2Request oAuth2Request = mock(OAuth2Request.class);
        AuthorizationRequest authorizationRequest = mock(AuthorizationRequest.class);
        when(clientAuthentication.isAuthenticated()).thenReturn(true);
        when(requestFactory.createAuthorizationRequest(anyMap())).thenReturn(authorizationRequest);
        when(clientAuthentication.getOAuth2Request()).thenReturn(oAuth2Request);
        when(oAuth2Request.getExtensions()).thenReturn(Map.of(ClaimConstants.CLIENT_AUTH_METHOD, CLIENT_AUTH_NONE));
        SecurityContextHolder.getContext().setAuthentication(clientAuthentication);
        filter.doFilter(request, response, chain);
        verify(clientAuthentication, times(0)).getDetails();
        verify(filter, times(1)).attemptTokenAuthentication(same(request), same(response));
        verify(passwordAuthManager, times(1)).authenticate(any());
        verify(oAuth2Request, times(1)).getExtensions();
        verifyNoInteractions(externalOAuthAuthenticationManager);
    }

    @Test
    void attemptPasswordAuthenticationWithDetails() throws Exception {
        request.addParameter(GRANT_TYPE, "password");
        request.addParameter("username", "marissa");
        request.addParameter("password", "koala");
        when(passwordAuthManager.authenticate(any())).thenReturn(mock(UaaAuthentication.class));
        UaaAuthentication clientAuthentication = mock(UaaAuthentication.class);
        UaaAuthenticationDetails uaaAuthenticationDetails = mock(UaaAuthenticationDetails.class);
        AuthorizationRequest authorizationRequest = mock(AuthorizationRequest.class);
        when(clientAuthentication.getDetails()).thenReturn(uaaAuthenticationDetails);
        when(clientAuthentication.isAuthenticated()).thenReturn(true);
        when((uaaAuthenticationDetails.getAuthenticationMethod())).thenReturn(CLIENT_AUTH_NONE);
        when(requestFactory.createAuthorizationRequest(anyMap())).thenReturn(authorizationRequest);
        SecurityContextHolder.getContext().setAuthentication(clientAuthentication);
        filter.doFilter(request, response, chain);
        verify(clientAuthentication, atLeast(1)).getDetails();
        verify(filter, times(1)).attemptTokenAuthentication(same(request), same(response));
        verify(passwordAuthManager, times(1)).authenticate(any());
        verify(authorizationRequest, times(1)).getExtensions();
        verifyNoInteractions(externalOAuthAuthenticationManager);
    }

    @Test
    void attemptSamlAssertionAuthentication() throws Exception {
        request.addParameter(GRANT_TYPE, GRANT_TYPE_SAML2_BEARER);
        request.addParameter("assertion", "saml-assertion-value-here");
        filter.doFilter(request, response, chain);

        verify(filter, times(1)).attemptTokenAuthentication(same(request), same(response));
        verify(saml2BearerGrantAuthenticationConverter, times(1)).convert(same(request));
        verifyNoInteractions(passwordAuthManager);
        verifyNoInteractions(externalOAuthAuthenticationManager);
        verify(saml2BearerGrantAuthenticationConverter, times(1)).convert(same(request));
    }

    @Test
    void samlAssertionMissing() throws Exception {
        request.addParameter(GRANT_TYPE, GRANT_TYPE_SAML2_BEARER);
        filter.doFilter(request, response, chain);

        verify(filter, times(1)).attemptTokenAuthentication(same(request), same(response));
        verifyNoInteractions(externalOAuthAuthenticationManager);
        verifyNoInteractions(passwordAuthManager);
        verifyNoInteractions(externalOAuthAuthenticationManager);
        verifyNoInteractions(saml2BearerGrantAuthenticationConverter);

        ArgumentCaptor<AuthenticationException> exceptionArgumentCaptor = ArgumentCaptor.forClass(AuthenticationException.class);
        verify(entryPoint, times(1)).commence(same(request), same(response), exceptionArgumentCaptor.capture());
        assertThat(exceptionArgumentCaptor.getValue())
                .hasMessage("SAML Assertion is missing")
                .isInstanceOf(InsufficientAuthenticationException.class);
    }

    @Test
    void attemptJwtTokenAuthentication() throws Exception {
        support = new TokenTestSupport(null, null);
        String idToken = support.getIdTokenAsString(Collections.singletonList(OPENID));
        request.addParameter(GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        request.addParameter("assertion", idToken);
        filter.doFilter(request, response, chain);
        verify(filter, times(1)).attemptTokenAuthentication(same(request), same(response));
        ArgumentCaptor<ExternalOAuthCodeToken> authenticateData = ArgumentCaptor.forClass(ExternalOAuthCodeToken.class);
        verify(externalOAuthAuthenticationManager, times(1)).authenticate(authenticateData.capture());
        verify(externalOAuthAuthenticationManager, times(1)).getOidcProxyIdpForTokenExchange(request);
        verifyNoInteractions(passwordAuthManager);
        verifyNoMoreInteractions(externalOAuthAuthenticationManager);
        assertThat(authenticateData.getValue().getIdToken()).isEqualTo(idToken);
        assertThat(authenticateData.getValue().getOrigin()).isNull();
    }

    @Test
    void attemptJwtTokenProxiedAuthentication() throws Exception {
        support = new TokenTestSupport(null, null);
        String idToken = support.getIdTokenAsString(Collections.singletonList(OPENID));
        request.addParameter(GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        request.addParameter("assertion", idToken);
        UaaAuthenticationDetailsSource uaaAuthenticationDetailsSource = new UaaAuthenticationDetailsSource();
        UaaAuthenticationDetails uaaAuthenticationDetails = uaaAuthenticationDetailsSource.buildDetails(request);
        IdentityProvider identityProvider = mock(IdentityProvider.class);
        doReturn(identityProvider).when(externalOAuthAuthenticationManager).getOidcProxyIdpForTokenExchange(request);
        filter.setAuthenticationDetailsSource(uaaAuthenticationDetailsSource);

        filter.doFilter(request, response, chain);
        verify(filter, times(1)).attemptTokenAuthentication(same(request), same(response));
        ArgumentCaptor<ExternalOAuthCodeToken> authenticateData = ArgumentCaptor.forClass(ExternalOAuthCodeToken.class);
        verify(externalOAuthAuthenticationManager, times(1)).authenticate(authenticateData.capture());
        verify(externalOAuthAuthenticationManager, times(1)).getOidcProxyIdpForTokenExchange(request);
        verify(externalOAuthAuthenticationManager, times(1)).oidcJwtBearerGrant(uaaAuthenticationDetails, identityProvider, idToken);
        verifyNoInteractions(passwordAuthManager);
        verifyNoMoreInteractions(externalOAuthAuthenticationManager);
        assertThat(authenticateData.getValue().getIdToken()).isEqualTo(idToken);
        assertThat(authenticateData.getValue().getOrigin()).isNull();
    }

    @Test
    void jwtAssertionMissing() throws Exception {
        request.addParameter(GRANT_TYPE, GRANT_TYPE_JWT_BEARER);
        filter.doFilter(request, response, chain);
        verify(filter, times(1)).attemptTokenAuthentication(same(request), same(response));
        verifyNoInteractions(externalOAuthAuthenticationManager);
        verifyNoInteractions(passwordAuthManager);
        verifyNoInteractions(externalOAuthAuthenticationManager);
        ArgumentCaptor<AuthenticationException> exceptionArgumentCaptor = ArgumentCaptor.forClass(AuthenticationException.class);
        verify(entryPoint, times(1)).commence(same(request), same(response), exceptionArgumentCaptor.capture());
        assertThat(exceptionArgumentCaptor.getValue()).isInstanceOf(InsufficientAuthenticationException.class);
        assertThat(exceptionArgumentCaptor.getValue().getMessage()).isEqualTo("Assertion is missing");
    }

    @Test
    void attemptTokenExchangeAuthenticationWithIdToken() throws Exception {
        support = new TokenTestSupport(null, null);
        String idToken = support.getIdTokenAsString(Collections.singletonList(OPENID));
        request.addParameter(GRANT_TYPE, GRANT_TYPE_TOKEN_EXCHANGE);
        request.addParameter("subject_token", idToken);
        request.addParameter("subject_token_type", TOKEN_TYPE_ID);
        filter.doFilter(request, response, chain);
        verify(filter, times(1)).attemptTokenAuthentication(same(request), same(response));
        ArgumentCaptor<TokenExchangeData> authenticateData = ArgumentCaptor.forClass(TokenExchangeData.class);
        verify(tokenExchangeAuthenticationManager, times(1)).authenticate(authenticateData.capture());
        verifyNoInteractions(externalOAuthAuthenticationManager);
        verifyNoInteractions(passwordAuthManager);
        verifyNoMoreInteractions(tokenExchangeAuthenticationManager);
        assertThat(authenticateData.getValue().getIdToken()).isEqualTo(idToken);
        assertThat(authenticateData.getValue().getAccessToken()).isNull();
        assertThat(authenticateData.getValue().getOrigin()).isNull();
    }

    @Test
    void attemptTokenExchangeAuthenticationWithAccessToken() throws Exception {
        support = new TokenTestSupport(null, null);
        String idToken = support.getIdTokenAsString(Collections.singletonList(OPENID));
        request.addParameter(GRANT_TYPE, GRANT_TYPE_TOKEN_EXCHANGE);
        request.addParameter("subject_token", idToken);
        request.addParameter("subject_token_type", TOKEN_TYPE_ACCESS);
        filter.doFilter(request, response, chain);
        verify(filter, times(1)).attemptTokenAuthentication(same(request), same(response));
        ArgumentCaptor<TokenExchangeData> authenticateData = ArgumentCaptor.forClass(TokenExchangeData.class);
        verify(tokenExchangeAuthenticationManager, times(1)).authenticate(authenticateData.capture());
        verifyNoInteractions(externalOAuthAuthenticationManager);
        verifyNoInteractions(passwordAuthManager);
        verifyNoMoreInteractions(tokenExchangeAuthenticationManager);
        assertThat(authenticateData.getValue().getAccessToken()).isEqualTo(idToken);
        assertThat(authenticateData.getValue().getIdToken()).isNull();
        assertThat(authenticateData.getValue().getOrigin()).isNull();
    }

    @Test
    void tokenExchangeSubjectTokenMissing() throws Exception {
        request.addParameter(GRANT_TYPE, GRANT_TYPE_TOKEN_EXCHANGE);
        filter.doFilter(request, response, chain);
        verify(filter, times(1)).attemptTokenAuthentication(same(request), same(response));
        verifyNoInteractions(externalOAuthAuthenticationManager);
        verifyNoInteractions(passwordAuthManager);
        verifyNoInteractions(tokenExchangeAuthenticationManager);
        ArgumentCaptor<AuthenticationException> exceptionArgumentCaptor = ArgumentCaptor.forClass(AuthenticationException.class);
        verify(entryPoint, times(1)).commence(same(request), same(response), exceptionArgumentCaptor.capture());
        assertThat(exceptionArgumentCaptor.getValue()).isInstanceOf(InsufficientAuthenticationException.class);
        assertThat(exceptionArgumentCaptor.getValue().getMessage()).isEqualTo("Invalid or missing subject_token");
    }
}
