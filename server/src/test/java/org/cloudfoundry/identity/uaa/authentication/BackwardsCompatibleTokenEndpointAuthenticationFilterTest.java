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

import org.cloudfoundry.identity.uaa.provider.oauth.XOAuthAuthenticationManager;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2RequestFactory;
import org.springframework.security.saml.SAMLProcessingFilter;

import javax.servlet.FilterChain;

import static org.cloudfoundry.identity.uaa.oauth.token.ClaimConstants.GRANT_TYPE;
import static org.cloudfoundry.identity.uaa.oauth.token.TokenConstants.GRANT_TYPE_SAML2_BEARER;
import static org.junit.Assert.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

public class BackwardsCompatibleTokenEndpointAuthenticationFilterTest {


    private AuthenticationManager passwordAuthManager;
    private OAuth2RequestFactory requestFactory;
    private SAMLProcessingFilter samlAuthFilter;
    private XOAuthAuthenticationManager xoAuthAuthenticationManager;
    private BackwardsCompatibleTokenEndpointAuthenticationFilter filter;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private FilterChain chain;

    @Before
    public void setUp() throws Exception {

        passwordAuthManager = mock(AuthenticationManager.class);
        requestFactory = mock(OAuth2RequestFactory.class);
        samlAuthFilter = mock(SAMLProcessingFilter.class);
        xoAuthAuthenticationManager = mock(XOAuthAuthenticationManager.class);

        filter = spy(
            new BackwardsCompatibleTokenEndpointAuthenticationFilter(
                passwordAuthManager,
                requestFactory,
                samlAuthFilter,
                xoAuthAuthenticationManager
            )
        );

        request = new MockHttpServletRequest("POST", "/oauth/token");
        response = new MockHttpServletResponse();
        chain = mock(FilterChain.class);
    }

    @After
    public void tearDown() throws Exception {
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    public void attempt_password_authentication() throws Exception {
        request.addParameter(GRANT_TYPE, "password");
        request.addParameter("username", "marissa");
        request.addParameter("password", "koala");
        filter.doFilter(request, response, chain);
        verify(filter, times(1)).attemptTokenAuthentication(same(request), same(response));
        verify(passwordAuthManager, times(1)).authenticate(any());
        verifyZeroInteractions(samlAuthFilter);
        verifyZeroInteractions(xoAuthAuthenticationManager);
    }

    @Test
    public void attempt_saml_assertion_authentication() throws Exception {
        request.addParameter(GRANT_TYPE, GRANT_TYPE_SAML2_BEARER);
        request.addParameter("assertion", "saml-assertion-value-here");
        filter.doFilter(request, response, chain);
        verify(filter, times(1)).attemptTokenAuthentication(same(request), same(response));
        verify(samlAuthFilter, times(1)).attemptAuthentication(same(request), same(response));
        verifyZeroInteractions(passwordAuthManager);
        verifyZeroInteractions(xoAuthAuthenticationManager);
    }

    @Test
    public void attempt_jwt_token_authentication() throws Exception {
        fail();
    }

}