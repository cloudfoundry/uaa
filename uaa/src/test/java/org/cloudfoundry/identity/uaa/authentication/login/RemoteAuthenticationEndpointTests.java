/*******************************************************************************
 *     Cloud Foundry 
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.authentication.login;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.cloudfoundry.identity.uaa.authentication.AccountNotVerifiedException;
import org.cloudfoundry.identity.uaa.authentication.RemoteAuthenticationEndpoint;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Luke Taylor
 */
public class RemoteAuthenticationEndpointTests {
    private Authentication success;
    private RemoteAuthenticationEndpoint endpoint;
    private AuthenticationManager am;
    private AuthenticationManager loginAuthMgr;
    private OAuth2Authentication loginAuthentication;

    @Before
    public void setUp() throws Exception {
        UaaPrincipal principal = new UaaPrincipal("user-id-001", "joe", "joe@example.com", OriginKeys.UAA, null, null);
        success = new UsernamePasswordAuthenticationToken(principal, null);

        loginAuthMgr = mock(AuthenticationManager.class);
        am = mock(AuthenticationManager.class);
        endpoint = new RemoteAuthenticationEndpoint(am);
        endpoint.setLoginAuthenticationManager(loginAuthMgr);
        loginAuthentication = mock(OAuth2Authentication.class);
    }

    @Test
    public void successfulAuthenticationGives200Status() throws Exception {

        when(am.authenticate(any(Authentication.class))).thenReturn(success);
        @SuppressWarnings("rawtypes")
        ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe","joespassword");
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

    @Test
    public void accountNotVerifiedExceptionGives403Status() throws Exception {
        when(am.authenticate(any(Authentication.class))).thenThrow(new AccountNotVerifiedException("failed"));
        @SuppressWarnings("rawtypes")
        ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe","joespassword");
        assertEquals(HttpStatus.FORBIDDEN, response.getStatusCode());
    }

    @Test
    public void authenticationExceptionGives401Status() throws Exception {
        when(am.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException("failed"));
        @SuppressWarnings("rawtypes")
        ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe","joespassword");
        assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());
    }

    @Test
    public void otherExceptionGives500Status() throws Exception {
        when(am.authenticate(any(Authentication.class))).thenThrow(new RuntimeException("error"));
        @SuppressWarnings("rawtypes")
        ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe","joespassword");
        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
    }

    @Test
    public void successfulLoginAuthenticationInvokesLoginAuthManager() throws Exception {
        SecurityContextHolder.getContext().setAuthentication(loginAuthentication);
        when(am.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException("Invalid authentication manager invoked"));
        when(loginAuthMgr.authenticate(any(Authentication.class))).thenReturn(new UsernamePasswordAuthenticationToken("joe", null));
        when(loginAuthentication.isClientOnly()).thenReturn(Boolean.TRUE);
        @SuppressWarnings("rawtypes")
        ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe","origin", null);
        assertEquals(HttpStatus.OK, response.getStatusCode());
    }

}
