package org.cloudfoundry.identity.uaa.authentication; /*******************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 * <p>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/

import org.cloudfoundry.identity.uaa.authentication.manager.CommonLoginPolicy;
import org.cloudfoundry.identity.uaa.authentication.manager.LoginPolicy.Result;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.web.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import java.io.IOException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

public class ClientParametersAuthenticationFilterTest {

    @Test
    public void doesNotContinueWithFilterChain_IfAuthenticationException() throws IOException, ServletException {
        ClientParametersAuthenticationFilter filter = new ClientParametersAuthenticationFilter();

        AuthenticationEntryPoint authenticationEntryPoint = mock(AuthenticationEntryPoint.class);
        filter.setAuthenticationEntryPoint(authenticationEntryPoint);

        AuthenticationManager clientAuthenticationManager = mock(AuthenticationManager.class);
        filter.setClientAuthenticationManager(clientAuthenticationManager);
        
        CommonLoginPolicy clientLoginPolicy = mock(CommonLoginPolicy.class);
        filter.setLoginPolicy(clientLoginPolicy);
        when(clientLoginPolicy.isAllowed(Mockito.anyString())).thenReturn(new Result(true, 0));

        BadCredentialsException badCredentialsException = new BadCredentialsException("bad credentials");
        when(clientAuthenticationManager.authenticate(Mockito.any())).thenThrow(badCredentialsException);

        MockFilterChain chain = mock(MockFilterChain.class);
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.addHeader("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);
        request.addParameter(AbstractClientParametersAuthenticationFilter.CLIENT_ID, "testClientId");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, chain);

        verify(authenticationEntryPoint).commence(any(request.getClass()), any(response.getClass()), any(BadCredentialsException.class));
        verifyNoMoreInteractions(chain);
    }

}