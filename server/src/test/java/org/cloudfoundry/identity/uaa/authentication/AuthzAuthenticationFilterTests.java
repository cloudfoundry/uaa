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
package org.cloudfoundry.identity.uaa.authentication;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;

public class AuthzAuthenticationFilterTests {

    @Test
    public void authenticatesValidUser() throws Exception {

        String msg = "{ \"username\":\"marissa\", \"password\":\"koala\"}";

        AuthenticationManager am = mock(AuthenticationManager.class);
        Authentication result = mock(Authentication.class);
        when(am.authenticate(any(AuthzAuthenticationRequest.class))).thenReturn(result);
        AuthzAuthenticationFilter filter = new AuthzAuthenticationFilter(am);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/authorize");
        request.setParameter("credentials", msg);
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, new MockFilterChain());

    }
}
