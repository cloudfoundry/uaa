/*******************************************************************************
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
package org.cloudfoundry.identity.uaa.authentication;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;

import static org.junit.Assert.*;

public class AbstractClientParametersAuthenticationFilterTest {

    private AbstractClientParametersAuthenticationFilter filter;
    private String capturedClientId;

    @Before
    public void setUp() {
        filter = new AbstractClientParametersAuthenticationFilter() {
            @Override
            public void wrapClientCredentialLogin(HttpServletRequest req, HttpServletResponse res, Map<String, String> loginInfo, String clientId) throws IOException, ServletException {
                capturedClientId = clientId;
            }
        };
    }

    @Test
    public void parseClientCredentialsFromHeader() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String encodedClientCredentials = new String(Base64.getEncoder().encode("testClientId:ClIeNtSeCrEt".getBytes()));
        request.addHeader("Authorization", "Basic " + encodedClientCredentials);

        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();

        try {
            filter.doFilter(request, response, chain);
        } catch(Exception ex) {

        }

        assertEquals("testClientId", capturedClientId);
    }

}