/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.authentication;

import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Arrays;

import static java.util.Collections.EMPTY_LIST;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;

public class WhitelistLogoutHandlerTest {

    private WhitelistLogoutHandler handler;
    private MockHttpServletRequest request = new MockHttpServletRequest();
    private MockHttpServletResponse response = new MockHttpServletResponse();
    private BaseClientDetails client = new BaseClientDetails(CLIENT_ID,"","","","","http://*.testing.com,http://testing.com");
    private ClientDetailsService clientDetailsService =  mock(ClientDetailsService.class);

    @Before
    public void setUp() {
        handler = new WhitelistLogoutHandler(EMPTY_LIST);
        handler.setDefaultTargetUrl("/login");
        handler.setAlwaysUseDefaultTargetUrl(true);
        handler.setTargetUrlParameter("redirect");
        when(clientDetailsService.loadClientByClientId(CLIENT_ID)).thenReturn(client);
        handler.setClientDetailsService(clientDetailsService);
    }

    @Test
    public void test_default_redirect_uri() throws Exception {
        assertEquals("/login", handler.determineTargetUrl(request, response));
        assertEquals("/login", handler.determineTargetUrl(request, response));
        handler.setAlwaysUseDefaultTargetUrl(false);
        assertEquals("/login", handler.determineTargetUrl(request, response));
    }

    @Test
    public void test_whitelist_reject() throws Exception {
        handler.setWhitelist(Arrays.asList("http://testing.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter("redirect", "http://testing.com");
        assertEquals("http://testing.com", handler.determineTargetUrl(request, response));
        request.setParameter("redirect", "http://www.testing.com");
        assertEquals("/login", handler.determineTargetUrl(request, response));
    }

    @Test
    public void test_open_redirect_no_longer_allowed() throws Exception {
        handler.setWhitelist(null);
        handler.setAlwaysUseDefaultTargetUrl(false);
        handler.setDefaultTargetUrl("/login");
        request.setParameter("redirect", "http://testing.com");
        assertEquals("/login", handler.determineTargetUrl(request, response));
        request.setParameter("redirect", "http://www.testing.com");
        assertEquals("/login", handler.determineTargetUrl(request, response));
    }

    @Test
    public void test_whitelist_redirect() throws Exception {
        handler.setWhitelist(Arrays.asList("http://somethingelse.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter("redirect", "http://somethingelse.com");
        assertEquals("http://somethingelse.com", handler.determineTargetUrl(request, response));
    }

    @Test
    public void test_whitelist_redirect_with_wildcard() throws Exception {
        handler.setWhitelist(Arrays.asList("http://*.somethingelse.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter("redirect", "http://www.somethingelse.com");
        assertEquals("http://www.somethingelse.com", handler.determineTargetUrl(request, response));
    }

    @Test
    public void test_client_redirect_with_path() throws Exception {
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter("redirect", "http://testing.com/path");
        request.setParameter(CLIENT_ID, CLIENT_ID);
        assertEquals("http://testing.com/path", handler.determineTargetUrl(request, response));
    }

    @Test
    public void test_client_redirect() throws Exception {
        handler.setWhitelist(Arrays.asList("http://somethingelse.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter("redirect", "http://testing.com");
        request.setParameter(CLIENT_ID, CLIENT_ID);
        assertEquals("http://testing.com", handler.determineTargetUrl(request, response));
    }


    @Test
    public void client_not_found_exception() throws Exception {
        when(clientDetailsService.loadClientByClientId("test")).thenThrow(new NoSuchClientException("test"));
        handler.setWhitelist(Arrays.asList("http://testing.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter("redirect", "http://notwhitelisted.com");
        request.setParameter(CLIENT_ID, "test");
        assertEquals("/login", handler.determineTargetUrl(request, response));
    }

    @Test
    public void test_client_redirect_using_wildcard() throws Exception {
        handler.setWhitelist(Arrays.asList("http://testing.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter(CLIENT_ID, CLIENT_ID);
        request.setParameter("redirect", "http://www.testing.com");
        assertEquals("http://www.testing.com", handler.determineTargetUrl(request, response));
    }

}
