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

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Collections;

import static java.util.Collections.EMPTY_LIST;
import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;

@ExtendWith(PollutionPreventionExtension.class)
class WhitelistLogoutHandlerTest {

    private WhitelistLogoutHandler handler;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private BaseClientDetails client;
    private MultitenantClientServices clientDetailsService;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        client = new BaseClientDetails(CLIENT_ID,"","","","","http://*.testing.com,http://testing.com");
        clientDetailsService =  mock(MultitenantClientServices.class);
        handler = new WhitelistLogoutHandler(EMPTY_LIST);
        handler.setDefaultTargetUrl("/login");
        handler.setAlwaysUseDefaultTargetUrl(true);
        handler.setTargetUrlParameter("redirect");
        when(clientDetailsService.loadClientByClientId(CLIENT_ID, "uaa")).thenReturn(client);
        handler.setClientDetailsService(clientDetailsService);
    }

    @Test
    void test_default_redirect_uri() {
        assertEquals("/login", handler.determineTargetUrl(request, response));
        assertEquals("/login", handler.determineTargetUrl(request, response));
        handler.setAlwaysUseDefaultTargetUrl(false);
        assertEquals("/login", handler.determineTargetUrl(request, response));
    }

    @Test
    void test_whitelist_reject() {
        handler.setWhitelist(Collections.singletonList("http://testing.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter("redirect", "http://testing.com");
        assertEquals("http://testing.com", handler.determineTargetUrl(request, response));
        request.setParameter("redirect", "http://www.testing.com");
        assertEquals("/login", handler.determineTargetUrl(request, response));
    }

    @Test
    void test_open_redirect_no_longer_allowed() {
        handler.setWhitelist(null);
        handler.setAlwaysUseDefaultTargetUrl(false);
        handler.setDefaultTargetUrl("/login");
        request.setParameter("redirect", "http://testing.com");
        assertEquals("/login", handler.determineTargetUrl(request, response));
        request.setParameter("redirect", "http://www.testing.com");
        assertEquals("/login", handler.determineTargetUrl(request, response));
    }

    @Test
    void test_whitelist_redirect() {
        handler.setWhitelist(Collections.singletonList("http://somethingelse.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter("redirect", "http://somethingelse.com");
        assertEquals("http://somethingelse.com", handler.determineTargetUrl(request, response));
    }

    @Test
    void test_whitelist_redirect_with_wildcard() {
        handler.setWhitelist(Collections.singletonList("http://*.somethingelse.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter("redirect", "http://www.somethingelse.com");
        assertEquals("http://www.somethingelse.com", handler.determineTargetUrl(request, response));
    }

    @Test
    void test_client_redirect() {
        handler.setWhitelist(Collections.singletonList("http://somethingelse.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter("redirect", "http://testing.com");
        request.setParameter(CLIENT_ID, CLIENT_ID);
        assertEquals("http://testing.com", handler.determineTargetUrl(request, response));
    }

    @Test
    void client_not_found_exception() {
        when(clientDetailsService.loadClientByClientId(eq("test"), any())).thenThrow(new NoSuchClientException("test"));
        handler.setWhitelist(Collections.singletonList("http://testing.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter("redirect", "http://notwhitelisted.com");
        request.setParameter(CLIENT_ID, "test");
        assertEquals("/login", handler.determineTargetUrl(request, response));
        verify(clientDetailsService).loadClientByClientId("test", "uaa");
    }

    @Test
    void test_client_redirect_using_wildcard() {
        handler.setWhitelist(Collections.singletonList("http://testing.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter(CLIENT_ID, CLIENT_ID);
        request.setParameter("redirect", "http://www.testing.com");
        assertEquals("http://www.testing.com", handler.determineTargetUrl(request, response));
    }

}
