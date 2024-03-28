/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
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

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.oauth.KeyInfoService;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthLogoutHandler;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.client.UaaClientDetails;

import javax.servlet.ServletException;
import java.io.IOException;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;


public class ZoneAwareWhitelistLogoutHandlerTests {

    private MockHttpServletRequest request = new MockHttpServletRequest();
    private MockHttpServletResponse response = new MockHttpServletResponse();
    private UaaClientDetails client = new UaaClientDetails(CLIENT_ID, "", "", "", "", "http://*.testing.com,http://testing.com");
    private MultitenantClientServices clientDetailsService =  mock(MultitenantClientServices.class);
    private ExternalOAuthLogoutHandler oAuthLogoutHandler = mock(ExternalOAuthLogoutHandler.class);
    private KeyInfoService keyInfoService = mock(KeyInfoService.class);
    private ZoneAwareWhitelistLogoutHandler handler;
    IdentityZoneConfiguration configuration = new IdentityZoneConfiguration();
    IdentityZoneConfiguration original;


    @Before
    public void setUp() {
        original = IdentityZone.getUaa().getConfig();
        configuration.getLinks().getLogout()
            .setRedirectUrl("/login")
            .setDisableRedirectParameter(true)
            .setRedirectParameterName("redirect");
        when(clientDetailsService.loadClientByClientId(CLIENT_ID, "uaa")).thenReturn(client);
        handler = new ZoneAwareWhitelistLogoutHandler(clientDetailsService, oAuthLogoutHandler, keyInfoService);
        IdentityZoneHolder.get().setConfig(configuration);
    }

    @After
    public void tearDown() {
        IdentityZoneHolder.clear();
        IdentityZone.getUaa().setConfig(original);
    }

    @Test
    public void test_null_config_defaults() throws Exception {
        IdentityZoneHolder.get().setConfig(null);
        test_default_redirect_uri();
    }


    @Test
    public void test_default_redirect_uri() {
        assertEquals("/login", handler.determineTargetUrl(request, response));
        assertEquals("/login", handler.determineTargetUrl(request, response));
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        assertEquals("/login", handler.determineTargetUrl(request, response));
    }

    @Test
    public void test_whitelist_reject() {
        configuration.getLinks().getLogout().setWhitelist(Collections.singletonList("http://testing.com"));
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        request.setParameter("redirect", "http://testing.com");
        assertEquals("http://testing.com", handler.determineTargetUrl(request, response));
        request.setParameter("redirect", "http://www.testing.com");
        assertEquals("/login", handler.determineTargetUrl(request, response));
    }

    @Test
    public void test_open_redirect_no_longer_allowed() {
        configuration.getLinks().getLogout().setWhitelist(null);
        configuration.getLinks().getLogout().setRedirectUrl("/login");
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        request.setParameter("redirect", "http://testing.com");
        assertEquals("/login", handler.determineTargetUrl(request, response));
        request.setParameter("redirect", "http://www.testing.com");
        assertEquals("/login", handler.determineTargetUrl(request, response));
    }

    @Test
    public void test_whitelist_redirect() {
        configuration.getLinks().getLogout().setWhitelist(Collections.singletonList("http://somethingelse.com"));
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        request.setParameter("redirect", "http://somethingelse.com");
        assertEquals("http://somethingelse.com", handler.determineTargetUrl(request, response));
    }

    @Test
    public void test_whitelist_redirect_with_wildcard() {
        configuration.getLinks().getLogout().setWhitelist(Collections.singletonList("http://*.somethingelse.com"));
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        request.setParameter("redirect", "http://www.somethingelse.com");
        assertEquals("http://www.somethingelse.com", handler.determineTargetUrl(request, response));
    }

    @Test
    public void test_client_redirect() {
        configuration.getLinks().getLogout().setWhitelist(Collections.singletonList("http://somethingelse.com"));
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        request.setParameter("redirect", "http://testing.com");
        request.setParameter(CLIENT_ID, CLIENT_ID);
        assertEquals("http://testing.com", handler.determineTargetUrl(request, response));
    }

    @Test
    public void client_not_found_exception() {
        when(clientDetailsService.loadClientByClientId("test", "uaa")).thenThrow(new NoSuchClientException("test"));
        configuration.getLinks().getLogout().setWhitelist(Collections.singletonList("http://testing.com"));
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        request.setParameter("redirect", "http://notwhitelisted.com");
        request.setParameter(CLIENT_ID, "test");
        assertEquals("/login", handler.determineTargetUrl(request, response));
    }

    @Test
    public void test_client_redirect_using_wildcard() {
        configuration.getLinks().getLogout().setWhitelist(Collections.singletonList("http://testing.com"));
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        request.setParameter(CLIENT_ID, CLIENT_ID);
        request.setParameter("redirect", "http://www.testing.com");
        assertEquals("http://www.testing.com", handler.determineTargetUrl(request, response));
    }

    @Test
    public void test_external_client_redirect() {
        configuration.getLinks().getLogout().setWhitelist(Collections.singletonList("http://somethingelse.com"));
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        when(oAuthLogoutHandler.getLogoutUrl(null)).thenReturn("");
        when(oAuthLogoutHandler.constructOAuthProviderLogoutUrl(request, "", null)).thenReturn("/login");
        request.setParameter("redirect", "http://testing.com");
        request.setParameter(CLIENT_ID, CLIENT_ID);
        assertEquals("/login", handler.determineTargetUrl(request, response));
    }

    @Test
    public void test_external_logout() throws ServletException, IOException {
        when(oAuthLogoutHandler.getLogoutUrl(null)).thenReturn("");
        when(oAuthLogoutHandler.getPerformRpInitiatedLogout(null)).thenReturn(true);
        handler.onLogoutSuccess(request, response, null);
        verify(oAuthLogoutHandler, times(1)).onLogoutSuccess(request, response, null);
    }

    @Test
    public void test_does_not_external_logout() throws ServletException, IOException {
        when(oAuthLogoutHandler.getLogoutUrl(null)).thenReturn("");
        when(oAuthLogoutHandler.getPerformRpInitiatedLogout(null)).thenReturn(false);
        handler.onLogoutSuccess(request, response, null);
        verify(oAuthLogoutHandler, times(0)).onLogoutSuccess(request, response, null);
    }

    @Test
    public void test_does_not_external_logout_when_logout_url_is_null() throws ServletException, IOException {
        when(oAuthLogoutHandler.getLogoutUrl(null)).thenReturn(null);
        when(oAuthLogoutHandler.getPerformRpInitiatedLogout(null)).thenReturn(true);
        handler.onLogoutSuccess(request, response, null);
        verify(oAuthLogoutHandler, times(0)).onLogoutSuccess(request, response, null);
    }

    @Test
    public void test_logout() throws ServletException, IOException {
        handler.onLogoutSuccess(request, response, null);
        verify(oAuthLogoutHandler, times(0)).onLogoutSuccess(request, response, null);
    }
}
