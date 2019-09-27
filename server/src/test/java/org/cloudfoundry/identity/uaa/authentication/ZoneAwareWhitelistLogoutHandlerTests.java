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

import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.oauth2.provider.NoSuchClientException;
import org.springframework.security.oauth2.provider.client.BaseClientDetails;

import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.security.oauth2.common.util.OAuth2Utils.CLIENT_ID;


public class ZoneAwareWhitelistLogoutHandlerTests {

    private MockHttpServletRequest request = new MockHttpServletRequest();
    private MockHttpServletResponse response = new MockHttpServletResponse();
    private BaseClientDetails client = new BaseClientDetails(CLIENT_ID, "", "", "", "", "http://*.testing.com,http://testing.com");
    private MultitenantClientServices clientDetailsService =  mock(MultitenantClientServices.class);
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
        handler = new ZoneAwareWhitelistLogoutHandler(clientDetailsService);
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

}
