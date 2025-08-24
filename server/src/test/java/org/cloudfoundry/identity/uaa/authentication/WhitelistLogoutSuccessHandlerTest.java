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

import org.cloudfoundry.identity.uaa.client.UaaClientDetails;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.Collections;

import static java.util.Collections.emptyList;
import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.CLIENT_ID;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(PollutionPreventionExtension.class)
class WhitelistLogoutSuccessHandlerTest {

    private WhitelistLogoutSuccessHandler handler;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;
    private MultitenantClientServices clientDetailsService;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        UaaClientDetails client = new UaaClientDetails(CLIENT_ID, "", "", "", "", "http://*.testing.com,http://testing.com");
        clientDetailsService = mock(MultitenantClientServices.class);
        handler = new WhitelistLogoutSuccessHandler(emptyList());
        handler.setDefaultTargetUrl("/login");
        handler.setAlwaysUseDefaultTargetUrl(true);
        handler.setTargetUrlParameter("redirect");
        when(clientDetailsService.loadClientByClientId(CLIENT_ID, "uaa")).thenReturn(client);
        handler.setClientDetailsService(clientDetailsService);
    }

    @Test
    void default_redirect_uri() {
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("/login");
        handler.setAlwaysUseDefaultTargetUrl(false);
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("/login");
    }

    @Test
    void whitelist_reject() {
        handler.setWhitelist(Collections.singletonList("http://testing.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter("redirect", "http://testing.com");
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("http://testing.com");
        request.setParameter("redirect", "http://www.testing.com");
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("/login");
    }

    @Test
    void open_redirect_no_longer_allowed() {
        handler.setWhitelist(null);
        handler.setAlwaysUseDefaultTargetUrl(false);
        handler.setDefaultTargetUrl("/login");
        request.setParameter("redirect", "http://testing.com");
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("/login");
        request.setParameter("redirect", "http://www.testing.com");
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("/login");
    }

    @Test
    void whitelist_redirect() {
        handler.setWhitelist(Collections.singletonList("http://somethingelse.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter("redirect", "http://somethingelse.com");
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("http://somethingelse.com");
    }

    @Test
    void whitelist_redirect_with_wildcard() {
        handler.setWhitelist(Collections.singletonList("http://*.somethingelse.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter("redirect", "http://www.somethingelse.com");
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("http://www.somethingelse.com");
    }

    @Test
    void client_redirect() {
        handler.setWhitelist(Collections.singletonList("http://somethingelse.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter("redirect", "http://testing.com");
        request.setParameter(CLIENT_ID, CLIENT_ID);
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("http://testing.com");
    }

    @Test
    void client_not_found_exception() {
        when(clientDetailsService.loadClientByClientId(eq("test"), any())).thenThrow(new NoSuchClientException("test"));
        handler.setWhitelist(Collections.singletonList("http://testing.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter("redirect", "http://notwhitelisted.com");
        request.setParameter(CLIENT_ID, "test");
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("/login");
        verify(clientDetailsService).loadClientByClientId("test", "uaa");
    }

    @Test
    void client_redirect_using_wildcard() {
        handler.setWhitelist(Collections.singletonList("http://testing.com"));
        handler.setAlwaysUseDefaultTargetUrl(false);
        request.setParameter(CLIENT_ID, CLIENT_ID);
        request.setParameter("redirect", "http://www.testing.com");
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("http://www.testing.com");
    }
}
