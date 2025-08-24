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
import org.cloudfoundry.identity.uaa.provider.NoSuchClientException;
import org.cloudfoundry.identity.uaa.provider.oauth.ExternalOAuthLogoutSuccessHandler;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.MultitenantClientServices;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.ServletException;
import java.io.IOException;
import java.util.Collections;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.CLIENT_ID;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ZoneAwareWhitelistLogoutSuccessHandlerTests {

    private final MockHttpServletRequest request = new MockHttpServletRequest();
    private final MockHttpServletResponse response = new MockHttpServletResponse();
    private final UaaClientDetails client = new UaaClientDetails(CLIENT_ID, "", "", "", "", "http://*.testing.com,http://testing.com");
    private ZoneAwareWhitelistLogoutSuccessHandler handler;
    IdentityZoneConfiguration configuration = new IdentityZoneConfiguration();
    IdentityZoneConfiguration original;

    @Mock
    private MultitenantClientServices clientDetailsService;
    @Mock
    private ExternalOAuthLogoutSuccessHandler oAuthLogoutHandler;
    @Mock
    private KeyInfoService keyInfoService;

    @BeforeEach
    void setUp() {
        original = IdentityZone.getUaa().getConfig();
        configuration.getLinks().getLogout()
                .setRedirectUrl("/login")
                .setDisableRedirectParameter(true)
                .setRedirectParameterName("redirect");
        handler = new ZoneAwareWhitelistLogoutSuccessHandler(clientDetailsService, oAuthLogoutHandler, keyInfoService);
        IdentityZoneHolder.get().setConfig(configuration);
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
        IdentityZone.getUaa().setConfig(original);
    }

    @Test
    void null_config_defaults() {
        IdentityZoneHolder.get().setConfig(null);
        default_redirect_uri();
    }

    @Test
    void default_redirect_uri() {
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("/login");
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("/login");
    }

    @Test
    void whitelist_reject() {
        configuration.getLinks().getLogout().setWhitelist(Collections.singletonList("http://testing.com"));
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        request.setParameter("redirect", "http://testing.com");
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("http://testing.com");
        request.setParameter("redirect", "http://www.testing.com");
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("/login");
    }

    @Test
    void open_redirect_no_longer_allowed() {
        configuration.getLinks().getLogout().setWhitelist(null);
        configuration.getLinks().getLogout().setRedirectUrl("/login");
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        request.setParameter("redirect", "http://testing.com");
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("/login");
        request.setParameter("redirect", "http://www.testing.com");
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("/login");
    }

    @Test
    void whitelist_redirect() {
        configuration.getLinks().getLogout().setWhitelist(Collections.singletonList("http://somethingelse.com"));
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        request.setParameter("redirect", "http://somethingelse.com");
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("http://somethingelse.com");
    }

    @Test
    void whitelist_redirect_with_wildcard() {
        configuration.getLinks().getLogout().setWhitelist(Collections.singletonList("http://*.somethingelse.com"));
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        request.setParameter("redirect", "http://www.somethingelse.com");
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("http://www.somethingelse.com");
    }

    @Test
    void client_redirect() {
        when(clientDetailsService.loadClientByClientId(CLIENT_ID, "uaa")).thenReturn(client);
        configuration.getLinks().getLogout().setWhitelist(Collections.singletonList("http://somethingelse.com"));
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        request.setParameter("redirect", "http://testing.com");
        request.setParameter(CLIENT_ID, CLIENT_ID);
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("http://testing.com");
    }

    @Test
    void client_not_found_exception() {
        when(clientDetailsService.loadClientByClientId("test", "uaa")).thenThrow(new NoSuchClientException("test"));
        configuration.getLinks().getLogout().setWhitelist(Collections.singletonList("http://testing.com"));
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        request.setParameter("redirect", "http://notwhitelisted.com");
        request.setParameter(CLIENT_ID, "test");
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("/login");
    }

    @Test
    void client_redirect_using_wildcard() {
        when(clientDetailsService.loadClientByClientId(CLIENT_ID, "uaa")).thenReturn(client);
        configuration.getLinks().getLogout().setWhitelist(Collections.singletonList("http://testing.com"));
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        request.setParameter(CLIENT_ID, CLIENT_ID);
        request.setParameter("redirect", "http://www.testing.com");
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("http://www.testing.com");
    }

    @Test
    void external_client_redirect() {
        configuration.getLinks().getLogout().setWhitelist(Collections.singletonList("http://somethingelse.com"));
        configuration.getLinks().getLogout().setDisableRedirectParameter(false);
        when(oAuthLogoutHandler.getLogoutUrl(null)).thenReturn("");
        when(oAuthLogoutHandler.constructOAuthProviderLogoutUrl(request, "", null, null)).thenReturn("/login");
        request.setParameter("redirect", "http://testing.com");
        request.setParameter(CLIENT_ID, CLIENT_ID);
        assertThat(handler.determineTargetUrl(request, response)).isEqualTo("/login");
    }

    /*
     * Parameterized Test replaces the following tests:
     * - external_logout
     * - does_not_external_logout
     * - does_not_external_logout_when_logout_url_is_null
     */
    @ParameterizedTest
    @CsvSource({
            "'',true,1",
            "'',false,0",
            ",true,0"})
    void external_logout(String url, boolean rpInitiated, int onSuccessCalls) throws ServletException, IOException {
        when(oAuthLogoutHandler.getLogoutUrl(null)).thenReturn(url);
        when(oAuthLogoutHandler.getPerformRpInitiatedLogout(null)).thenReturn(rpInitiated);
        handler.onLogoutSuccess(request, response, null);
        verify(oAuthLogoutHandler, times(onSuccessCalls)).onLogoutSuccess(request, response, null);
    }

    @Test
    void logout() throws ServletException, IOException {
        handler.onLogoutSuccess(request, response, null);
        verify(oAuthLogoutHandler, times(0)).onLogoutSuccess(request, response, null);
    }
}
