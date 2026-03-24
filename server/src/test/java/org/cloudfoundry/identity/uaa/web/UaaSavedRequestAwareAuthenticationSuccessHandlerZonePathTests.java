/*
 * ****************************************************************************
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
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.web;

import org.cloudfoundry.identity.uaa.util.ZoneRequestPathMode;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.cloudfoundry.identity.uaa.extensions.EnabledIfZonePathsEnabled;

import jakarta.servlet.ServletException;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Zone-path awareness for {@link UaaSavedRequestAwareAuthenticationSuccessHandler}.
 * ZONE_PATH uses context path (via {@link ZoneRequestPathMode#applyRequestPath}); the handler returns
 * context-relative "/" and RedirectStrategy prepends the request's context path for the final redirect URL.
 */
@EnabledIfZonePathsEnabled
class UaaSavedRequestAwareAuthenticationSuccessHandlerZonePathTests {

    private static final String SPRING_SECURITY_SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST";

    private MockHttpServletRequest request;
    private UaaSavedRequestAwareAuthenticationSuccessHandler handler;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        handler = new UaaSavedRequestAwareAuthenticationSuccessHandler();
    }

    @AfterEach
    void tearDown() {
        IdentityZoneHolder.clear();
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void determineTargetUrl_with_no_override_returns_zone_aware_default(ZoneRequestPathMode mode) {
        mode.setZone();
        mode.applyRequestPath(request, "/login.do");
        // Handler returns context-relative default "/"; zone-aware redirect comes from RedirectStrategy
        // prepending request.getContextPath() (which for ZONE_PATH is /z/test-zone, set by applyRequestPath).
        assertThat(handler.determineTargetUrl(request, new MockHttpServletResponse())).isEqualTo("/");
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void determineTargetUrl_with_context_path_returns_zone_aware_default(ZoneRequestPathMode mode) {
        mode.setZone();
        request.setContextPath("/uaa");
        mode.applyRequestPath(request, "/login.do");
        // Handler returns context-relative "/"; RedirectStrategy prepends context path (e.g. /uaa/z/test-zone).
        assertThat(handler.determineTargetUrl(request, new MockHttpServletResponse())).isEqualTo("/");
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void onAuthenticationSuccess_noSavedRequest_redirects_to_zone_aware_default(ZoneRequestPathMode mode) throws ServletException, IOException {
        mode.setZone();
        mode.applyRequestPath(request, "/login.do");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = mock(Authentication.class);

        handler.onAuthenticationSuccess(request, response, authentication);

        String expected = mode.redirectPrefix().isEmpty() ? "/" : mode.redirectPrefix() + "/";
        assertThat(response.getRedirectedUrl()).isEqualTo(expected);
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void onAuthenticationSuccess_noSavedRequest_with_context_path_redirects_to_zone_aware_default(ZoneRequestPathMode mode) throws ServletException, IOException {
        mode.setZone();
        request.setContextPath("/uaa");
        mode.applyRequestPath(request, "/login.do");
        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = mock(Authentication.class);

        handler.onAuthenticationSuccess(request, response, authentication);

        // RedirectStrategy prepends context path: DEFAULT -> "/uaa/", ZONE_PATH -> "/uaa/z/test-zone/"
        String expected = mode.redirectPrefix().isEmpty() ? "/uaa/" : "/uaa" + mode.redirectPrefix() + "/";
        assertThat(response.getRedirectedUrl()).isEqualTo(expected);
    }

    @ParameterizedTest
    @EnumSource(ZoneRequestPathMode.class)
    void onAuthenticationSuccess_withSavedRequest_redirects_to_saved_url(ZoneRequestPathMode mode) throws ServletException, IOException {
        mode.setZone();
        mode.applyRequestPath(request, "/login.do");
        // DEFAULT: no zone path in URL; ZONE_PATH: zone path in path
        String savedRedirectUrl = mode.redirectPrefix().isEmpty()
                ? "http://localhost/oauth/authorize?client_id=admin"
                : "http://localhost" + mode.redirectPrefix() + "/oauth/authorize?client_id=admin";
        org.springframework.security.web.savedrequest.SavedRequest savedRequest =
                mock(org.springframework.security.web.savedrequest.SavedRequest.class);
        when(savedRequest.getRedirectUrl()).thenReturn(savedRedirectUrl);
        request.getSession(true).setAttribute(SPRING_SECURITY_SAVED_REQUEST, savedRequest);

        MockHttpServletResponse response = new MockHttpServletResponse();
        Authentication authentication = mock(Authentication.class);

        handler.onAuthenticationSuccess(request, response, authentication);

        assertThat(response.getRedirectedUrl()).isEqualTo(savedRedirectUrl);
    }
}
