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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.web.savedrequest.SavedRequest;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpSession;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.FORM_REDIRECT_PARAMETER;
import static org.cloudfoundry.identity.uaa.web.UaaSavedRequestAwareAuthenticationSuccessHandler.URI_OVERRIDE_ATTRIBUTE;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class UaaSavedRequestAwareAuthenticationSuccessHandlerTests {

    private static final String SPRING_SECURITY_SAVED_REQUEST = "SPRING_SECURITY_SAVED_REQUEST";

    MockHttpServletRequest request;
    UaaSavedRequestAwareAuthenticationSuccessHandler handler;

    @BeforeEach
    void setUp() {
        request = new MockHttpServletRequest();
        handler = new UaaSavedRequestAwareAuthenticationSuccessHandler();
    }

    @Test
    void allow_url_override() {
        String overrideUrl = "https://test.com";
        request.setAttribute(URI_OVERRIDE_ATTRIBUTE, overrideUrl);
        assertThat(handler.determineTargetUrl(request, new MockHttpServletResponse())).isEqualTo(overrideUrl);
    }

    @Test
    void form_parameter_is_overridden() {
        request.setParameter(FORM_REDIRECT_PARAMETER, "https://test.com");
        String overrideUrl = "https://override.test.com";
        request.setAttribute(URI_OVERRIDE_ATTRIBUTE, overrideUrl);
        assertThat(handler.determineTargetUrl(request, new MockHttpServletResponse())).isEqualTo(overrideUrl);
    }

    @Test
    void validFormRedirectIsReturned() {
        String redirectUri = request.getScheme() + "://" + request.getServerName() + "/test";

        request.setParameter(FORM_REDIRECT_PARAMETER, redirectUri);
        assertThat(handler.determineTargetUrl(request, new MockHttpServletResponse())).isEqualTo(redirectUri);
    }

    @Test
    void invalidFormRedirectIsNotReturned() {
        String redirectUri = "https://test.com/test";

        request.setParameter(FORM_REDIRECT_PARAMETER, redirectUri);
        assertThat(handler.determineTargetUrl(request, new MockHttpServletResponse())).isEqualTo("/");
    }

    @Test
    void onAuthenticationSuccess_noSavedRequest_hasRelayStateUrl() throws ServletException, IOException {
        String redirectUri = "https://test.com/test2";
        request.setParameter(Saml2ParameterNames.RELAY_STATE, redirectUri);

        var response = new MockHttpServletResponse();
        var authentication = mock(Authentication.class);
        handler.onAuthenticationSuccess(request, response, authentication);

        assertThat(response.getRedirectedUrl()).isEqualTo(redirectUri);
    }

    @Test
    void onAuthenticationSuccess_noSavedRequest_noRelayStateUrl() throws ServletException, IOException {
        request.setParameter(Saml2ParameterNames.RELAY_STATE, "123");
        request.getSession().setAttribute("SPRING_SECURITY_LAST_EXCEPTION", "exception");

        var response = new MockHttpServletResponse();
        var authentication = mock(Authentication.class);

        handler.onAuthenticationSuccess(request, response, authentication);

        assertThat(response.getRedirectedUrl()).isEqualTo("/");
        // Clears Authentication Attributes
        assertThat(request.getSession().getAttribute("SPRING_SECURITY_LAST_EXCEPTION")).isNull();
    }

    @Test
    void onAuthenticationSuccess_withSavedRequest_targetUrlParameter() throws ServletException, IOException {
        String redirectUri = "https://test.com/test3";
        SavedRequest savedRequest = mock(SavedRequest.class);
        when(savedRequest.getRedirectUrl()).thenReturn(redirectUri);

        HttpSession session = request.getSession();
        session.setAttribute(SPRING_SECURITY_SAVED_REQUEST, savedRequest);

        var response = new MockHttpServletResponse();
        var authentication = mock(Authentication.class);

        handler.onAuthenticationSuccess(request, response, authentication);
        assertThat(response.getRedirectedUrl()).isEqualTo(redirectUri);
    }
}
