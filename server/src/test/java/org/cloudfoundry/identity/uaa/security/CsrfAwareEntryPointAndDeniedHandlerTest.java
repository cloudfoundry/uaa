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

package org.cloudfoundry.identity.uaa.security;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.csrf.MissingCsrfTokenException;

import jakarta.servlet.http.HttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.AssertionsForClassTypes.assertThatExceptionOfType;

class CsrfAwareEntryPointAndDeniedHandlerTest {

    protected CsrfAwareEntryPointAndDeniedHandler handler = new CsrfAwareEntryPointAndDeniedHandler("/csrf", "/login");
    protected MockHttpServletRequest request = new MockHttpServletRequest();
    protected MockHttpServletResponse response = new MockHttpServletResponse();

    @BeforeEach
    void setUpCsrfAccessDeniedHandler() {
        response.setCommitted(false);
    }

    @AfterEach
    void cleanUpAuth() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void handleWhenNotLoggedInAndNoCsrf() throws Exception {
        AccessDeniedException ex = new MissingCsrfTokenException("something");
        handler.handle(request, response, ex);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FOUND);
        assertThat(ex).isSameAs(request.getAttribute(WebAttributes.ACCESS_DENIED_403));
        assertThat(response.isCommitted()).isTrue();
        assertThat(response.getHeader("Location")).isEqualTo("http://localhost/login");
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_MOVED_TEMPORARILY);
    }

    @Test
    void handleWhenCsrfMissingForJson() throws Exception {
        request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
        AccessDeniedException ex = new MissingCsrfTokenException("something");
        handler.handle(request, response, ex);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        assertThat(response.getContentAsString()).isEqualTo("{\"error\":\"" + ex.getMessage() + "\"}");
        assertThat(response.getErrorMessage()).isNull();
    }

    @Test
    void handleWhenNotLoggedIn() throws Exception {
        AccessDeniedException ex = new AccessDeniedException("something");
        handler.handle(request, response, ex);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FOUND);
        assertThat(ex).isSameAs(request.getAttribute(WebAttributes.ACCESS_DENIED_403));
        assertThat(response.isCommitted()).isTrue();
        assertThat(response.getHeader("Location")).isEqualTo("http://localhost/login");
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_MOVED_TEMPORARILY);
    }

    @Test
    void handleWhenNotLoggedInJson() throws Exception {
        request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
        AccessDeniedException ex = new AccessDeniedException("something");
        handler.handle(request, response, ex);
        assertThat(response.getStatus()).isEqualTo(HttpServletResponse.SC_FORBIDDEN);
        assertThat(response.getContentAsString()).isEqualTo("{\"error\":\"something\"}");
        assertThat(response.getErrorMessage()).isNull();
    }

    @Test
    void nullCsrfUrl() {
        assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> new CsrfAwareEntryPointAndDeniedHandler(null, "/login"));
    }

    @Test
    void invalidCsrfUrl() {
        assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> new CsrfAwareEntryPointAndDeniedHandler("csrf", "/login"));
    }

    @Test
    void nullLoginfUrl() {
        assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> new CsrfAwareEntryPointAndDeniedHandler("/csrf", null));
    }

    @Test
    void invalidLoginUrl() {
        assertThatExceptionOfType(NullPointerException.class).isThrownBy(() -> new CsrfAwareEntryPointAndDeniedHandler("/csrf", "login"));
    }

}