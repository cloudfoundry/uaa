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

package org.cloudfoundry.identity.uaa.oauth;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.cloudfoundry.identity.uaa.oauth.common.util.OAuth2Utils.RESPONSE_TYPE;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.verify;

class DisableIdTokenResponseTypeFilterTest {

    DisableIdTokenResponseTypeFilter filter;
    DisableIdTokenResponseTypeFilter disabledFilter;
    List<String> applyPaths = Arrays.asList("/oauth/authorze", "/**/oauth/authorize");
    MockHttpServletRequest request = new MockHttpServletRequest();
    MockHttpServletResponse response = new MockHttpServletResponse();
    ArgumentCaptor<HttpServletRequest> captor = ArgumentCaptor.forClass(HttpServletRequest.class);
    FilterChain chain = mock(FilterChain.class);

    @BeforeEach
    void setUp() {
        filter = new DisableIdTokenResponseTypeFilter(false, applyPaths);
        disabledFilter = new DisableIdTokenResponseTypeFilter(true, applyPaths);
        request.setPathInfo("/oauth/authorize");
    }

    @Test
    void isIdTokenDisabled() {
        assertThat(filter.isIdTokenDisabled()).isFalse();
        assertThat(disabledFilter.isIdTokenDisabled()).isTrue();
    }

    @Test
    void applyPath() {
        shouldApplyPath("/oauth/token", false);
        shouldApplyPath("/someotherpath/uaa/oauth/authorize", true);
        shouldApplyPath("/uaa/oauth/authorize", true);
        shouldApplyPath("/oauth/authorize", true);
        shouldApplyPath(null, false);
        shouldApplyPath("", false);
    }

    public void shouldApplyPath(String path, boolean expectedOutCome) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setPathInfo(path);
        assertThat(filter.applyPath(path)).isEqualTo(expectedOutCome);
        assertThat(disabledFilter.applyPath(path)).isEqualTo(expectedOutCome);
    }

    @Test
    void doFilterInternalNOResponseTypeParameter() throws Exception {
        filter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(captor.capture(), any());
        assertThat(captor.getValue()).isSameAs(request);
        reset(chain);

        disabledFilter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(captor.capture(), any());
        assertThat(request).isNotSameAs(captor.getValue());
    }

    @Test
    void doFilterInternalCodeResponseTypeParameter() throws Exception {
        String responseType = "code";
        request.addParameter(RESPONSE_TYPE, responseType);
        filter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(captor.capture(), any());
        assertThat(captor.getValue()).isSameAs(request);
        reset(chain);
        assertThat(captor.getValue().getParameter(RESPONSE_TYPE)).isEqualTo(responseType);
        assertThat(captor.getValue().getParameterMap().get(RESPONSE_TYPE)).hasSize(1);
        assertThat(captor.getValue().getParameterMap().get(RESPONSE_TYPE)[0]).isEqualTo(responseType);
        assertThat(captor.getValue().getParameterValues(RESPONSE_TYPE)).hasSize(1);
        assertThat(captor.getValue().getParameterValues(RESPONSE_TYPE)[0]).isEqualTo(responseType);

        disabledFilter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(captor.capture(), any());
        assertThat(request).isNotSameAs(captor.getValue());
        assertThat(captor.getValue().getParameter(RESPONSE_TYPE)).isEqualTo(responseType);
        assertThat(captor.getValue().getParameterMap().get(RESPONSE_TYPE)).hasSize(1);
        assertThat(captor.getValue().getParameterMap().get(RESPONSE_TYPE)[0]).isEqualTo(responseType);
        assertThat(captor.getValue().getParameterValues(RESPONSE_TYPE)).hasSize(1);
        assertThat(captor.getValue().getParameterValues(RESPONSE_TYPE)[0]).isEqualTo(responseType);
    }

    @Test
    void doFilterInternalCodeAndIdTokenResponseTypeParameter() throws Exception {
        String responseType = "code id_token";
        String removedType = "code";
        validate_filter(responseType, removedType);
    }

    @Test
    void doFilterInternalIdTokenAndCodeResponseTypeParameter() throws Exception {
        String responseType = "code id_token";
        String removedType = "code";
        validate_filter(responseType, removedType);
    }

    @Test
    void doFilterInternalTokenAndIdTokenAndCodeResponseTypeParameter() throws Exception {
        String responseType = "token code id_token";
        String removedType = "token code";
        validate_filter(responseType, removedType);
    }

    public void validate_filter(String responseType, String removedType) throws Exception {
        request.addParameter(RESPONSE_TYPE, responseType);
        filter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(captor.capture(), any());
        assertThat(captor.getValue()).isSameAs(request);
        reset(chain);
        assertThat(captor.getValue().getParameter(RESPONSE_TYPE)).isEqualTo(responseType);
        assertThat(captor.getValue().getParameterMap().get(RESPONSE_TYPE)).hasSize(1);
        assertThat(captor.getValue().getParameterMap().get(RESPONSE_TYPE)[0]).isEqualTo(responseType);
        assertThat(captor.getValue().getParameterValues(RESPONSE_TYPE)).hasSize(1);
        assertThat(captor.getValue().getParameterValues(RESPONSE_TYPE)[0]).isEqualTo(responseType);

        disabledFilter.doFilterInternal(request, response, chain);
        verify(chain).doFilter(captor.capture(), any());
        assertThat(request).isNotSameAs(captor.getValue());
        assertThat(captor.getValue().getParameter(RESPONSE_TYPE)).isEqualTo(removedType);
        assertThat(captor.getValue().getParameterMap().get(RESPONSE_TYPE)).hasSize(1);
        assertThat(captor.getValue().getParameterMap().get(RESPONSE_TYPE)[0]).isEqualTo(removedType);
        assertThat(captor.getValue().getParameterValues(RESPONSE_TYPE)).hasSize(1);
        assertThat(captor.getValue().getParameterValues(RESPONSE_TYPE)[0]).isEqualTo(removedType);
    }
}
