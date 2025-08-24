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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import java.io.IOException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class UTF8ConversionFilterTests {

    private MockHttpServletResponse response;
    private MockHttpServletRequest request;
    private UTF8ConversionFilter filter;

    @Mock
    private FilterChain chain;

    @BeforeEach
    void setup() {
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
        filter = new UTF8ConversionFilter();
    }

    private void verifyChain(int count) throws IOException, ServletException {
        filter.doFilter(request, response, chain);
        verify(chain, times(count)).doFilter(any(), any());
        if (count == 0) {
            assertThat(response.getStatus()).isEqualTo(400);
        }
    }

    @Test
    void validateParamsAndContinue() throws Exception {
        verifyChain(1);
    }

    @Test
    void nullCharactersInSingleValueParams_1() throws Exception {
        request.setParameter("test", new String(new char[]{'a', 'b', '\u0000'}));
        verifyChain(0);
    }

    @Test
    void nullCharactersInSingleValueParams_2() throws Exception {
        request.setParameter("test", new String(new char[]{'a', 'b', (char) 0}));
        verifyChain(0);
    }
}
