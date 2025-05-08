/*
 * *****************************************************************************
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
 *******************************************************************************/

package org.cloudfoundry.identity.uaa.error;

import org.cloudfoundry.identity.uaa.web.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.web.ExceptionReport;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import java.util.HashMap;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Dave Syer
 */
class ConvertingExceptionViewTests {

    private ConvertingExceptionView view;

    private final HttpMessageConverter<?>[] messageConverters = new HttpMessageConverter<?>[]{new StringHttpMessageConverter()};

    private final MockHttpServletRequest request = new MockHttpServletRequest();

    private final MockHttpServletResponse response = new MockHttpServletResponse();

    @Test
    void getContentType() {
        RuntimeException e = new RuntimeException("Unexpected error");
        view = new ConvertingExceptionView(new ResponseEntity<>(new ExceptionReport(e),
                HttpStatus.INTERNAL_SERVER_ERROR), messageConverters);
        assertThat(view.getContentType()).isEqualTo(MediaType.APPLICATION_JSON_VALUE);
    }

    @Test
    void render() throws Exception {
        RuntimeException e = new RuntimeException("Unexpected error");
        view = new ConvertingExceptionView(new ResponseEntity<>(new ExceptionReport(e),
                HttpStatus.INTERNAL_SERVER_ERROR), messageConverters);
        view.render(new HashMap<>(), request, response);
        assertThat(response.getContentAsString()).isNotNull();
    }
}
