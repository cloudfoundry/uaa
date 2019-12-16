/*******************************************************************************
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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.HashMap;

import org.cloudfoundry.identity.uaa.web.ConvertingExceptionView;
import org.cloudfoundry.identity.uaa.web.ExceptionReport;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

/**
 * @author Dave Syer
 * 
 */
public class ConvertingExceptionViewTests {

    private ConvertingExceptionView view;

    private HttpMessageConverter<?>[] messageConverters = new HttpMessageConverter<?>[] { new StringHttpMessageConverter() };

    private MockHttpServletRequest request = new MockHttpServletRequest();

    private MockHttpServletResponse response = new MockHttpServletResponse();

    @Test
    public void testGetContentType() {
        RuntimeException e = new RuntimeException("Unexpected error");
        view = new ConvertingExceptionView(new ResponseEntity<ExceptionReport>(new ExceptionReport(e),
                        HttpStatus.INTERNAL_SERVER_ERROR), messageConverters);
        assertEquals("*/*", view.getContentType());
    }

    @Test
    public void testRender() throws Exception {
        RuntimeException e = new RuntimeException("Unexpected error");
        view = new ConvertingExceptionView(new ResponseEntity<ExceptionReport>(new ExceptionReport(e),
                        HttpStatus.INTERNAL_SERVER_ERROR), messageConverters);
        view.render(new HashMap<String, Object>(), request, response);
        assertNotNull(response.getContentAsString());
    }

}
