/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */

package org.cloudfoundry.identity.uaa.error;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.util.HashMap;

import org.cloudfoundry.identity.uaa.scim.ScimException;
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
	public void testGetContentType() throws Exception {
		ScimException e = new ScimException("Unexpected error", new RuntimeException("foo"), HttpStatus.INTERNAL_SERVER_ERROR);
		view = new ConvertingExceptionView(new ResponseEntity<Exception>(e, e.getStatus()), messageConverters );
		assertEquals("*/*", view.getContentType());
	}

	@Test
	public void testRender() throws Exception {
		ScimException e = new ScimException("Unexpected error", new RuntimeException("foo"), HttpStatus.INTERNAL_SERVER_ERROR);
		view = new ConvertingExceptionView(new ResponseEntity<Exception>(e, e.getStatus()), messageConverters );
		view.render(new HashMap<String, Object>(), request , response);
		assertNotNull(response.getContentAsString());
	}

}
