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

import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;

/**
 * @author Dave Syer
 * 
 */
public class JsonAwareAccessDeniedHandlerTests {

	private JsonAwareAccessDeniedHandler entryPoint = new JsonAwareAccessDeniedHandler();

	private MockHttpServletRequest request = new MockHttpServletRequest();

	private MockHttpServletResponse response = new MockHttpServletResponse();

	@Test
	public void testCommenceWithJson() throws Exception {
		request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
		entryPoint.handle(request, response, new AccessDeniedException("Bad"));
		assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
		assertEquals("{\"error\":\"Bad\"}", response.getContentAsString());
		assertEquals(null, response.getErrorMessage());
	}

	@Test
	public void testCommenceWithEmptyAccept() throws Exception {
		entryPoint.handle(request, response, new AccessDeniedException("Bad"));
		assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
		assertEquals("Bad", response.getErrorMessage());
	}

	@Test
	public void testCommenceWithHtmlAccept() throws Exception {
		request.addHeader("Accept", MediaType.TEXT_HTML_VALUE);
		entryPoint.handle(request, response, new AccessDeniedException("Bad"));
		assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
		assertEquals("Bad", response.getErrorMessage());
	}

	@Test
	public void testCommenceWithHtmlAndJsonAccept() throws Exception {
		request.addHeader("Accept", String.format("%s,%s", MediaType.TEXT_HTML_VALUE, MediaType.APPLICATION_JSON));
		entryPoint.handle(request, response, new AccessDeniedException("Bad"));
		assertEquals(HttpServletResponse.SC_FORBIDDEN, response.getStatus());
		assertEquals(null, response.getErrorMessage());
	}

}
