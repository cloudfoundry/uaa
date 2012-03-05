/*
 * Copyright 2006-2011 the original author or authors.
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
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
