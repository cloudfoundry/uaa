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
import org.springframework.security.authentication.BadCredentialsException;

/**
 * @author Dave Syer
 * 
 */
public class JsonAwareAuthenticationEntryPointTests {

	private JsonAwareAuthenticationEntryPoint entryPoint = new JsonAwareAuthenticationEntryPoint();

	private MockHttpServletRequest request = new MockHttpServletRequest();

	private MockHttpServletResponse response = new MockHttpServletResponse();

	{
		entryPoint.setRealmName("UAA");
	}

	@Test(expected = IllegalStateException.class)
	public void testAfterPropertiesSet() throws Exception {
		entryPoint = new JsonAwareAuthenticationEntryPoint();
		entryPoint.afterPropertiesSet();
	}

	@Test
	public void testCommenceWithJson() throws Exception {
		request.addHeader("Accept", MediaType.APPLICATION_JSON_VALUE);
		entryPoint.commence(request, response, new BadCredentialsException("Bad"));
		assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
		assertEquals("{\"error\":\"Bad\"}", response.getContentAsString());
		assertEquals(null, response.getErrorMessage());
	}

	@Test
	public void testTypeName() throws Exception {
		entryPoint.setTypeName("Foo");
		entryPoint.commence(request, response, new BadCredentialsException("Bad"));
		assertEquals("Foo realm=\"UAA\"", response.getHeader("WWW-Authenticate"));
	}

	@Test
	public void testCommenceWithEmptyAccept() throws Exception {
		entryPoint.commence(request, response, new BadCredentialsException("Bad"));
		assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
		assertEquals("Bad", response.getErrorMessage());
	}

	@Test
	public void testCommenceWithHtmlAccept() throws Exception {
		request.addHeader("Accept", MediaType.TEXT_HTML_VALUE);
		entryPoint.commence(request, response, new BadCredentialsException("Bad"));
		assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
		assertEquals("Bad", response.getErrorMessage());
	}

	@Test
	public void testCommenceWithHtmlAndJsonAccept() throws Exception {
		request.addHeader("Accept", String.format("%s,%s", MediaType.TEXT_HTML_VALUE, MediaType.APPLICATION_JSON));
		entryPoint.commence(request, response, new BadCredentialsException("Bad"));
		assertEquals(HttpServletResponse.SC_UNAUTHORIZED, response.getStatus());
		assertEquals(null, response.getErrorMessage());
	}

}
