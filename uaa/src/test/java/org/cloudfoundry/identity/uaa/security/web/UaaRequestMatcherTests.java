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
package org.cloudfoundry.identity.uaa.security.web;

import java.util.Collections;

import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.Assert.*;

/**
 */
public class UaaRequestMatcherTests {

	private MockHttpServletRequest request(String path, String accept, String... parameters) {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setContextPath("/ctx");
		request.setRequestURI("/ctx" + path);
		if (accept != null) {
			request.addHeader("Accept", accept);
		}
		for (int i = 0; i < parameters.length; i += 2) {
			String key = parameters[i];
			String value = parameters[i + 1];
			request.addParameter(key, value);
		}
		return request;
	}

	@Test
	public void pathMatcherMatchesExpectedPaths() throws Exception {
		UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
		assertTrue(matcher.matches(request("/somePath", null)));
		assertTrue(matcher.matches(request("/somePath", "application/json")));
		assertTrue(matcher.matches(request("/somePath", "application/html")));
		assertTrue(matcher.matches(request("/somePath/aak", null)));
		assertTrue(matcher.matches(request("/somePath?blah=x", null)));
		// We don't actually want this for anything but it's a consequence of using substring matching
		assertTrue(matcher.matches(request("/somePathOrOther", null)));
	}

	@Test
	public void pathMatcherMatchesExpectedPathsAndAcceptHeaderValues() throws Exception {
		// Accept only JSON
		UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
		matcher.setAccept(MediaType.APPLICATION_JSON);
		assertTrue(matcher.matches(request("/somePath", null)));
		assertTrue(matcher.matches(request("/somePath", "application/json")));
		assertFalse(matcher.matches(request("/somePath", "application/html")));
	}

	@Test
	public void pathMatcherMatchesExpectedPathsAndRequestParameters() throws Exception {
		// Accept only JSON
		UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
		matcher.setAccept(MediaType.APPLICATION_JSON);
		matcher.setParameters(Collections.singletonMap("response_type", "token"));
		assertTrue(matcher.matches(request("/somePath", null, "response_type", "token")));
	}

}
