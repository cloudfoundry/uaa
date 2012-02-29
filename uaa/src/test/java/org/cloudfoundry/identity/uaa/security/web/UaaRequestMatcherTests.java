/**
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

	@Test
	public void pathMatcherMatchesWithMultipleAccepts() throws Exception {
		// Accept only JSON
		UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
		matcher.setAccept(MediaType.APPLICATION_JSON);
		assertTrue(matcher
				.matches(request("/somePath",
				String.format("%s,%s", MediaType.APPLICATION_JSON, MediaType.APPLICATION_XML))));
	}

}
