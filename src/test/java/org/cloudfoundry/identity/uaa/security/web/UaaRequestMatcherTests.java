package org.cloudfoundry.identity.uaa.security.web;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.junit.Assert.*;

/**
 */
public class UaaRequestMatcherTests {

	private MockHttpServletRequest request(String path, String accept) {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setContextPath("/ctx");
		request.setRequestURI("/ctx" + path);
		if (accept != null) {
			request.addHeader("Accept", accept);
		}

		return request;
	}

	@Test
	public void pathMatcherMatchesExpectedPathsAndAcceptHeaderValues() throws Exception {
		UaaRequestMatcher matcher = new UaaRequestMatcher("/somePath");
		assertTrue(matcher.matches(request("/somePath", null)));
		assertTrue(matcher.matches(request("/somePath", "application/json")));
		assertTrue(matcher.matches(request("/somePath", "application/html")));
		assertTrue(matcher.matches(request("/somePath/aak", null)));
		assertTrue(matcher.matches(request("/somePath?blah=x", null)));
		// We don't actually want this  for anything but it's a consequence of using substring matching
		assertTrue(matcher.matches(request("/somePathOrOther", null)));

		// Accept only JSON
		matcher = new UaaRequestMatcher("/somePath", "application/json");
		assertTrue(matcher.matches(request("/somePath", null)));
		assertTrue(matcher.matches(request("/somePath", "application/json")));
		assertFalse(matcher.matches(request("/somePath", "application/html")));
	}
}
