package org.cloudfoundry.identity.uaa.authentication;

import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthzAuthenticationFilterTests {

	@Test
	public void authenticatesValidUser() throws Exception {
		String msg = "{ \"username\":\"marissa\", \"password\":\"koala\"}";

		AuthenticationManager am = mock(AuthenticationManager.class);
		Authentication result = mock(Authentication.class);
		when(am.authenticate(any(AuthzAuthenticationRequest.class))).thenReturn(result);
		AuthzAuthenticationFilter filter = new AuthzAuthenticationFilter(am);

		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/oauth/authorize");
		request.setParameter("credentials", msg);
		MockHttpServletResponse response = new MockHttpServletResponse();

		filter.doFilter(request, response, new MockFilterChain());


	}
}
