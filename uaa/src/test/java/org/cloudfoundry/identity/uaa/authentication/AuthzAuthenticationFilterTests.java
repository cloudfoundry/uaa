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
package org.cloudfoundry.identity.uaa.authentication;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;

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
