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
package org.cloudfoundry.identity.app.web;

import static org.junit.Assert.assertNotNull;

import java.util.HashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.http.AccessTokenRequiredException;
import org.springframework.security.oauth2.client.resource.BaseOAuth2ProtectedResourceDetails;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * @author Dave Syer
 *
 */
public class OpenIdClientFilterTests {
	
	private OpenIdClientFilter filter = new OpenIdClientFilter("/login");
	private HttpServletRequest request = new MockHttpServletRequest();
	private HttpServletResponse response = new MockHttpServletResponse();

	@Test
	public void testFilterSunnyDay() throws Exception {
		filter.setRestTemplate(new RestTemplate() {
			@SuppressWarnings("unchecked")
			@Override
			public <T> T getForObject(String url, Class<T> responseType, Object... urlVariables)
					throws RestClientException {
				HashMap<String, String> map = new HashMap<String, String>();
				map.put("user_id", "foo");
				map.put("email", "foo@bar.com");
				return (T) map;
			}
		});
		Authentication authentication = filter.attemptAuthentication(request , response);
		assertNotNull(authentication);
	}

	@Test(expected=BadCredentialsException.class)
	public void testFilterMissingId() throws Exception {
		filter.setRestTemplate(new RestTemplate() {
			@SuppressWarnings("unchecked")
			@Override
			public <T> T getForObject(String url, Class<T> responseType, Object... urlVariables)
					throws RestClientException {
				HashMap<String, String> map = new HashMap<String, String>();
				return (T) map;
			}
		});
		Authentication authentication = filter.attemptAuthentication(request , response);
		assertNotNull(authentication);
	}

	@Test(expected=AccessTokenRequiredException.class)
	public void testFilterUnsuccessfulWithAccessTokenRequired() throws Exception {
		filter.unsuccessfulAuthentication(request, response, new AccessTokenRequiredException(new BaseOAuth2ProtectedResourceDetails()));
	}

	@Test
	public void testFilterUnsuccessfulWithRuntimeException() throws Exception {
		// The default strategy should kick in for a vanilla AuthenticationException
		filter.unsuccessfulAuthentication(request, response, new BadCredentialsException("test"));
	}

}
