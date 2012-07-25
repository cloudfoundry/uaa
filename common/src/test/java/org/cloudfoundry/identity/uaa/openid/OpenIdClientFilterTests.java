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
package org.cloudfoundry.identity.uaa.openid;

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
@SuppressWarnings("deprecation")
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
				map.put("user_id", "12345");
				map.put("user_name", "foo");
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
