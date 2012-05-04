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

package org.cloudfoundry.identity.uaa.login;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestOperations;
import org.springframework.web.client.RestTemplate;

/**
 * An authentication manager that can be used to login to a remote UAA service with username and password credentials,
 * without the local server needing to know anything about the user accounts. The request to authenticate is simply
 * passed on to the form login endpoint of the remote server and treated as successful if there is no error.
 * 
 * @author Dave Syer
 * 
 */
public class RemoteUaaAuthenticationManager implements AuthenticationManager {

	private final Log logger = LogFactory.getLog(getClass());

	private RestOperations restTemplate = new RestTemplate();

	private static String DEFAULT_LOGIN_URL = "http://uaa.cloudfoundry.com/login.do";

	private String loginUrl = DEFAULT_LOGIN_URL;

	/**
	 * @param loginUrl the login url to set
	 */
	public void setLoginUrl(String loginUrl) {
		this.loginUrl = loginUrl;
	}

	/**
	 * @param restTemplate a rest template to use
	 */
	public void setRestTemplate(RestOperations restTemplate) {
		this.restTemplate = restTemplate;
	}

	public RemoteUaaAuthenticationManager() {
		RestTemplate restTemplate = new RestTemplate();
		// The default java.net client doesn't allow you to handle 4xx responses
		restTemplate.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
		restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
			public boolean hasError(ClientHttpResponse response) throws IOException {
				HttpStatus statusCode = response.getStatusCode();
				return statusCode.series() == HttpStatus.Series.SERVER_ERROR;
			}
		});
		this.restTemplate = restTemplate;
	}

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {

		logger.debug("Processing authentication request for " + authentication.getName());

		String username = authentication.getName();
		String password = (String) authentication.getCredentials();

		MultiValueMap<String, Object> parameters = new LinkedMultiValueMap<String, Object>();
		parameters.set("username", username);
		parameters.set("password", password);

		ResponseEntity<Void> response = restTemplate.exchange(loginUrl, HttpMethod.POST,
				new HttpEntity<MultiValueMap<String, Object>>(parameters), Void.class);

		if (response.getHeaders().getLocation() != null) {
			String location = response.getHeaders().getLocation().toString();
			// Successful authentication redirects to the home page with no error
			if (!location.contains("error=true")) {
				return new UsernamePasswordAuthenticationToken(username, password, UaaAuthority.USER_AUTHORITIES);
			}
		}

		throw new BadCredentialsException("Could not authenticate with remote server");

	}

}
