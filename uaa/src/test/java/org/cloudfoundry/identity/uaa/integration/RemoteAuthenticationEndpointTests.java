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

package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.*;

import java.util.Arrays;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.*;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.DefaultResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * @author Luke Taylor
 */
public class RemoteAuthenticationEndpointTests {
	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	@Test
	public void remoteAuthenticationSucceedsWithCorrectCredentials() throws Exception {
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = authenticate("marissa", "koala");
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("marissa", response.getBody().get("username"));
	}

	@Test
	public void remoteAuthenticationFailsWithIncorrectCredentials() throws Exception {
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = authenticate("marissa", "wrong");
		assertFalse(HttpStatus.OK == response.getStatusCode());
		assertFalse("marissa".equals(response.getBody().get("username")));
	}

	@SuppressWarnings("rawtypes")
	ResponseEntity<Map> authenticate(String username, String password) {
		RestTemplate restTemplate = new RestTemplate();
		// The default java.net client doesn't allow you to handle 4xx responses
		restTemplate.setRequestFactory(new HttpComponentsClientHttpRequestFactory());
		restTemplate.setErrorHandler(new DefaultResponseErrorHandler() {
			protected boolean hasError(HttpStatus statusCode) {
				return statusCode.series() == HttpStatus.Series.SERVER_ERROR;
			}
		});
		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

		MultiValueMap<String, Object> parameters = new LinkedMultiValueMap<String, Object>();
		parameters.set("username", username);
		parameters.set("password", password);

		ResponseEntity<Map> result = restTemplate.exchange(serverRunning.getUrl("/authenticate"),
				HttpMethod.POST, new HttpEntity<MultiValueMap<String, Object>>(parameters, headers), Map.class);
		return result;
	}
}
