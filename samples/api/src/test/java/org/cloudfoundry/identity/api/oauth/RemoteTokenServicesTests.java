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
package org.cloudfoundry.identity.api.oauth;

import static org.junit.Assert.*;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

/**
 * @author Dave Syer
 * 
 */
public class RemoteTokenServicesTests {

	private RemoteTokenServices services = new RemoteTokenServices();

	private Map<String, Object> body = new HashMap<String, Object>();

	private HttpHeaders headers = new HttpHeaders();

	private HttpStatus status = HttpStatus.OK;

	public RemoteTokenServicesTests() {
		services.setClientId("client");
		services.setClientSecret("secret");
		body.put("client_id", "remote");
		body.put("user_name", "olds");
		services.setRestTemplate(new RestTemplate() {
			@SuppressWarnings("unchecked")
			@Override
			public <T> ResponseEntity<T> exchange(String url, HttpMethod method, HttpEntity<?> requestEntity,
					Class<T> responseType, Object... uriVariables) throws RestClientException {
				return new ResponseEntity<T>((T) body, headers, status);
			}
		});
	}

	@Test
	public void testTokenRetrieval() throws Exception {
		OAuth2Authentication result = services.loadAuthentication("FOO");
		assertNotNull(result);
		assertEquals("remote", result.getAuthorizationRequest().getClientId());
		assertEquals("olds", result.getUserAuthentication().getName());
	}

	@Test
	public void testTokenRetrievalWithClientAuthorities() throws Exception {
		body.put("client_authorities", Collections.singleton("ROLE_CLIENT"));
		OAuth2Authentication result = services.loadAuthentication("FOO");
		assertNotNull(result);
		assertEquals("[ROLE_CLIENT]", result.getAuthorizationRequest().getAuthorities().toString());
	}

	@Test
	public void testTokenRetrievalWithUserAuthorities() throws Exception {
		body.put("user_authorities", Collections.singleton("ROLE_USER"));
		OAuth2Authentication result = services.loadAuthentication("FOO");
		assertNotNull(result);
		assertEquals("[ROLE_USER]", result.getUserAuthentication().getAuthorities().toString());
	}

}
