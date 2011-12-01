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
package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Dave Syer
 */
public class CheckTokenEndpointIntegrationTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	/**
	 * tests a happy-day flow of the <code>/check_token</code> endpoint
	 */
	@Test
	public void testHappyDay() throws Exception {

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "password");
		formData.add("client_id", "app");
		formData.add("client_secret", "appclientsecret");
		formData.add("username", "marissa");
		formData.add("password", "koala");
		formData.add("scope", "read");

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap("/oauth/token", formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		String token = (String) response.getBody().get("access_token");

		formData = new LinkedMultiValueMap<String, String>();
		formData.add("token", token);
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

		headers.set("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes("UTF-8"))));
		response = serverRunning.postForMap("/check_token", formData, headers);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		System.err.println(response.getBody());

		@SuppressWarnings("unchecked")
		Map<String,String> map = response.getBody();
		assertEquals("marissa", map.get("user_id"));
		assertEquals("marissa@test.org", map.get("email"));

	}

}
