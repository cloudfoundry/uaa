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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;

/**
 * @author Dave Syer
 */
public class LoginInfoEndpointIntegrationTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	/**
	 * tests a happy-day flow of the <code>/login_info</code> endpoint
	 */
	@Test
	public void testHappyDay() throws Exception {

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.getForObject("/login", Map.class);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		@SuppressWarnings("unchecked")
		Map<String, String[]> prompts = (Map<String, String[]>) response.getBody().get("prompts");
		assertNotNull(prompts);

	}

	/**
	 * tests a happy-day flow of the <code>/login_info</code> endpoint
	 */
	@Test
	public void testHappyDayHtml() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.TEXT_HTML));
		ResponseEntity<String> response = serverRunning.getForString("/login", headers );
		assertEquals(HttpStatus.OK, response.getStatusCode());
		String body = response.getBody();
		// System.err.println(body);
		assertNotNull(body);
		assertTrue("Wrong body: "+body, body.contains("<form id=\"loginForm\""));

	}

}
