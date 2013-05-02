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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;
import java.util.List;
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
	 * tests a happy-day flow of the <code>/info</code> endpoint
	 */
	@Test
	public void testHappyDay() throws Exception {

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.getForObject("/info", Map.class);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		@SuppressWarnings("unchecked")
		List<Map<String, String[]>> prompts = (List<Map<String, String[]>>) response.getBody().get("prompts");
		assertNotNull(prompts);

	}

	/**
	 * tests a happy-day flow of the <code>/login</code> endpoint
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
		assertTrue("Wrong body: "+body, body.contains("<form id="));

	}

}
