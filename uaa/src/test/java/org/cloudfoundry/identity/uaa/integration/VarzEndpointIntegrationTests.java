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
import static org.junit.Assert.assertTrue;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;

/**
 * @author Dave Syer
 */
public class VarzEndpointIntegrationTests {

	@Rule
	public ServerRunning server = ServerRunning.isRunning();

	@Rule
	public TestAccountSetup testAccounts = TestAccountSetup.standard();
	
	@Before
	public void checkVcap() {
		// If running against vcap we don't know the varz password
		Assume.assumeTrue(!testAccounts.isProfileActive("vcap"));		
	}
	
	/**
	 * tests a happy-day flow of the <code>/varz</code> endpoint
	 */
	@Test
	public void testHappyDay() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", testAccounts.getVarzAuthorizationHeader());
		ResponseEntity<String> response = server.getForString("/varz", headers);
		assertEquals(HttpStatus.OK, response.getStatusCode());

		String map = response.getBody();
		assertTrue(map.contains("spring.application"));

	}

	/**
	 * tests a unauthorized flow of the <code>/varz</code> endpoint
	 */
	@Test
	public void testUnauthorized() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", String.format("Basic %s", new String(Base64.encode("varz:bogus".getBytes()))));
		ResponseEntity<String> response = server.getForString("/varz", headers);
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());

		String map = response.getBody();
		// System.err.println(map);
		assertTrue(map.contains("{\"error\""));

	}

}
