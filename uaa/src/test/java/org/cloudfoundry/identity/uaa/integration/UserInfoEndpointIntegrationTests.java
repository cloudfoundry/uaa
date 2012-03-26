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
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * @author Dave Syer
 */
@OAuth2ContextConfiguration(OAuth2ContextConfiguration.GrantType.RESOURCE_OWNER)
public class UserInfoEndpointIntegrationTests {

	@Rule
	public ServerRunning server = ServerRunning.isRunning();
	
	private TestAccounts testAccounts = TestAccounts.standard(server);
	
	@Rule
	public OAuth2ContextSetup context = OAuth2ContextSetup.standard(server, testAccounts);
	
	/**
	 * tests a happy-day flow of the <code>/userinfo</code> endpoint
	 */
	@Test
	public void testHappyDay() throws Exception {

		Assume.assumeTrue(!testAccounts.isProfileActive("vcap"));

		ResponseEntity<String> user = server.getForString("/userinfo");
		assertEquals(HttpStatus.OK, user.getStatusCode());

		String map = user.getBody();
		assertTrue(testAccounts.getUserName(), map.contains("user_id"));
		assertTrue(testAccounts.getEmail(), map.contains("email"));

	}

}
