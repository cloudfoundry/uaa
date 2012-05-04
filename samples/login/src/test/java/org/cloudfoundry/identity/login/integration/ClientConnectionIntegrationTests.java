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

package org.cloudfoundry.identity.login.integration;

import static org.junit.Assert.assertNotNull;

import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.ResponseEntity;

/**
 * @author Dave Syer
 *
 */
public class ClientConnectionIntegrationTests {
	
	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	@Test
	public void testPrompts() {
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> entity = serverRunning.getRestTemplate().getForEntity(serverRunning.getUrl("/login"), Map.class);
		@SuppressWarnings("unchecked")
		Map<String,Object> result = (Map<String, Object>) entity.getBody();
		assertNotNull(result.get("timestamp"));
	}

}
