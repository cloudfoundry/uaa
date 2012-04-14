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
package org.cloudfoundry.identity.uaa.oauth;

import static org.junit.Assert.assertEquals;

import java.util.Collections;
import java.util.Map;

import org.junit.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.InMemoryClientDetailsService;
import org.springframework.ui.ModelMap;

/**
 * @author Dave Syer
 * 
 */
public class AccessControllerTests {

	private AccessController controller = new AccessController();

	@Test
	public void testSunnyDay() throws Exception {
		InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
		clientDetailsService.setClientDetailsStore(Collections.singletonMap("client", new BaseClientDetails()));
		controller.setClientDetailsService(clientDetailsService);
		String result = controller.confirm(new AuthorizationRequest("client", null, null, null), new ModelMap(),
				new MockHttpServletRequest());
		assertEquals("access_confirmation", result);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testSchemePreserved() throws Exception {
		InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
		clientDetailsService.setClientDetailsStore(Collections.singletonMap("client", new BaseClientDetails()));
		controller.setClientDetailsService(clientDetailsService);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setScheme("https");
		request.addHeader("Host", "foo");
		ModelMap model = new ModelMap();
		controller.confirm(new AuthorizationRequest("client", null, null, null), model, request);
		assertEquals("https://foo/oauth/authorize",
				((Map<String, Object>) ((Map<String, Object>) model.get("options")).get("confirm")).get("location"));
	}

}
