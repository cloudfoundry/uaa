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

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.oauth.approval.ApprovalStore;
import org.junit.Test;
import org.mockito.Mockito;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.provider.BaseClientDetails;
import org.springframework.security.oauth2.provider.DefaultAuthorizationRequest;
import org.springframework.security.oauth2.provider.InMemoryClientDetailsService;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.support.SimpleSessionStatus;

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
		controller.setApprovalStore(Mockito.mock(ApprovalStore.class));
		Authentication auth = UaaAuthenticationTestFactory.getAuthentication("foo@bar.com", "Foo Bar", "foo@bar.com");
		String result = controller.confirm(new ModelMap(), new MockHttpServletRequest(), auth, new SimpleSessionStatus());
		assertEquals("access_confirmation", result);
	}

	@SuppressWarnings("unchecked")
	@Test
	public void testSchemePreserved() throws Exception {
		InMemoryClientDetailsService clientDetailsService = new InMemoryClientDetailsService();
		clientDetailsService.setClientDetailsStore(Collections.singletonMap("client", new BaseClientDetails()));
		controller.setClientDetailsService(clientDetailsService);
		controller.setApprovalStore(Mockito.mock(ApprovalStore.class));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setScheme("https");
		request.addHeader("Host", "foo");
		ModelMap model = new ModelMap();
		model.put("authorizationRequest",new DefaultAuthorizationRequest("client", null));
		Authentication auth = UaaAuthenticationTestFactory.getAuthentication("foo@bar.com", "Foo Bar", "foo@bar.com");
		controller.confirm(model, request, auth, new SimpleSessionStatus());
		Map<String, Object> options = (Map<String, Object>) ((Map<String, Object>) model.get("options")).get("confirm");
		assertEquals("https://foo/oauth/authorize", options.get("location"));
		assertEquals("/oauth/authorize", options.get("path"));
	}

}
