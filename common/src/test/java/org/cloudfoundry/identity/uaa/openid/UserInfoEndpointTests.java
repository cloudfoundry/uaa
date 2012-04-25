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
package org.cloudfoundry.identity.uaa.openid;

import static org.junit.Assert.assertEquals;

import java.util.Collections;
import java.util.Map;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserTestFactory;
import org.junit.Test;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Dave Syer
 * 
 */
public class UserInfoEndpointTests {

	private UserInfoEndpoint endpoint = new UserInfoEndpoint();

	private InMemoryUaaUserDatabase userDatabase = new InMemoryUaaUserDatabase(Collections.singletonMap("olds",
			UaaUserTestFactory.getUser("12345", "olds", "olds@vmware.com", "Dale", "Olds")));

	public UserInfoEndpointTests() {
		endpoint.setUserDatabase(userDatabase);
	}

	@Test
	public void testSunnyDay() {
		UaaUser user = userDatabase.retrieveUserByName("olds");
		UaaAuthentication authentication = UaaAuthenticationTestFactory.getAuthentication(user.getId(), "olds", "olds@vmware.com");
		Map<String, String> map = endpoint.loginInfo(new OAuth2Authentication(null, authentication));
		assertEquals("olds", map.get("user_name"));
		assertEquals("Dale Olds", map.get("name"));
		assertEquals("olds@vmware.com", map.get("email"));
	}

	@Test(expected = UsernameNotFoundException.class)
	public void testMissingUser() {
		UaaAuthentication authentication = UaaAuthenticationTestFactory.getAuthentication("12345", "Dale", "olds@vmware.com");
		Map<String, String> map = endpoint.loginInfo(new OAuth2Authentication(null, authentication));
		assertEquals("olds", map.get("user_name"));
		assertEquals("Dale Olds", map.get("name"));
		assertEquals("olds@vmware.com", map.get("email"));
	}

}
