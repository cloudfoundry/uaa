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

import static org.cloudfoundry.identity.uaa.oauth.Claims.EMAIL;
import static org.cloudfoundry.identity.uaa.oauth.Claims.USER_ID;
import static org.cloudfoundry.identity.uaa.oauth.Claims.USER_NAME;
import static org.junit.Assert.assertEquals;

import java.util.Map;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.junit.Test;

/**
 * @author Dave Syer
 *
 */
public class UaaUserTokenConverterTests {

	private UaaUserTokenConverter converter = new UaaUserTokenConverter();

	@Test
	public void test() {
		Map<String, ?> map = converter.convertUserAuthentication(UaaAuthenticationTestFactory.getAuthentication("FOO", "foo", "foo@test.org"));
		assertEquals("FOO", map.get(USER_ID));
		assertEquals("foo@test.org", map.get(EMAIL));
		assertEquals("foo", map.get(USER_NAME));
	}

}
