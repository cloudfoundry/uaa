/**
 * Cloud Foundry 2012.02.03 Beta Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 * 
 * This product is licensed to you under the Apache License, Version 2.0 (the "License"). You may not use this product
 * except in compliance with the License.
 * 
 * This product includes a number of subcomponents with separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.oauth;

import static org.junit.Assert.assertNotNull;

import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

/**
 * @author Dave Syer
 * 
 */
public class JwtTokenEnhancerTests {

	private JwtTokenEnhancer tokenEnhancer;

	private UaaAuthentication userAuthentication;

	@Before
	public void setUp() throws Exception {
		tokenEnhancer = new JwtTokenEnhancer();
		userAuthentication = UaaAuthenticationTestFactory.getAuthentication("foo@bar.com", "Foo Bar", "foo@bar.com");
	}

	@Test
	public void testEnhanceAccessToken() {
		OAuth2Authentication authentication = new OAuth2Authentication(
				new AuthorizationRequest("foo", null, null, null), userAuthentication);
		OAuth2AccessToken token = tokenEnhancer.enhance(new DefaultOAuth2AccessToken("FOO"), authentication);
		assertNotNull(token.getValue());
	}

}
