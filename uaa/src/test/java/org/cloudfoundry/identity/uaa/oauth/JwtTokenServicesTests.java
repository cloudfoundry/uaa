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
package org.cloudfoundry.identity.uaa.oauth;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.mockito.Mockito.mock;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.authentication.LegacyAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationTestFactory;
import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.AuthorizationRequest;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;

/**
 * @author Dave Syer
 * 
 */
public class JwtTokenServicesTests {

	private JwtTokenServices tokenServices;

	private UaaAuthentication userAuthentication;

	private Map<String, String> authData;

	@Before
	public void setUp() throws Exception {
		tokenServices = new JwtTokenServices();
		tokenServices.setTokenStore(new InMemoryTokenStore());
		authData = new HashMap<String, String>();
		userAuthentication = new LegacyAuthentication(UaaAuthenticationTestFactory.getPrincipal("NaN", "foo@bar.com",
				"foo@bar.com"), Arrays.<GrantedAuthority> asList(new SimpleGrantedAuthority("ROLE_USER")),
				mock(UaaAuthenticationDetails.class), authData);

	}

	@Test
	public void testCreateAccessToken() {
		authData.put("token", "FOO");
		OAuth2Authentication authentication = new OAuth2Authentication(
				new AuthorizationRequest("foo", null, null, null), userAuthentication);
		OAuth2AccessToken token = tokenServices.createAccessToken(authentication, null);
		assertNotNull(token.getValue());
	}

	@Test
	public void testDuplicateTokens() {
		authData.put("token", "FOO");
		OAuth2Authentication authentication1 = new OAuth2Authentication(
				new AuthorizationRequest("id", null, null, null), userAuthentication);
		OAuth2AccessToken token1 = tokenServices.createAccessToken(authentication1);
		OAuth2Authentication authentication2 = new OAuth2Authentication(new AuthorizationRequest("id",
				Collections.singleton("read"), null, null), userAuthentication);
		OAuth2AccessToken token2 = tokenServices.createAccessToken(authentication2);
		assertNotSame(token1, token2);
	}

}
