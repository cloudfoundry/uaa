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
package org.cloudfoundry.identity.uaa.authentication;

import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.*;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.ClientToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.InMemoryTokenStore;

/**
 * @author Dave Syer
 *
 */
public class LegacyTokenServicesTests {

	private LegacyTokenServices tokenServices;
	private UaaAuthentication userAuthentication;
	private Map<String,String> authData;

	@Before
	public void setUp() throws Exception {
		tokenServices = new LegacyTokenServices();
		tokenServices.setTokenStore(new InMemoryTokenStore());
		authData = new HashMap<String, String>();
		userAuthentication = new LegacyAuthentication(UaaTestFactory.getPrincipal("NaN", "foo@bar.com", "foo@bar.com"),
				Arrays.<GrantedAuthority> asList(new SimpleGrantedAuthority("ROLE_USER")), mock(UaaAuthenticationDetails.class), authData);

	}

	@Test
	public void testCreateAccessToken() {
		authData.put("token", "FOO");
		OAuth2Authentication authentication = new OAuth2Authentication(new ClientToken("foo", "bar", null), userAuthentication);
		OAuth2AccessToken token = tokenServices.createAccessToken(authentication , null);
		assertEquals("FOO", token.getValue());
	}

}
