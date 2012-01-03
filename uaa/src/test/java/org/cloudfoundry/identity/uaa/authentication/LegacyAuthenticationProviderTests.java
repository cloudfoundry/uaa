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
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Map;

import org.cloudfoundry.identity.uaa.integration.LegacyTokenServer;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * @author Dave Syer
 *
 */
public class LegacyAuthenticationProviderTests {
	
	private LegacyAuthenticationProvider authenticationProvider = new LegacyAuthenticationProvider();
	private static LegacyTokenServer tokenServer = new LegacyTokenServer(8887);
	
	@BeforeClass
	public static void setup() throws Exception {
		tokenServer.init();
	}
	
	@AfterClass
	public static void close() throws Exception {
		tokenServer.close();
	}

	@Test
	public void testAuthenticate() {
		authenticationProvider.setCloudControllerUrl("http://localhost:8887/token");
		Authentication result = authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken("foo@bar.com", ""));
		assertNotNull(result);
		@SuppressWarnings("unchecked")
		Map<String,String> details = (Map<String,String>)result.getDetails();
		assertEquals("FOO", details.get("token"));
	}
	
	@Test
	public void testSupports() throws Exception {
		assertTrue(authenticationProvider.supports(UsernamePasswordAuthenticationToken.class));
		assertFalse(authenticationProvider.supports(UaaAuthentication.class));
	}

}
