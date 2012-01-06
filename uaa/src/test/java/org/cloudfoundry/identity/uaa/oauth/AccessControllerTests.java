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

import static org.junit.Assert.assertEquals;

import java.util.Collections;

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

}
