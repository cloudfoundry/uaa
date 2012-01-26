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
package org.cloudfoundry.identity.uaa.authentication.manager;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.isA;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

import org.cloudfoundry.identity.uaa.authentication.LegacyAuthentication;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.manager.LegacyAuthenticationManager;
import org.cloudfoundry.identity.uaa.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.integration.LegacyTokenServer;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * @author Dave Syer
 * @author Luke Taylor
 */
public class LegacyAuthenticationManagerTests {

	private LegacyAuthenticationManager am;
	private static LegacyTokenServer tokenServer = new LegacyTokenServer(8887, "password");

	@Before
	public void setUp() throws Exception {
		am = new LegacyAuthenticationManager();
		am.setCloudControllerUrl("http://localhost:8887/token");
		am.setApplicationEventPublisher(mock(ApplicationEventPublisher.class));
	}

	@BeforeClass
	public static void setup() throws Exception {
		tokenServer.init();
	}

	@AfterClass
	public static void close() throws Exception {
		tokenServer.close();
	}

	@Test
	public void successfulAuthenticationReturnsTokenAndPublishesEvent() throws Exception {
		ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
		am.setApplicationEventPublisher(publisher);

		Authentication result = am.authenticate(new UsernamePasswordAuthenticationToken("foo@bar.com", "password"));

		assertNotNull(result);
		assertNotNull(((LegacyAuthentication)result).getToken());

		assertEquals("foo@bar.com", result.getName());
		assertEquals("foo@bar.com", ((UaaPrincipal)result.getPrincipal()).getName());

		verify(publisher).publishEvent(isA(UserAuthenticationSuccessEvent.class) );
	}

	@Test
	public void unsuccessfulAuthenticationPublishesFailureEvent() {
		ApplicationEventPublisher publisher = mock(ApplicationEventPublisher.class);
		am.setApplicationEventPublisher(publisher);

		try {
			am.authenticate(new UsernamePasswordAuthenticationToken("foo@bar.com", "wrongpassword"));
			fail();
		}
		catch (BadCredentialsException expected) {
		}

		verify(publisher).publishEvent(isA(UserAuthenticationFailureEvent.class));
	}
}
