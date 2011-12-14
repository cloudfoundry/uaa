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
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;
import static org.mockito.Matchers.any;
import static org.mockito.Matchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

/**
 * @author Luke Taylor
 */
public class AuthzAuthenticationManagerTests {
	private AuthzAuthenticationMgr mgr;
	private UaaUserDatabase db;
	private ApplicationEventPublisher publisher;
	// "password"
	private static final String PASSWORD = "$2a$10$HoWPAUn9zqmmb0b.2TBZWe6cjQcxyo8TDwTX.5G46PBL347N3/0zO";
	private UaaUser user = new UaaUser("auser", PASSWORD, "auser@blah.com", "A", "User");

	@Before
	public void setUp() throws Exception {
		db = mock(UaaUserDatabase.class);
		publisher = mock(ApplicationEventPublisher.class);
		mgr = new AuthzAuthenticationMgr(db);
		mgr.setApplicationEventPublisher(publisher);
	}

	@Test
	public void successfulAuthenticationReturnsTokenAndPublishesEvent() throws Exception {
		when(db.retrieveUserByName("auser")).thenReturn(user);
		Authentication result = mgr.authenticate(createAuthRequest("auser","password"));

		assertNotNull(result);
		assertEquals("auser", result.getName());
		assertEquals("auser", ((UaaPrincipal)result.getPrincipal()).getName());

		verify(publisher).publishEvent(any(AuthenticationSuccessEvent.class));
	}

	@Test
	public void invalidPasswordPublishesAuthenticationFailureEvent() {
		when(db.retrieveUserByName("auser")).thenReturn(user);
		try {
			mgr.authenticate(createAuthRequest("auser", "wrongpassword"));
			fail();
		}
		catch (BadCredentialsException expected) {
		}

		verify(publisher).publishEvent(any(UaaAuthenticationFailureEvent.class));
	}

	@Test
	public void missingUserPublishesNotFoundEvent() {
		when(db.retrieveUserByName(eq("aguess"))).thenThrow(new UsernameNotFoundException("mocked"));
		try {
			mgr.authenticate(createAuthRequest("aguess", "password"));
			fail();
		}
		catch (BadCredentialsException expected) {
		}

		verify(publisher).publishEvent(any(UserNotFoundEvent.class));
	}

	AuthzAuthenticationRequest createAuthRequest(String username, String password) {
		Map<String,String> userdata = new HashMap<String,String>();
		userdata.put("username", username);
		userdata.put("password", password);
		return new AuthzAuthenticationRequest(userdata);
	}
}
