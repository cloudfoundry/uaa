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
package org.cloudfoundry.identity.uaa.authentication.manager;


import static org.junit.Assert.*;
import static org.mockito.Mockito.*;


import org.cloudfoundry.identity.uaa.authentication.AuthzAuthenticationRequest;
import org.cloudfoundry.identity.uaa.authentication.UaaAuthenticationDetails;
import org.cloudfoundry.identity.uaa.authentication.UaaPrincipal;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserAuthenticationSuccessEvent;
import org.cloudfoundry.identity.uaa.authentication.event.UserNotFoundEvent;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;

/**
 * @author Luke Taylor
 */
public class AuthzAuthenticationManagerTests {
	private AuthzAuthenticationManager mgr;
	private UaaUserDatabase db;
	private ApplicationEventPublisher publisher;
	// "password"
	private static final String PASSWORD = "$2a$10$HoWPAUn9zqmmb0b.2TBZWe6cjQcxyo8TDwTX.5G46PBL347N3/0zO";
	private UaaUser user = new UaaUser("auser", PASSWORD, "auser@blah.com", "A", "User");

	@Before
	public void setUp() throws Exception {
		db = mock(UaaUserDatabase.class);
		publisher = mock(ApplicationEventPublisher.class);
		mgr = new AuthzAuthenticationManager(db);
		mgr.setApplicationEventPublisher(publisher);
	}

	@Test
	public void successfulAuthenticationReturnsTokenAndPublishesEvent() throws Exception {
		when(db.retrieveUserByName("auser")).thenReturn(user);
		Authentication result = mgr.authenticate(createAuthRequest("auser","password"));

		assertNotNull(result);
		assertEquals("auser", result.getName());
		assertEquals("auser", ((UaaPrincipal)result.getPrincipal()).getName());

		verify(publisher).publishEvent(isA(UserAuthenticationSuccessEvent.class) );
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

		verify(publisher).publishEvent(isA(UserAuthenticationFailureEvent.class));
	}

	@Test(expected = BadCredentialsException.class)
	public void authenticationIsDeniedIfRejectedByLoginPolicy() throws Exception {
		when(db.retrieveUserByName("auser")).thenReturn(user);
		AccountLoginPolicy lp = mock(AccountLoginPolicy.class);
		when(lp.isAllowed(any(UaaUser.class), any(Authentication.class))).thenReturn(false);
		mgr.setAccountLoginPolicy(lp);
		mgr.authenticate(createAuthRequest("auser","password"));
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

		verify(publisher).publishEvent(isA(UserNotFoundEvent.class));
	}

	AuthzAuthenticationRequest createAuthRequest(String username, String password) {
		Map<String,String> userdata = new HashMap<String,String>();
		userdata.put("username", username);
		userdata.put("password", password);
		return new AuthzAuthenticationRequest(userdata, new UaaAuthenticationDetails(mock(HttpServletRequest.class)));
	}
}
