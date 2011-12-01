package org.cloudfoundry.identity.uaa.authentication;

import static org.junit.Assert.*;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.*;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.cloudfoundry.identity.uaa.user.UaaUserDatabase;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.HashMap;
import java.util.Map;

/**
 * @author Luke Taylor
 */
public class AuthzAuthenticationManagerTests {
	private AuthzAuthenticationMgr mgr;
	private UaaUserDatabase db;
	private ApplicationEventPublisher publisher;
	private UaaUser user = new UaaUser("auser", "password", "auser@blah.com", "A", "User");

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
	public void invalidPasswordPublishesNotFoundEvent() {
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
