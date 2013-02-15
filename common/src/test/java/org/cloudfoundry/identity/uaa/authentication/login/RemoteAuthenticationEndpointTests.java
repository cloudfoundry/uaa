package org.cloudfoundry.identity.uaa.authentication.login;

import static org.junit.Assert.assertEquals;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * @author Luke Taylor
 */
public class RemoteAuthenticationEndpointTests {
	private Authentication success = new UsernamePasswordAuthenticationToken("joe", null);
	private RemoteAuthenticationEndpoint endpoint;
	private AuthenticationManager am;

	@Before
	public void setUp() throws Exception {
		am = mock(AuthenticationManager.class);
		endpoint = new RemoteAuthenticationEndpoint(am);
	}

	@Test
	public void successfulAuthenticationGives200Status() throws Exception {
		when(am.authenticate(any(Authentication.class))).thenReturn(success);
		@SuppressWarnings("rawtypes")
		ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe", "joespassword");
		assertEquals(HttpStatus.OK,  response.getStatusCode());
	}

	@Test
	public void authenticationExceptionGives401Status() throws Exception {
		when(am.authenticate(any(Authentication.class))).thenThrow(new BadCredentialsException("failed"));
		@SuppressWarnings("rawtypes")
		ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe", "joespassword");
		assertEquals(HttpStatus.UNAUTHORIZED,  response.getStatusCode());
	}

	@Test
	public void otherExceptionGives500Status() throws Exception {
		when(am.authenticate(any(Authentication.class))).thenThrow(new RuntimeException("error"));
		@SuppressWarnings("rawtypes")
		ResponseEntity response = (ResponseEntity) endpoint.authenticate(new MockHttpServletRequest(), "joe", "joespassword");
		assertEquals(HttpStatus.INTERNAL_SERVER_ERROR,  response.getStatusCode());
	}
}
