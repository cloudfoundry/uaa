package org.cloudfoundry.identity.uaa.oauth.common;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.junit.Test;

import java.util.Date;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class JsonSerializationTests {

	@Test
	public void testDefaultSerialization() throws Exception {
		DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
		accessToken.setExpiration(new Date(System.currentTimeMillis() + 10000));
		String result = new ObjectMapper().writeValueAsString(accessToken);
		// System.err.println(result);
		assertTrue("Wrong token: " + result, result.contains("\"token_type\":\"bearer\""));
		assertTrue("Wrong token: " + result, result.contains("\"access_token\":\"FOO\""));
		assertTrue("Wrong token: " + result, result.contains("\"expires_in\":"));
	}

	@Test
	public void testRefreshSerialization() throws Exception {
		DefaultOAuth2AccessToken accessToken = new DefaultOAuth2AccessToken("FOO");
		accessToken.setRefreshToken(new DefaultOAuth2RefreshToken("BAR"));
		accessToken.setExpiration(new Date(System.currentTimeMillis() + 10000));
		String result = new ObjectMapper().writeValueAsString(accessToken);
		// System.err.println(result);
		assertTrue("Wrong token: " + result, result.contains("\"token_type\":\"bearer\""));
		assertTrue("Wrong token: " + result, result.contains("\"access_token\":\"FOO\""));
		assertTrue("Wrong token: " + result, result.contains("\"refresh_token\":\"BAR\""));
		assertTrue("Wrong token: " + result, result.contains("\"expires_in\":"));
	}

	@Test
	public void testExceptionSerialization() throws Exception {
		InvalidClientException exception = new InvalidClientException("FOO");
		exception.addAdditionalInformation("foo", "bar");
		String result = new ObjectMapper().writeValueAsString(exception);
		// System.err.println(result);
		assertTrue("Wrong result: "+result, result.contains("\"error\":\"invalid_client\""));
		assertTrue("Wrong result: "+result, result.contains("\"error_description\":\"FOO\""));
		assertTrue("Wrong result: "+result, result.contains("\"foo\":\"bar\""));
	}

	@Test
	public void testDefaultDeserialization() throws Exception {
		String accessToken = "{\"access_token\": \"FOO\", \"expires_in\": 100, \"token_type\": \"mac\"}";
		OAuth2AccessToken result = new ObjectMapper().readValue(accessToken, OAuth2AccessToken.class);
		// System.err.println(result);
		assertEquals("FOO", result.getValue());
		assertEquals("mac", result.getTokenType());
		assertTrue(result.getExpiration().getTime() > System.currentTimeMillis());
	}

	@Test
	public void testExceptionDeserialization() throws Exception {
		String exception = "{\"error\": \"invalid_client\", \"error_description\": \"FOO\", \"foo\": \"bar\"}";
		OAuth2Exception result = new ObjectMapper().readValue(exception, OAuth2Exception.class);
		// System.err.println(result);
		assertEquals("FOO", result.getMessage());
		assertEquals("invalid_client", result.getOAuth2ErrorCode());
		assertEquals("{foo=bar}", result.getAdditionalInformation().toString());
		assertTrue(result instanceof InvalidClientException);
	}

}
