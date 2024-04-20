package org.cloudfoundry.identity.uaa.oauth.common;

import org.cloudfoundry.identity.uaa.oauth.common.exceptions.InvalidClientException;
import org.cloudfoundry.identity.uaa.oauth.common.exceptions.OAuth2Exception;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

/**
 * Moved test class of from spring-security-oauth2 into UAA
 * Scope: Test class
 */
public class DefaultOAuth2SerializationServiceTests {

	@Test
	public void testDefaultDeserialization() throws Exception {
		Map<String, String> accessToken = MapBuilder.create("access_token", "FOO").add("expires_in", "100")
				.add("token_type", "mac").build();
		OAuth2AccessToken result = DefaultOAuth2AccessToken.valueOf(accessToken);
		// System.err.println(result);
		assertEquals("FOO", result.getValue());
		assertEquals("mac", result.getTokenType());
		assertTrue(result.getExpiration().getTime() > System.currentTimeMillis());
	}

	@Test
	public void testExceptionDeserialization() throws Exception {
		Map<String, String> exception = MapBuilder.create("error", "invalid_client").add("error_description", "FOO")
				.build();
		OAuth2Exception result = OAuth2Exception.valueOf(exception);
		// System.err.println(result);
		assertEquals("FOO", result.getMessage());
		assertEquals("invalid_client", result.getOAuth2ErrorCode());
		assertTrue(result instanceof InvalidClientException);
	}

	private static class MapBuilder {

		private HashMap<String, String> map = new HashMap<String, String>();

		private MapBuilder(String key, String value) {
			map.put(key, value);
		}

		public static MapBuilder create(String key, String value) {
			return new MapBuilder(key, value);
		}

		public MapBuilder add(String key, String value) {
			map.put(key, value);
			return this;
		}

		public Map<String, String> build() {
			return map;
		}
	}

}
