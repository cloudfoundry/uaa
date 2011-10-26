package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import java.io.ByteArrayInputStream;
import java.util.List;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Ryan Heaton
 * @author Dave Syer
 */
public class NativeApplicationIntegrationTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	/**
	 * tests a happy-day flow of the Resource Owner Password Credentials grant type.
	 * (formerly native application profile).
	 */
	@Test
	public void testHappyDay() throws Exception {

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "password");
		formData.add("client_id", "app");
		formData.add("client_secret", "appclientsecret");
		formData.add("username", "marissa");
		formData.add("password", "koala");
		formData.add("scope", "read_photos");
		ResponseEntity<String> response = serverRunning.postForString("/cloudfoundry-identity-uaa/oauth/token", formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));
	}

	/**
	 * tests that an error occurs if you attempt to use username/password creds for a non-password grant type.
	 */
	public void testInvalidGrantType() throws Exception {

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "authorization_code");
		formData.add("client_id", "my-trusted-client");
		formData.add("username", "marissa");
		formData.add("password", "koala");
		ResponseEntity<String> response = serverRunning.postForString("/cloudfoundry-identity-uaa/oauth/token", formData);
		assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
		List<String> newCookies = response.getHeaders().get("Set-Cookie");
		if (newCookies != null && !newCookies.isEmpty()) {
			fail("No cookies should be set. Found: " + newCookies.get(0) + ".");
		}
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));

		DefaultOAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();
		try {
			throw serializationService.deserializeJsonError(new ByteArrayInputStream(response.getBody().getBytes()));
		} catch (OAuth2Exception e) {
			assertEquals("invalid_request", e.getOAuth2ErrorCode());
		}
	}
}
