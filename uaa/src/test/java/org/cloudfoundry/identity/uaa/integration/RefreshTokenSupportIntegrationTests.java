package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.util.Arrays;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.DefaultOAuth2SerializationService;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Dave Syer
 */
public class RefreshTokenSupportIntegrationTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	/**
	 * tests a happy-day flow of the native application profile.
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

		DefaultOAuth2SerializationService serializationService = new DefaultOAuth2SerializationService();
		OAuth2AccessToken accessToken = serializationService.deserializeJsonAccessToken(new ByteArrayInputStream(
				response.getBody().getBytes()));

		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

		// now use the refresh token to get a new access token.
		assertNotNull(accessToken.getRefreshToken());
		formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "refresh_token");
		formData.add("client_id", "app");
		formData.add("client_secret", "appclientsecret");
		formData.add("refresh_token", accessToken.getRefreshToken().getValue());
		response = serverRunning.postForString("/cloudfoundry-identity-uaa/oauth/token", formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		assertEquals("no-store", response.getHeaders().getFirst("Cache-Control"));
		OAuth2AccessToken newAccessToken = serializationService.deserializeJsonAccessToken(new ByteArrayInputStream(
				response.getBody().getBytes()));
		assertFalse(newAccessToken.getValue().equals(accessToken.getValue()));

	}
}
