package org.cloudfoundry.identity.api.web;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

/**
 * @author Dave Syer
 */
public class AppsIntegrationTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();
	
	/**
	 * tests a happy-day flow of the native application profile.
	 */
	@Test
	public void testHappyDay() throws Exception {

		OAuth2AccessToken accessToken = serverRunning.getToken();
		// now try and use the token to access a protected resource.

		// first make sure the resource is actually protected.
		assertNotSame(HttpStatus.OK, serverRunning.getStatusCode("/api/apps"));

		// then make sure an authorized request is valid.
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));
		headers.set("Authorization", String.format("%s %s", OAuth2AccessToken.BEARER_TYPE, accessToken.getValue()));
		ResponseEntity<String> result = serverRunning.getForString("/api/apps", headers);
		assertEquals(HttpStatus.OK, result.getStatusCode());
		String body = result.getBody();
		assertTrue("Wrong response: "+body, body.contains("dsyerapi.cloudfoundry.com"));

	}

}
