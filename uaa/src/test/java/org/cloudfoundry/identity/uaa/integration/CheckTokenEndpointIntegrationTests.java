package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.Map;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * @author Dave Syer
 */
public class CheckTokenEndpointIntegrationTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	/**
	 * tests a happy-day flow of the <code>/check_token</code> endpoint
	 */
	@Test
	public void testHappyDay() throws Exception {

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<String, String>();
		formData.add("grant_type", "password");
		formData.add("client_id", "app");
		formData.add("client_secret", "appclientsecret");
		formData.add("username", "marissa");
		formData.add("password", "koala");
		formData.add("scope", "read");

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = serverRunning.postForMap("/uaa/oauth/token", formData);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		String token = (String) response.getBody().get("access_token");

		formData = new LinkedMultiValueMap<String, String>();
		formData.add("token", token);
		HttpHeaders headers = new HttpHeaders();
		headers.setAccept(Arrays.asList(MediaType.APPLICATION_JSON));

		headers.set("Authorization", "Basic " + new String(Base64.encode("app:appclientsecret".getBytes("UTF-8"))));
		response = serverRunning.postForMap("/uaa/check_token", formData, headers);
		assertEquals(HttpStatus.OK, response.getStatusCode());
		System.err.println(response.getBody());

		@SuppressWarnings("unchecked")
		Map<String,String> map = response.getBody();
		assertEquals("marissa", map.get("user_name"));
		assertEquals("marissa@test.org", map.get("user_email"));

	}

}
