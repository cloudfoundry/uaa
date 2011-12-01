package org.cloudfoundry.identity.app.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

/**
 * Tests implicit grant using a direct posting of credentials to the /authorize endpoint and
 * also with an intermediate form login.
 * 
 * @author Dave Syer
 */
public class AuthenticationIntegrationTests {

	@Rule
	public ServerRunning serverRunning = ServerRunning.isRunning();

	@Test
	public void formLoginSucceeds() throws Exception {

		ResponseEntity<Void> result;
		String location;
		String cookie;

		HttpHeaders uaaHeaders = new HttpHeaders();
		HttpHeaders appHeaders = new HttpHeaders();
		uaaHeaders.setAccept(Arrays.asList(MediaType.TEXT_HTML));
		appHeaders.setAccept(Arrays.asList(MediaType.TEXT_HTML));

		// *** GET /app/
		result = serverRunning.getForResponse("/app/", appHeaders);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		location = result.getHeaders().getLocation().toString();
		
		cookie = result.getHeaders().getFirst("Set-Cookie");
		assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
		appHeaders.set("Cookie", cookie);
		
		assertTrue("Wrong location: "+ location, location.contains("/app/login"));
		// *** GET /app/login
		result = serverRunning.getForResponse(location, appHeaders);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		location = result.getHeaders().getLocation().toString();
		
		assertTrue("Wrong location: "+ location, location.contains("/uaa/oauth/authorize"));
		// *** GET /uaa/oauth/authorize
		result = serverRunning.getForResponse(location, uaaHeaders);
		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		location = result.getHeaders().getLocation().toString();

		cookie = result.getHeaders().getFirst("Set-Cookie");
		assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
		uaaHeaders.set("Cookie", cookie);

		assertTrue("Wrong location: "+ location, location.contains("/uaa/login"));
		location = "/uaa/login.do";

		MultiValueMap<String, String> formData;
		formData = new LinkedMultiValueMap<String, String>();
		formData.add("username", "marissa");
		formData.add("password", "koala");

		// *** POST /uaa/login.do
		result = serverRunning.postForResponse(location, uaaHeaders, formData);

		cookie = result.getHeaders().getFirst("Set-Cookie");
		assertNotNull("Expected cookie in " + result.getHeaders(), cookie);
		uaaHeaders.set("Cookie", cookie);

		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		location = result.getHeaders().getLocation().toString();

		assertTrue("Wrong location: "+ location, location.contains("/uaa/oauth/authorize"));
		// *** GET /uaa/oauth/authorize
		result = serverRunning.getForResponse(location, uaaHeaders);
		assertEquals(HttpStatus.OK, result.getStatusCode());

		location = "/uaa/oauth/authorize";

		formData = new LinkedMultiValueMap<String, String>();
		formData.add("user_oauth_approval", "true");

		// *** POST /uaa/oauth/authorize
		result = serverRunning.postForResponse(location, uaaHeaders, formData);
		location = result.getHeaders().getLocation().toString();

		assertTrue("Wrong location: "+ location, location.contains("app/login"));
		// *** GET /app/login
		result = serverRunning.getForResponse(location, appHeaders);

		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		location = result.getHeaders().getLocation().toString();
		
		assertTrue("Wrong location: "+ location, location.contains("app/login"));
		// *** GET /app/login
		result = serverRunning.getForResponse(location, appHeaders);

		assertEquals(HttpStatus.FOUND, result.getStatusCode());
		location = result.getHeaders().getLocation().toString();
		
		// SUCCESS
		assertTrue("Wrong location: "+ location, location.endsWith("/app/"));

		// *** GET /app/
		result = serverRunning.getForResponse(location, appHeaders);
		System.err.println(result.getHeaders());
		assertEquals(HttpStatus.OK, result.getStatusCode());
	}

}
