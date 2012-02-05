package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.codec.Base64;

/**
 * @author Dave Syer
 */
public class VarzEndpointIntegrationTests {

	@Rule
	public ServerRunning server = ServerRunning.isRunning();

	@Rule
	public TestAccountSetup testAccounts = TestAccountSetup.standard();
	
	/**
	 * tests a happy-day flow of the <code>/varz</code> endpoint
	 */
	@Test
	public void testHappyDay() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", testAccounts.getVarzAuthorizationHeader());
		ResponseEntity<String> response = server.getForString("/varz", headers);
		assertEquals(HttpStatus.OK, response.getStatusCode());

		String map = response.getBody();
		assertTrue(map.contains("spring.application"));

	}

	/**
	 * tests a unauthorized flow of the <code>/varz</code> endpoint
	 */
	@Test
	public void testUnauthorized() throws Exception {

		HttpHeaders headers = new HttpHeaders();
		headers.add("Authorization", String.format("Basic %s", new String(Base64.encode("varz:bogust".getBytes()))));
		ResponseEntity<String> response = server.getForString("/varz", headers);
		assertEquals(HttpStatus.UNAUTHORIZED, response.getStatusCode());

		String map = response.getBody();
		// System.err.println(map);
		assertTrue(map.contains("{\"error\""));

	}

}
