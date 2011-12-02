package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

/**
 * @author Dave Syer
 */
public class UserInfoEndpointIntegrationTests {

	@Rule
	public ServerRunning server = ServerRunning.isRunning();

	@Rule
	public OAuth2ContextSetup context = OAuth2ContextSetup.resourceOwner(server, "marissa", "koala");

	/**
	 * tests a happy-day flow of the <code>/userinfo</code> endpoint
	 */
	@Test
	public void testHappyDay() throws Exception {
		
		HttpHeaders headers = new HttpHeaders();
		ResponseEntity<String> user = server.getForString("/userinfo", headers);
		assertEquals(HttpStatus.OK, user.getStatusCode());
		System.err.println(user.getBody());

		String map = user.getBody();
		assertTrue("marissa", map.contains("user_id"));
		assertTrue("marissa@test.org", map.contains("email"));

	}

}
