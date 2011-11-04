package org.cloudfoundry.identity.uaa.integration;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.converter.json.MappingJacksonHttpMessageConverter;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.Assert.assertEquals;

/**
 * @author Luke Taylor
 */
public class ScimEndpointIntegrationTests {
	ObjectMapper mapper = new ObjectMapper();

	private final String userEndpoint = "/cloudfoundry-identity-uaa/User";

	@Rule
	public ServerRunning server = ServerRunning.isRunning();

	private RestTemplate client;

	@Before
	public void createRestTemplate() {
		client = server.getRestTemplate();
		List<HttpMessageConverter<?>> list = new ArrayList<HttpMessageConverter<?>>();
		list.add(new MappingJacksonHttpMessageConverter());
		list.add(new StringHttpMessageConverter());
		client.setMessageConverters(list);
	}

	// curl -v -H "Content-Type: application/json" -H "Accept: application/json" --data  "{\"userName\":\"joe\",\"schemas\":[\"urn:scim:schemas:core:1.0\"]}" http://localhost:8080/cloudfoundry-identity-uaa/User
	@Test
	public void createUserSucceeds() throws Exception {
		ScimUser user = new ScimUser();
		user.setUserName("joe");
		user.addEmail("joe@blah.com");

		ResponseEntity<ScimUser> response = client.postForEntity(server.getUrl(userEndpoint), user, ScimUser.class);
		ScimUser joe1 = response.getBody();
		assertEquals("joe", joe1.getUserName());

		// Check we can GET the user
		ScimUser joe2 = client.getForObject(server.getUrl(userEndpoint + "/{id}"), ScimUser.class, response.getBody().getId());

		assertEquals(joe1.getId(), joe2.getId());
	}

	@Test
	public void getReturnsNotFoundForNonExistentUser() throws Exception {
		ResponseEntity<String> response = server.getForString(userEndpoint + "/9999");
		assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
	}
}
