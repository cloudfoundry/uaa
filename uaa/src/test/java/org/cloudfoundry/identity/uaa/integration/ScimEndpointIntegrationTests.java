package org.cloudfoundry.identity.uaa.integration;

import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.identity.uaa.scim.ScimException;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.StringHttpMessageConverter;
import org.springframework.http.converter.json.MappingJacksonHttpMessageConverter;
import org.springframework.web.client.ResponseErrorHandler;
import org.springframework.web.client.RestTemplate;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class ScimEndpointIntegrationTests {
	ObjectMapper mapper = new ObjectMapper();

	private final String userEndpoint = "/uaa/User";

	@Rule
	public ServerRunning server = ServerRunning.isRunning();
	
	{
		server.setPort(8001);
	}

	private RestTemplate client;

	@Before
	public void createRestTemplate() {
		client = server.getRestTemplate();
		List<HttpMessageConverter<?>> list = new ArrayList<HttpMessageConverter<?>>();
		list.add(new MappingJacksonHttpMessageConverter());
		list.add(new StringHttpMessageConverter());
		client.setErrorHandler(new ResponseErrorHandler() {
			@Override
			public boolean hasError(ClientHttpResponse response) throws IOException {
				return false;
			}

			@Override
			public void handleError(ClientHttpResponse response) throws IOException {
			}
		});
		client.setMessageConverters(list);
		client.delete(server.getUrl(userEndpoint + "/{id}"), "joe"); // ignore errors
		client.delete(server.getUrl(userEndpoint + "/{id}"), "joel"); // ignore errors
	}

	// curl -v -H "Content-Type: application/json" -H "Accept: application/json" --data
	// "{\"userName\":\"joe\",\"schemas\":[\"urn:scim:schemas:core:1.0\"]}" http://localhost:8080/uaa/User
	@Test
	public void createUserSucceeds() throws Exception {
		ScimUser user = new ScimUser();
		user.setUserName("joe");
		user.addEmail("joe@blah.com");

		ResponseEntity<ScimUser> response = client.postForEntity(server.getUrl(userEndpoint), user, ScimUser.class);
		ScimUser joe1 = response.getBody();
		assertEquals("joe", joe1.getUserName());

		// Check we can GET the user
		ScimUser joe2 = client.getForObject(server.getUrl(userEndpoint + "/{id}"), ScimUser.class, response.getBody()
				.getId());

		assertEquals(joe1.getId(), joe2.getId());
	}

	// curl -v -H "Content-Type: application/json" -H "Accept: application/json" --data
	// "{\"userName\":\"joe\",\"schemas\":[\"urn:scim:schemas:core:1.0\"]}" http://localhost:8080/uaa/User
	@Test
	public void createUserTwiceFails() throws Exception {
		ScimUser user = new ScimUser();
		user.setUserName("joel");
		user.addEmail("joel@blah.com");

		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = client.postForEntity(server.getUrl(userEndpoint), user, Map.class);
		@SuppressWarnings("unchecked")
		Map<String, String> joe1 = response.getBody();
		assertEquals("joel", joe1.get("userName"));

		response = client.postForEntity(server.getUrl(userEndpoint), user, Map.class);
		@SuppressWarnings("unchecked")
		Map<String, String> error = response.getBody();
		;
		assertEquals(IllegalArgumentException.class.getName(), error.get("error"));

	}

	// curl -v -H "Content-Type: application/json" -H "Accept: application/json" -X DELETE
	// http://localhost:8080/uaa/User/joel
	@Test
	public void deleteUserFails() throws Exception {
		@SuppressWarnings("rawtypes")
		ResponseEntity<Map> response = client.exchange(server.getUrl(userEndpoint + "/{id}"), HttpMethod.DELETE,
				new HttpEntity<Void>((Void) null), Map.class, "99999");
		System.err.println(response.getBody());
		@SuppressWarnings("unchecked")
		Map<String, String> error = response.getBody();
		System.err.println(error);
		assertEquals(ScimException.class.getName(), error.get("error"));

	}

	@Test
	public void getReturnsNotFoundForNonExistentUser() throws Exception {
		ResponseEntity<String> response = server.getForString(userEndpoint + "/9999");
		assertEquals(HttpStatus.NOT_FOUND, response.getStatusCode());
	}
}
