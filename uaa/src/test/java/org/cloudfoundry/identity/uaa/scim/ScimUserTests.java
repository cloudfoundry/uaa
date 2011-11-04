package org.cloudfoundry.identity.uaa.scim;

import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * @author Luke Taylor
 */
public class ScimUserTests {
	ObjectMapper mapper = new ObjectMapper();

	private static final String SCHEMAS = "\"schemas\": [\"urn:scim:schemas:core:1.0\"],";

	@Test
	public void minimalJsonMapsToUser() throws Exception {
		String minimal = "{" + SCHEMAS +
				"  \"userName\": \"bjensen@example.com\"\n" +
				"}";

		ScimUser user = mapper.readValue(minimal, ScimUser.class);
		assertEquals("bjensen@example.com", user.getUserName());
	}

	@Test
	public void minimalUserMapsToJson() throws Exception {
		ScimUser user = new ScimUser("123");
		user.setUserName("joe");

		assertEquals("{\"id\":\"123\",\"userName\":\"joe\",\"schemas\":[\"urn:scim:schemas:core:1.0\"]}",
				mapper.writeValueAsString(user));

	}

	@Test
	public void emailsAreMappedCorrectly() throws Exception {
		String json = "{ \"userName\":\"bjensen\"," +
				"\"emails\": [\n" +
				"{\"value\": \"bj@jensen.org\",\"type\": \"other\"}," +
				"{\"value\": \"bjensen@example.com\", \"type\": \"work\",\"primary\": true}," +
				"{\"value\": \"babs@jensen.org\",\"type\": \"home\"}" +
				"],\n" +
				"\"schemas\":[\"urn:scim:schemas:core:1.0\"]}";
		ScimUser user = mapper.readValue(json, ScimUser.class);
		assertEquals(3, user.getEmails().size());
		assertEquals("bjensen@example.com", user.getEmails().get(1).getValue());
		assertEquals("babs@jensen.org", user.getEmails().get(2).getValue());
		assertEquals("bjensen@example.com", user.getPrimaryEmail().getValue());
		assertFalse(user.getEmails().get(0).isPrimary());
//		System.out.println(mapper.writeValueAsString(user));
	}
}
