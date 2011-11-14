package org.cloudfoundry.identity.uaa.scim;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Test;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

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
	
	@Test
	public void testSpelFilter() throws Exception {
		ScimUser user = new ScimUser("123");
		user.setUserName("joe");
		ScimUser.Email email = new ScimUser.Email();
		email.setValue("foo@bar.com");
		user.setEmails(Arrays.asList(email));
		StandardEvaluationContext context = new StandardEvaluationContext(user);
		assertTrue(new SpelExpressionParser().parseExpression("userName == 'joe' and !(emails.?[value=='foo@bar.com']).empty").getValue(context, Boolean.class));
	}

}
