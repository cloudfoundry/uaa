/*
 * Cloud Foundry 2012.02.03 Beta
 * Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
 *
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 *
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 */
package org.cloudfoundry.identity.uaa.scim;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Group;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.Test;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.StandardEvaluationContext;

import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

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
		assertEquals(null, user.getPassword());
	}

	@Test
	public void passwordJsonMapsToUser() throws Exception {
		String minimal = "{" + SCHEMAS +
				"  \"userName\": \"bjensen@example.com\",\n" +
				"  \"password\": \"foo\"\n" +
				"}";

		ScimUser user = mapper.readValue(minimal, ScimUser.class);
		assertEquals("foo", user.getPassword());
	}

	@Test
	public void minimalUserMapsToJson() throws Exception {
		ScimUser user = new ScimUser();
		user.setId("123");
		user.setUserName("joe");
		user.getMeta().setCreated(new SimpleDateFormat("yyyy-MM-dd").parse("2011-11-30"));

		String json = mapper.writeValueAsString(user);
		// System.err.println(json);
		assertTrue(json.contains("\"userName\":\"joe\""));
		assertTrue(json.contains("\"id\":\"123\""));
		assertTrue(json.contains("\"meta\":"));
		assertTrue(json.contains("\"created\":\"2011-11-30"));
		assertTrue(json.matches(".*\\\"created\\\":\\\"([0-9-]*-?)T([0-9:.]*)Z\\\".*"));
		assertFalse(json.contains("\"lastModified\":"));

	}

	@Test
	public void anotherUserMapsToJson() throws Exception {
		ScimUser user = new ScimUser();
		user.setId("123");
		user.setUserName("joe");
		user.getMeta().setCreated(new SimpleDateFormat("yyyy-MM-dd").parse("2011-11-30"));
		user.addEmail("joe@test.org");
		user.addPhoneNumber("+1-222-1234567");

		String json = mapper.writeValueAsString(user);
		// System.err.println(json);
		assertTrue(json.contains("\"emails\":"));
		assertTrue(json.contains("\"phoneNumbers\":"));

	}

	@Test
	public void userWithGroupsMapsToJson() throws Exception {
		ScimUser user = new ScimUser();
		user.setId("123");
		user.setUserName("joe");
		user.setGroups(Collections.singleton(new Group(null, "foo")));

		String json = mapper.writeValueAsString(user);
		// System.err.println(json);
		assertTrue(json.contains("\"groups\":"));
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
		assertEquals("bjensen@example.com", user.getPrimaryEmail());
		assertFalse(user.getEmails().get(0).isPrimary());
//		System.out.println(mapper.writeValueAsString(user));
	}

	@Test
	public void groupsAreMappedCorrectly() throws Exception {
		String json = "{ \"userName\":\"bjensen\"," +
				"\"groups\": [\n" +
				"{\"value\": \"12345\",\"display\": \"uaa.admin\"}," +
				"{\"value\": \"123456\",\"display\": \"dash.admin\"}" +
				"],\n" +
				"\"schemas\":[\"urn:scim:schemas:core:1.0\"]}";
		ScimUser user = mapper.readValue(json, ScimUser.class);
		assertEquals(2, user.getGroups().size());
//		System.out.println(mapper.writeValueAsString(user));
	}

	@Test
	public void datesAreMappedCorrectly() throws Exception {
		String json = "{ \"userName\":\"bjensen\"," +
				"\"meta\":{\"version\":10,\"created\":\"2011-11-30T10:46:16.475Z\"}}";
		ScimUser user = mapper.readValue(json, ScimUser.class);
		assertEquals(10, user.getVersion());
		assertEquals("2011-11-30", new SimpleDateFormat("yyyy-MM-dd").format(user.getMeta().getCreated()));
//		System.out.println(mapper.writeValueAsString(user));
	}

    @Test
	public void basicNamesAreMappedCorrectly() {
		ScimUser roz = new ScimUser("1234", "roz", "Roslyn", "MacRae");
		assertEquals("1234", roz.getId());
		assertEquals("roz", roz.getUserName());
		assertEquals("Roslyn", roz.getGivenName());
		assertEquals("MacRae", roz.getFamilyName());
	}

	@Test
	public void testSpelFilter() throws Exception {
		ScimUser user = new ScimUser();
		user.setId("123");
		user.setUserName("joe");
		ScimUser.Email email = new ScimUser.Email();
		email.setValue("foo@bar.com");
		user.setEmails(Arrays.asList(email));
		StandardEvaluationContext context = new StandardEvaluationContext(user);
		assertTrue(new SpelExpressionParser().parseExpression("userName == 'joe' and !(emails.?[value=='foo@bar.com']).empty").getValue(context, Boolean.class));
	}

}
