/*
 * Copyright 2006-2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package org.cloudfoundry.identity.uaa.scim;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.expression.spel.SpelEvaluationException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class InMemoryScimUserProvisioningTests {

	private Map<String, UaaUser> users = new HashMap<String, UaaUser>();
	private InMemoryScimUserProvisioning db =  new InMemoryScimUserProvisioning(users);

	@Before
	public void seed() {
		ScimUser user;
		user = new ScimUser(null, "joe", "Joe", "User");
		user.addEmail("joe@blah.com");
		db.createUser(user, "password");
		user = new ScimUser(null, "mabel", "Mabel", "User");
		user.addEmail("mabel@blah.com");
		db.createUser(user, "password");
	}

	@Test
	public void canCreateUser() throws Exception {
	}

	@Test
	public void canDeleteUser() throws Exception {
		ScimUser user = db.removeUser("1", 0);
		assertEquals(1, db.retrieveUsers().size());
		assertNotNull(user);
		db.createUser(user, "password");
		assertEquals(2, db.retrieveUsers().size());
	}

	@Test
	public void canUpdateUser() throws Exception {
		ScimUser user;
		user = new ScimUser("1", "joe", "Joe", "User");
		user.addEmail("joe@unblah.com");
		ScimUser result = db.updateUser("1", user);
		assertEquals(result.getId(), user.getId());
		Collection<ScimUser> users = db.retrieveUsers();
		assertEquals(2, users.size());
		ScimUser joe = null;
		// Check that the value retreived from a GET is what we just PUT
		for (ScimUser scim : users) {
			if (scim.getUserName().equals("joe")) {
				joe = scim;
			}
		}
		assertNotNull(joe);
		assertEquals("1", joe.getId());
	}

	@Test
	public void canChangePassword() throws Exception {
		assertTrue(db.changePassword("1", null, "newpassword"));
		assertTrue(new BCryptPasswordEncoder().matches("newpassword", users.get("joe").getPassword()));
	}

	@Test
	public void canRetrieveUsers() throws Exception {
		assertEquals(2, db.retrieveUsers().size());
	}

	@Test
	public void canRetrieveUsersWithFilter() throws Exception {
		assertEquals(1, db.retrieveUsers("userName eq 'joe'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterExists() {
		assertEquals(2, db.retrieveUsers("userName pr").size());
	}

	@Test
	public void canRetrieveUsersWithFilterEquals() {
		assertEquals(1, db.retrieveUsers("userName eq 'joe'").size());
	}

	@Test
	@Ignore
	public void canRetrieveUsersWithFilterCaseSensitivity() {
		// TODO: CFID40 fix this.
		assertEquals(1, db.retrieveUsers("USERNAME eq 'joe'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterContains() {
		assertEquals(2, db.retrieveUsers("userName co 'e'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterStartsWith() {
		assertEquals(1, db.retrieveUsers("userName sw 'j'").size());
	}

	@Test
	public void canRetrieveUsersWithEmailFilter() {
		assertEquals(1, db.retrieveUsers("emails.value sw 'j'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterBooleanAnd() {
		assertEquals(2, db.retrieveUsers("userName pr and emails.value co '.com'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterBooleanOr() {
		assertEquals(2, db.retrieveUsers("userName eq 'joe' or emails.value co '.com'").size());
	}

	@Test(expected=SpelEvaluationException.class)
	public void canRetrieveUsersWithIllegalFilter() {
		assertEquals(2, db.retrieveUsers("emails.type eq 'bar'").size());
	}

}
