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

import static org.junit.Assert.*;

import java.util.Collection;
import java.util.HashMap;

import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class InMemoryScimUserProvisioningTests {
	private static InMemoryScimUserProvisioning db;
	private static String joeId;
	private static String mabelId;

	@BeforeClass
	public static void seed() {
		db = new InMemoryScimUserProvisioning(new HashMap<String, UaaUser>());
		ScimUser user = new ScimUser(null, "joe", "Joe", "User");
		user.addEmail("joe@blah.com");
		joeId = db.createUser(user, "password").getId();
		user = new ScimUser(null, "mabel", "Mabel", "User");
		user.addEmail("mabel@blah.com");
		mabelId = db.createUser(user, "password").getId();
	}

	@AfterClass
	public static void shutdownDb() throws Exception {
		db.destroy();
	}

	@Test
	public void canDeleteUser() throws Exception {
		ScimUser user = db.removeUser(mabelId, 0);
		assertEquals(1, db.retrieveUsers().size());
		assertNotNull(user);
		db.createUser(user, "password");
		assertEquals(2, db.retrieveUsers().size());
	}

	@Test
	public void canUpdateUser() throws Exception {
		ScimUser user = new ScimUser(joeId, "joe", "Joe", "User");
		user.addEmail("joe@unblah.com");
		ScimUser result = db.updateUser(joeId, user);
		assertEquals(joeId, result.getId());
		Collection<ScimUser> users = db.retrieveUsers();
		assertEquals(2, users.size());
		ScimUser joe = null;
		// Check that the value retrieved from a GET is what we just PUT
		for (ScimUser scim : users) {
			if (scim.getUserName().equals("joe")) {
				joe = scim;
			}
		}
		assertNotNull(joe);
		assertEquals(joeId, joe.getId());
	}

}
