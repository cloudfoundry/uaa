package org.cloudfoundry.identity.uaa.user;

import static org.junit.Assert.assertEquals;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.junit.Test;

import java.util.Collections;

/**
 * @author Luke Taylor
 */
public class InMemoryUaaUserDatabaseTests {

	private InMemoryUaaUserDatabase db =  new InMemoryUaaUserDatabase(Collections.<UaaUser>emptyList());

	@Test
	public void canCreateUser() throws Exception {
		ScimUser user = new ScimUser(null, "joe", "Joe", "User");
		user.addEmail("joe@blah.com");
		db.createUser(user, "password");
	}

	@Test
	public void canRetrieveUsers() throws Exception {
		canCreateUser();
		assertEquals(1, db.retrieveUsers().size());
	}

	@Test
	public void canRetrieveUsersWithFilter() throws Exception {
		canCreateUser();
		assertEquals(1, db.retrieveUsers("userName eq 'joe'").size());
	}

}
