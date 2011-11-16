package org.cloudfoundry.identity.uaa.authentication;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;

/**
 * @author Luke Taylor
 */
public class InMemoryUaaUserDatabaseTests {

	@Test
	public void canCreateUser() throws Exception {
		InMemoryUaaUserDatabase db =  new InMemoryUaaUserDatabase(Collections.<UaaUser>emptyList());
		ScimUser user = new ScimUser(null, "joe", "Joe", "User");
		user.addEmail("joe@blah.com");
		db.createUser(user, "password");
	}
}
