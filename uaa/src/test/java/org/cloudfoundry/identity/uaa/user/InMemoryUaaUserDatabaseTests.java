package org.cloudfoundry.identity.uaa.user;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.user.InMemoryUaaUserDatabase;
import org.cloudfoundry.identity.uaa.user.UaaUser;
import org.junit.Test;

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
