package org.cloudfoundry.identity.uaa.user;

import static org.junit.Assert.assertEquals;

import java.util.Collections;

import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.expression.spel.SpelEvaluationException;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
public class InMemoryUaaUserDatabaseTests {

	private InMemoryUaaUserDatabase db =  new InMemoryUaaUserDatabase(Collections.<UaaUser>emptyList());
	
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
