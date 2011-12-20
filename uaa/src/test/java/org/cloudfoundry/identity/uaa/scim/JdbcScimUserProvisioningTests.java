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
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

import java.sql.Connection;
import java.util.Collection;
import java.util.UUID;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.TestUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.DataSourceUtils;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.jdbc.datasource.init.ScriptStatementFailedException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
@ContextConfiguration("file:./src/main/webapp/WEB-INF/spring-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
public class JdbcScimUserProvisioningTests {

	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	private JdbcScimUserProvisioning db;

	private static final String JOE_ID = "550e8400-e29b-41d4-a716-446655440000";

	private static final String MABEL_ID = UUID.randomUUID().toString();

	private static final String SQL_INJECTION_FIELDS = "password,version,created,lastModified,username,email,givenName,familyName";

	@Before
	public void createDatasource() throws Exception {

		template = new JdbcTemplate(dataSource);
		db = new JdbcScimUserProvisioning(template);
		TestUtils.createSchema(dataSource);
		template.execute("insert into users (id, username, password, email, givenName, familyName) " + "values ('"
				+ JOE_ID + "', 'joe','joespassword','joe@joe.com','Joe','User')");
		template.execute("insert into users (id, username, password, email, givenName, familyName) " + "values ('"
				+ MABEL_ID + "', 'mabel','mabelspassword','mabel@mabel.com','Mabel','User')");

	}

	@After
	public void clear() throws Exception {
		TestUtils.dropSchema(dataSource);
	}

	@Test
	public void canCreateUser() {
		ScimUser user = new ScimUser(null, "JO@FOO.COM", "Jo", "User");
		user.addEmail("jo@blah.com");
		ScimUser created = db.createUser(user, "j7hyqpassX");
		assertEquals("jo@foo.com", created.getUserName());
		assertNotNull(created.getId());
		assertNotSame(user.getId(), created.getId());
	}

	@Test(expected = InvalidUserException.class)
	public void cannotCreateUserWithNonAsciiUsername() {
		ScimUser user = new ScimUser(null, "joe$eph", "Jo", "User");
		user.addEmail("jo@blah.com");
		db.createUser(user, "j7hyqpassX");
	}

	@Test
	public void updateModifiesExpectedData() {
		ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
		jo.addEmail("jo@blah.com");

		ScimUser joe = db.updateUser(JOE_ID, jo);

		// Can't change username (yet)
		assertEquals("joe", joe.getUserName());
		assertEquals("jo@blah.com", joe.getPrimaryEmail());
		assertEquals("Jo", joe.getGivenName());
		assertEquals("NewUser", joe.getFamilyName());
		assertEquals(1, joe.getVersion());
		assertEquals(JOE_ID, joe.getId());
	}

	@Test(expected = OptimisticLockingFailureException.class)
	public void updateWithWrongVersionIsError() {
		ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
		jo.addEmail("jo@blah.com");
		jo.setVersion(1);
		ScimUser joe = db.updateUser(JOE_ID, jo);
		assertEquals("joe", joe.getUserName());
	}

	@Test(expected = InvalidUserException.class)
	public void updateWithBadUsernameIsError() {
		ScimUser jo = new ScimUser(null, "jo$ephine", "Jo", "NewUser");
		jo.addEmail("jo@blah.com");
		jo.setVersion(1);
		ScimUser joe = db.updateUser(JOE_ID, jo);
		assertEquals("joe", joe.getUserName());
	}

	@Test
	public void canChangePassword() throws Exception {
		assertTrue(db.changePassword(JOE_ID, "newpassword"));
		String storedPassword = template.queryForObject("SELECT password from USERS where ID=?", String.class, JOE_ID);
		assertTrue(BCrypt.checkpw("newpassword", storedPassword));
	}

	@Test(expected=UserNotFoundException.class)
	public void cannotChangePasswordNonexistentUser() {
		assertTrue(db.changePassword("9999", "newpassword"));
	}

	@Test
	public void canRetrieveExistingUser() {
		ScimUser joe = db.retrieveUser(JOE_ID);
		assertJoe(joe);
	}

	@Test(expected=UserNotFoundException.class)
	public void cannotRetrieveNonexistentUser() {
		ScimUser joe = db.retrieveUser("9999");
		assertJoe(joe);
	}

	private void assertJoe(ScimUser joe) {
		assertNotNull(joe);
		assertEquals(JOE_ID, joe.getId());
		assertEquals("Joe", joe.getGivenName());
		assertEquals("User", joe.getFamilyName());
		assertEquals("joe@joe.com", joe.getPrimaryEmail());
		assertEquals("joe", joe.getUserName());
	}

	@Test
	public void canRemoveExistingUser() {
		ScimUser joe = db.removeUser(JOE_ID, 0);
		assertJoe(joe);
		template.queryForList("select * from users").isEmpty();
	}

	@Test(expected=UserNotFoundException.class)
	public void cannotRemoveNonexistentUser() {
		ScimUser joe = db.removeUser("9999", 0);
		assertJoe(joe);
	}

	@Test(expected = OptimisticLockingFailureException.class)
	public void removeWithWrongVersionIsError() {
		ScimUser joe = db.removeUser(JOE_ID, 1);
		assertJoe(joe);
	}

	@Test
	public void canRetrieveUsers() {
		assertEquals(2, db.retrieveUsers().size());
	}

	@Test
	public void canRetrieveUsersWithFilterExists() {
		assertEquals(2, db.retrieveUsers("username pr").size());
	}

	@Test
	public void canRetrieveUsersWithFilterEquals() {
		assertEquals(1, db.retrieveUsers("username eq 'joe'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterKeyCaseSensitivity() {
		// This actually depends on the RDBMS.
		assertEquals(1, db.retrieveUsers("USERNAME eq 'joe'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterOperatorCaseSensitivity() {
		// This actually depends on the RDBMS.
		assertEquals(1, db.retrieveUsers("username EQ 'joe'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterValueCaseSensitivity() {
		// This actually depends on the RDBMS.
		assertEquals(1, db.retrieveUsers("username eq 'Joe'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterContains() {
		assertEquals(2, db.retrieveUsers("username co 'e'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterStartsWith() {
		assertEquals(1, db.retrieveUsers("username sw 'j'").size());
	}

	@Test
	public void canRetrieveUsersWithEmailFilter() {
		assertEquals(1, db.retrieveUsers("emails.value sw 'j'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterBooleanAnd() {
		assertEquals(2, db.retrieveUsers("username pr and emails.value co '.com'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterBooleanOr() {
		assertEquals(2, db.retrieveUsers("username eq 'joe' or emails.value co '.com'").size());
	}

	@Test(expected = UnsupportedOperationException.class)
	public void cannotRetrieveUsersWithIllegalFilterField() {
		assertEquals(2, db.retrieveUsers("emails.type eq 'bar'").size());
	}

	@Test(expected = BadSqlGrammarException.class)
	public void cannotRetrieveUsersWithIllegalFilterQuotes() {
		assertEquals(2, db.retrieveUsers("username eq 'bar").size());
	}

	@Test(expected=DataAccessException.class)
	public void cannotRetrieveUsersWithNativeSqlInjectionAttack() {
		String password = template.queryForObject("select password from users where username='joe'", String.class);
		assertNotNull(password);
		Collection<ScimUser> users = db
				.retrieveUsers("username='joe'; select " +
						SQL_INJECTION_FIELDS + " from users where username='joe'");
		assertEquals(password, users.iterator().next().getId());
	}

	@Test(expected=DataAccessException.class)
	public void cannotRetrieveUsersWithSqlInjectionAttackOnGt() {
		String password = template.queryForObject("select password from users where username='joe'", String.class);
		assertNotNull(password);
		Collection<ScimUser> users = db
				.retrieveUsers("username gt 'h'; select " +
						SQL_INJECTION_FIELDS + " from users where username='joe'");
		assertEquals(password, users.iterator().next().getId());
	}

	@Test(expected=DataAccessException.class)
	public void cannotRetrieveUsersWithSqlInjectionAttack() {
		String password = template.queryForObject("select password from users where username='joe'", String.class);
		assertNotNull(password);
		Collection<ScimUser> users = db
				.retrieveUsers("username eq 'joe'; select " +
						SQL_INJECTION_FIELDS + " from users where username='joe'");
		assertEquals(password, users.iterator().next().getId());
	}

	@Test(expected=DataAccessException.class)
	public void cannotRetrieveUsersWithAnotherSqlInjectionAttack() {
		String password = template.queryForObject("select password from users where username='joe'", String.class);
		assertNotNull(password);
		Collection<ScimUser> users = db
				.retrieveUsers("username eq 'joe''; select id from users where id='''; select " +
						SQL_INJECTION_FIELDS + " from users where username='joe'");
		assertEquals(password, users.iterator().next().getId());
	}

	@Test(expected=BadSqlGrammarException.class)
	public void cannotRetrieveUsersWithYetAnotherSqlInjectionAttack() {
		String password = template.queryForObject("select password from users where username='joe'", String.class);
		assertNotNull(password);
		Collection<ScimUser> users = db
				.retrieveUsers("username eq 'joe''; select " +
						SQL_INJECTION_FIELDS + " from users where username='joe''");
		assertEquals(password, users.iterator().next().getId());
	}

}
