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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertTrue;

import java.util.Collection;
import java.util.UUID;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.TestUtils;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.OptimisticLockingFailureException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.test.annotation.IfProfileValue;
import org.springframework.test.annotation.ProfileValueSourceConfiguration;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;

/**
 * @author Luke Taylor
 * @author Dave Syer
 */
@ContextConfiguration("classpath:/test-data-source.xml")
@RunWith(SpringJUnit4ClassRunner.class)
@IfProfileValue(name = "spring.profiles.active", values = { "", "test,postgresql", "hsqldb" })
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
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

		TestUtils.assertNoSuchUser(template, "id", JOE_ID);
		TestUtils.assertNoSuchUser(template, "id", MABEL_ID);
		TestUtils.assertNoSuchUser(template, "userName", "jo@foo.com");

		db = new JdbcScimUserProvisioning(template);
		BCryptPasswordEncoder pe = new BCryptPasswordEncoder(4);
		template.execute("insert into users (id, username, password, email, givenName, familyName) " + "values ('"
				+ JOE_ID + "', 'joe','" + pe.encode("joespassword") + "','joe@joe.com','Joe','User')");
		template.execute("insert into users (id, username, password, email, givenName, familyName) " + "values ('"
				+ MABEL_ID + "', 'mabel','" + pe.encode("mabelspassword") + "','mabel@mabel.com','Mabel','User')");
	}

	@After
	public void clear() throws Exception {
		template.execute("delete from users where id = '" + JOE_ID + "'");
		template.execute("delete from users where id = '" + MABEL_ID + "'");
		template.execute("delete from users where userName = 'jo@foo.com'");
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
	public void canChangePasswordWithouOldPassword() throws Exception {
		assertTrue(db.changePassword(JOE_ID, null, "newpassword"));
		String storedPassword = template.queryForObject("SELECT password from USERS where ID=?", String.class, JOE_ID);
		assertTrue(BCrypt.checkpw("newpassword", storedPassword));
	}

	@Test
	public void canChangePasswordWithCorrectOldPassword() throws Exception {
		assertTrue(db.changePassword(JOE_ID, "joespassword", "newpassword"));
		String storedPassword = template.queryForObject("SELECT password from USERS where ID=?", String.class, JOE_ID);
		assertTrue(BCrypt.checkpw("newpassword", storedPassword));
	}

	@Test(expected = BadCredentialsException.class)
	public void cannotChangePasswordNonexistentUser() {
		db.changePassword(JOE_ID, "notjoespassword", "newpassword");
	}

	@Test(expected = UserNotFoundException.class)
	public void cannotChangePasswordIfOldPasswordDoesntMatch() {
		assertTrue(db.changePassword("9999", null, "newpassword"));
	}

	@Test
	public void canRetrieveExistingUser() {
		ScimUser joe = db.retrieveUser(JOE_ID);
		assertJoe(joe);
	}

	@Test(expected = UserNotFoundException.class)
	public void cannotRetrieveNonexistentUser() {
		ScimUser joe = db.retrieveUser("9999");
		assertJoe(joe);
	}

	@Test
	public void canRemoveExistingUser() {
		ScimUser joe = db.removeUser(JOE_ID, 0);
		assertJoe(joe);
		assertEquals(1, template.queryForList("select * from users where id=? and active=false", JOE_ID).size());
		assertFalse(joe.isActive());
	}

	@Test(expected=UserAlreadyExistsException.class)
	public void canRemoveExistingUserAndThenCreateHimAgain() {
		ScimUser joe = db.removeUser(JOE_ID, 0);
		assertJoe(joe);
		joe.setActive(true);
		ScimUser user = db.createUser(joe, "foobarspam1234");
		assertEquals(JOE_ID, user.getId());
	}

	@Test(expected = UserNotFoundException.class)
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
		assertTrue(2 <= db.retrieveUsers().size());
	}

	@Test
	public void canRetrieveUsersWithFilterExists() {
		assertTrue(2 <= db.retrieveUsers("username pr").size());
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
		assertEquals(1, db.retrieveUsers("username sw 'joe'").size());
	}

	@Test
	public void canRetrieveUsersWithEmailFilter() {
		assertEquals(1, db.retrieveUsers("emails.value sw 'joe'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterBooleanAnd() {
		assertTrue(2 <= db.retrieveUsers("username pr and emails.value co '.com'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterBooleanOr() {
		assertTrue(2 <= db.retrieveUsers("username eq 'joe' or emails.value co '.com'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterBooleanOrMatchesSecond() {
		assertEquals(1, db.retrieveUsers("username eq 'foo' or username eq 'joe'").size());
	}

	@Test(expected = UnsupportedOperationException.class)
	public void cannotRetrieveUsersWithIllegalFilterField() {
		assertEquals(2, db.retrieveUsers("emails.type eq 'bar'").size());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveUsersWithIllegalFilterQuotes() {
		assertEquals(2, db.retrieveUsers("username eq 'bar").size());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveUsersWithNativeSqlInjectionAttack() {
		String password = template.queryForObject("select password from users where username='joe'", String.class);
		assertNotNull(password);
		Collection<ScimUser> users = db.retrieveUsers("username='joe'; select " + SQL_INJECTION_FIELDS
				+ " from users where username='joe'");
		assertEquals(password, users.iterator().next().getId());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveUsersWithSqlInjectionAttackOnGt() {
		String password = template.queryForObject("select password from users where username='joe'", String.class);
		assertNotNull(password);
		Collection<ScimUser> users = db.retrieveUsers("username gt 'h'; select " + SQL_INJECTION_FIELDS
				+ " from users where username='joe'");
		assertEquals(password, users.iterator().next().getId());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveUsersWithSqlInjectionAttack() {
		String password = template.queryForObject("select password from users where username='joe'", String.class);
		assertNotNull(password);
		Collection<ScimUser> users = db.retrieveUsers("username eq 'joe'; select " + SQL_INJECTION_FIELDS
				+ " from users where username='joe'");
		assertEquals(password, users.iterator().next().getId());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveUsersWithAnotherSqlInjectionAttack() {
		String password = template.queryForObject("select password from users where username='joe'", String.class);
		assertNotNull(password);
		Collection<ScimUser> users = db.retrieveUsers("username eq 'joe''; select id from users where id='''; select "
				+ SQL_INJECTION_FIELDS + " from users where username='joe'");
		assertEquals(password, users.iterator().next().getId());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveUsersWithYetAnotherSqlInjectionAttack() {
		String password = template.queryForObject("select password from users where username='joe'", String.class);
		assertNotNull(password);
		Collection<ScimUser> users = db.retrieveUsers("username eq 'joe''; select " + SQL_INJECTION_FIELDS
				+ " from users where username='joe''");
		assertEquals(password, users.iterator().next().getId());
	}

	private void assertJoe(ScimUser joe) {
		assertNotNull(joe);
		assertEquals(JOE_ID, joe.getId());
		assertEquals("Joe", joe.getGivenName());
		assertEquals("User", joe.getFamilyName());
		assertEquals("joe@joe.com", joe.getPrimaryEmail());
		assertEquals("joe", joe.getUserName());
	}

}
