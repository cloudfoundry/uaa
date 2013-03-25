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
package org.cloudfoundry.identity.uaa.scim.jdbc;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import javax.sql.DataSource;

import org.cloudfoundry.identity.uaa.rest.SimpleAttributeNameMapper;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.ScimUser.Group;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidScimResourceException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceAlreadyExistsException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimResourceNotFoundException;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.test.NullSafeSystemProfileValueSource;
import org.cloudfoundry.identity.uaa.user.UaaAuthority;
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
@IfProfileValue(name = "spring.profiles.active", values = { "", "test,postgresql", "hsqldb", "test,mysql" })
@ProfileValueSourceConfiguration(NullSafeSystemProfileValueSource.class)
public class JdbcScimUserProvisioningTests {

	@Autowired
	private DataSource dataSource;

	private JdbcTemplate template;

	private JdbcScimUserProvisioning db;

	private static final String JOE_ID = "550e8400-e29b-41d4-a716-446655440000";

	private static final String MABEL_ID = UUID.randomUUID().toString();

    private static final String SQL_INJECTION_FIELDS = "password,version,created,lastModified,username,email,givenName,familyName";

    private static final String addUserSqlFormat = "insert into users (id, username, password, email, givenName, familyName, phoneNumber) values ('%s','%s','%s','%s','%s','%s', '%s')";

    private static final String deleteUserSqlFormat = "delete from users where id='%s'";

    private int existingUserCount = 0;

	@Before
	public void createDatasource() throws Exception {

        template = new JdbcTemplate(dataSource);

		db = new JdbcScimUserProvisioning(template);
		ScimSearchQueryConverter filterConverter = new ScimSearchQueryConverter();
		Map<String, String> replaceWith = new HashMap<String, String>();
		replaceWith.put("emails\\.value", "email");
		replaceWith.put("groups\\.display", "authorities");
		replaceWith.put("phoneNumbers\\.value", "phoneNumber");
		filterConverter.setAttributeNameMapper(new SimpleAttributeNameMapper(replaceWith));
		db.setQueryConverter(filterConverter);
		BCryptPasswordEncoder pe = new BCryptPasswordEncoder(4);

		existingUserCount = template.queryForInt("select count(id) from users");

        addUser(JOE_ID, "joe", pe.encode("joespassword"), "joe@joe.com", "Joe", "User", "+1-222-1234567");
        addUser(MABEL_ID, "mabel", pe.encode("mabelspassword"), "mabel@mabel.com", "Mabel", "User", "");
	}

    private String createUserForDelete() {
        String tmpUserId = UUID.randomUUID().toString();
        addUser(tmpUserId, tmpUserId, "password", tmpUserId + "@delete.com", "ToDelete", "User", "+1-234-5678910");
        return tmpUserId;
    }

    private void addUser(String id, String username, String password, String email, String givenName, String familyName, String phoneNumber) {
        TestUtils.assertNoSuchUser(template, "id", id);
        template.execute(String.format(addUserSqlFormat, id, username, password, email, givenName, familyName, phoneNumber));
    }

    private void removeUser (String id) {
        template.execute(String.format(deleteUserSqlFormat, id));
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
		assertEquals("JO@FOO.COM", created.getUserName());
		assertNotNull(created.getId());
		assertNotSame(user.getId(), created.getId());
		Map<String, Object> map = template.queryForMap("select * from users where id=?", created.getId());
		assertEquals(user.getUserName(), map.get("userName"));
		assertEquals(user.getUserType(), map.get(UaaAuthority.UAA_USER.getUserType()));
		assertNull(created.getGroups());
	}

	@Test
	public void canCreateUserWithoutGivenNameAndFamilyName() {
		ScimUser user = new ScimUser(null, "JO@FOO.COM", null, null);
		user.addEmail("jo@blah.com");
		ScimUser created = db.createUser(user, "j7hyqpassX");
		assertEquals("JO@FOO.COM", created.getUserName());
		assertNotNull(created.getId());
		assertNotSame(user.getId(), created.getId());
		Map<String, Object> map = template.queryForMap("select * from users where id=?", created.getId());
		assertEquals(user.getUserName(), map.get("userName"));
		assertEquals(user.getUserType(), map.get(UaaAuthority.UAA_USER.getUserType()));
		assertNull(created.getGroups());
	}

	@Test(expected = InvalidScimResourceException.class)
	public void cannotCreateUserWithNonAsciiUsername() {
		ScimUser user = new ScimUser(null, "joe$eph", "Jo", "User");
		user.addEmail("jo@blah.com");
		db.createUser(user, "j7hyqpassX");
	}

	@Test
	public void updateModifiesExpectedData() {
		ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
		jo.addEmail("jo@blah.com");
		jo.setUserType(UaaAuthority.UAA_ADMIN.getUserType());

		ScimUser joe = db.update(JOE_ID, jo);

		// Can change username
		assertEquals("josephine", joe.getUserName());
		assertEquals("jo@blah.com", joe.getPrimaryEmail());
		assertEquals("Jo", joe.getGivenName());
		assertEquals("NewUser", joe.getFamilyName());
		assertEquals(1, joe.getVersion());
		assertEquals(JOE_ID, joe.getId());
		assertNull(joe.getGroups());
	}

	@Test
	public void updateCannotModifyGroups() {
		ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
		jo.addEmail("jo@blah.com");
		jo.setGroups(Collections.singleton(new Group(null, "dash/user")));

		ScimUser joe = db.update(JOE_ID, jo);

		assertEquals(JOE_ID, joe.getId());
		assertNull(joe.getGroups());
	}

	@Test(expected = OptimisticLockingFailureException.class)
	public void updateWithWrongVersionIsError() {
		ScimUser jo = new ScimUser(null, "josephine", "Jo", "NewUser");
		jo.addEmail("jo@blah.com");
		jo.setVersion(1);
		ScimUser joe = db.update(JOE_ID, jo);
		assertEquals("joe", joe.getUserName());
	}

	@Test(expected = InvalidScimResourceException.class)
	public void updateWithBadUsernameIsError() {
		ScimUser jo = new ScimUser(null, "jo$ephine", "Jo", "NewUser");
		jo.addEmail("jo@blah.com");
		jo.setVersion(1);
		ScimUser joe = db.update(JOE_ID, jo);
		assertEquals("joe", joe.getUserName());
	}

	@Test
	public void canChangePasswordWithouOldPassword() throws Exception {
		assertTrue(db.changePassword(JOE_ID, null, "koala123$marissa"));
		String storedPassword = template.queryForObject("SELECT password from users where ID=?", String.class, JOE_ID);
		assertTrue(BCrypt.checkpw("koala123$marissa", storedPassword));
	}

	@Test
	public void canChangePasswordWithCorrectOldPassword() throws Exception {
		assertTrue(db.changePassword(JOE_ID, "joespassword", "koala123$marissa"));
		String storedPassword = template.queryForObject("SELECT password from users where ID=?", String.class, JOE_ID);
		assertTrue(BCrypt.checkpw("koala123$marissa", storedPassword));
	}

	@Test(expected = BadCredentialsException.class)
	public void cannotChangePasswordNonexistentUser() {
		db.changePassword(JOE_ID, "notjoespassword", "newpassword");
	}

	@Test(expected = ScimResourceNotFoundException.class)
	public void cannotChangePasswordIfOldPasswordDoesntMatch() {
		assertTrue(db.changePassword("9999", null, "newpassword"));
	}

	@Test(expected = InvalidPasswordException.class)
	public void cannotChangePasswordToNewInvalidPassword() {
		db.changePassword(JOE_ID, "joespassword", "koala123$");
	}

	@Test
	public void canRetrieveExistingUser() {
		ScimUser joe = db.retrieve(JOE_ID);
		assertJoe(joe);
	}

	@Test(expected = ScimResourceNotFoundException.class)
	public void cannotRetrieveNonexistentUser() {
		ScimUser joe = db.retrieve("9999");
		assertJoe(joe);
	}

	@Test
	public void canDeactivateExistingUser() {
        String tmpUserId = createUserForDelete();
        ScimUser deletedUser = db.delete(tmpUserId, 0);
		assertEquals(1, template.queryForList("select * from users where id=? and active=false", tmpUserId).size());
		assertFalse(deletedUser.isActive());
		assertEquals(1, db.query("username eq '" + tmpUserId + "' and active eq false").size());
        removeUser(tmpUserId);
	}

	@Test(expected = ScimResourceAlreadyExistsException.class)
	public void cannotDeactivateExistingUserAndThenCreateHimAgain() {
        String tmpUserId = createUserForDelete();
        ScimUser deletedUser = db.delete(tmpUserId, 0);
        deletedUser.setActive(true);
		try {
        db.createUser(deletedUser, "foobarspam1234");
        } catch (ScimResourceAlreadyExistsException e) {
            removeUser(tmpUserId);
            throw e;
        }
	}

	@Test(expected = ScimResourceNotFoundException.class)
	public void cannotDeactivateNonexistentUser() {
		ScimUser joe = db.delete("9999", 0);
		assertJoe(joe);
	}

	@Test(expected = OptimisticLockingFailureException.class)
	public void deactivateWithWrongVersionIsError() {
		ScimUser joe = db.delete(JOE_ID, 1);
		assertJoe(joe);
	}

    @Test
    public void canDeleteExistingUser() {
        String tmpUserId = createUserForDelete();
        db.setDeactivateOnDelete(false);
        db.delete(tmpUserId, 0);
        assertEquals(0, template.queryForList("select * from users where id=?", tmpUserId).size());
        assertEquals(0, db.query("username eq '" + tmpUserId + "'").size());
    }

    @Test //(expected = ScimResourceAlreadyExistsException.class)
    public void canDeleteExistingUserAndThenCreateHimAgain() {
        String tmpUserId = createUserForDelete();
        db.setDeactivateOnDelete(false);
        ScimUser deletedUser = db.delete(tmpUserId, 0);
        assertEquals(0, template.queryForList("select * from users where id=?", tmpUserId).size());

        deletedUser.setActive(true);
        ScimUser user = db.createUser(deletedUser, "foobarspam1234");
        assertNotNull(user);
        assertNotNull(user.getId());
        assertNotSame(tmpUserId, user.getId());
        assertEquals(1, db.query("username eq '" + tmpUserId + "'").size());
        removeUser(user.getId());
    }

    @Test(expected = ScimResourceNotFoundException.class)
    public void cannotDeleteNonexistentUser() {
        db.setDeactivateOnDelete(false);
        ScimUser joe = db.delete("9999", 0);
        assertJoe(joe);
    }

    @Test(expected = OptimisticLockingFailureException.class)
    public void deleteWithWrongVersionIsError() {
        db.setDeactivateOnDelete(false);
        ScimUser joe = db.delete(JOE_ID, 1);
        assertJoe(joe);
    }

    @Test
	public void canRetrieveUsers() {
		assertTrue(2 <= db.retrieveAll().size());
	}

	@Test
	public void canRetrieveUsersWithFilterExists() {
		assertTrue(2 <= db.query("username pr").size());
	}

	@Test
	public void canRetrieveUsersWithFilterEquals() {
		assertEquals(1, db.query("username eq 'joe'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterEqualsDoubleQuote() {
		assertEquals(1, db.query("username eq \"joe\"").size());
	}

	@Test
	public void canRetrieveUsersWithFilterKeyCaseSensitivity() {
		// This actually depends on the RDBMS.
		assertEquals(1, db.query("USERNAME eq 'joe'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterOperatorCaseSensitivity() {
		// This actually depends on the RDBMS.
		assertEquals(1, db.query("username EQ 'joe'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterValueCaseSensitivity() {
		// This actually depends on the RDBMS.
		assertEquals(1, db.query("username eq 'Joe'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterContains() {
		assertEquals(2 + existingUserCount, db.query("username co 'e'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterStartsWith() {
		assertEquals(1 + existingUserCount, db.query("username sw 'joe'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterGreater() {
		assertEquals(1 + existingUserCount, db.query("username gt 'joe'").size());
	}

	@Test
	public void canRetrieveUsersWithEmailFilter() {
		assertEquals(1, db.query("emails.value sw 'joe'").size());
	}

	@Test
	public void canRetrieveUsersWithGroupsFilter() {
		assertEquals(2, db.query("groups.display co 'uaa.user'").size());
	}

	@Test
	public void canRetrieveUsersWithPhoneNumberFilter() {
		assertEquals(1, db.query("phoneNumbers.value sw '+1-222'").size());
	}

	@Test
	public void canRetrieveUsersWithMetaVersionFilter() {
		assertEquals(1, db.query("userName eq 'joe' and meta.version eq 0").size());
	}

	@Test
	public void canRetrieveUsersWithMetaDateFilter() {
		assertEquals(2 + existingUserCount, db.query("meta.created gt '1970-01-01T00:00:00.000Z'").size());
	}

	@Test
	public void canRetrieveUsersWithBooleanFilter() {
		assertEquals(2 + existingUserCount, db.query("username pr and active eq true").size());
	}

	@Test
	public void canRetrieveUsersWithSortBy() {
		assertEquals(2 + existingUserCount, db.query("username pr", "username", true).size());
	}

	@Test
	public void canRetrieveUsersWithSortByEmail() {
		assertEquals(2 + existingUserCount, db.query("username pr", "emails.value", true).size());
	}

	@Test
	public void canRetrieveUsersWithFilterBooleanAnd() {
		assertEquals(2 + existingUserCount, db.query("username pr and emails.value co '.com'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterBooleanOr() {
		assertEquals(2 + existingUserCount, db.query("username eq 'joe' or emails.value co '.com'").size());
	}

	@Test
	public void canRetrieveUsersWithFilterBooleanOrMatchesSecond() {
		assertEquals(1, db.query("username eq 'foo' or username eq 'joe'").size());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveUsersWithIllegalFilterField() {
		assertEquals(2, db.query("emails.type eq 'bar'").size());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveUsersWithIllegalPhoneNumberFilterField() {
		assertEquals(2, db.query("phoneNumbers.type eq 'bar'").size());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveUsersWithIllegalFilterQuotes() {
		assertEquals(2, db.query("username eq 'bar").size());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveUsersWithNativeSqlInjectionAttack() {
		String password = template.queryForObject("select password from users where username='joe'", String.class);
		assertNotNull(password);
		Collection<ScimUser> users = db.query("username='joe'; select " + SQL_INJECTION_FIELDS
				+ " from users where username='joe'");
		assertEquals(password, users.iterator().next().getId());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveUsersWithSqlInjectionAttackOnGt() {
		String password = template.queryForObject("select password from users where username='joe'", String.class);
		assertNotNull(password);
		Collection<ScimUser> users = db.query("username gt 'h'; select " + SQL_INJECTION_FIELDS
				+ " from users where username='joe'");
		assertEquals(password, users.iterator().next().getId());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveUsersWithSqlInjectionAttack() {
		String password = template.queryForObject("select password from users where username='joe'", String.class);
		assertNotNull(password);
		Collection<ScimUser> users = db.query("username eq 'joe'; select " + SQL_INJECTION_FIELDS
				+ " from users where username='joe'");
		assertEquals(password, users.iterator().next().getId());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveUsersWithAnotherSqlInjectionAttack() {
		String password = template.queryForObject("select password from users where username='joe'", String.class);
		assertNotNull(password);
		Collection<ScimUser> users = db.query("username eq 'joe''; select id from users where id='''; select "
				+ SQL_INJECTION_FIELDS + " from users where username='joe'");
		assertEquals(password, users.iterator().next().getId());
	}

	@Test(expected = IllegalArgumentException.class)
	public void cannotRetrieveUsersWithYetAnotherSqlInjectionAttack() {
		String password = template.queryForObject("select password from users where username='joe'", String.class);
		assertNotNull(password);
		Collection<ScimUser> users = db.query("username eq 'joe''; select " + SQL_INJECTION_FIELDS
				+ " from users where username='joe''");
		assertEquals(password, users.iterator().next().getId());
	}

	@Test
	public void filterEqWithoutQuotesIsRejected() {
		try {
			db.query("username eq joe");
			fail();
		}
		catch (Exception e) {
			assertTrue(e.getMessage().startsWith("Eq argument in filter"));
		}
	}

	private void assertJoe(ScimUser joe) {
		assertNotNull(joe);
		assertEquals(JOE_ID, joe.getId());
		assertEquals("Joe", joe.getGivenName());
		assertEquals("User", joe.getFamilyName());
		assertEquals("joe@joe.com", joe.getPrimaryEmail());
		assertEquals("joe", joe.getUserName());
		assertEquals("+1-222-1234567", joe.getPhoneNumbers().get(0).getValue());
		assertNull(joe.getGroups());
	}

}
