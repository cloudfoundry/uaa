package org.cloudfoundry.identity.uaa.password;

import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.impl.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.impl.NullPasswordValidator;
import org.cloudfoundry.identity.uaa.scim.dao.PasswordChangeRequest;
import org.cloudfoundry.identity.uaa.scim.dao.ScimUser;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PasswordChangeEndpointTests {

	private static ScimUser joel;

	private static ScimUser dale;

	private static PasswordChangeEndpoint endpoints;

	private static EmbeddedDatabase database;

	@BeforeClass
	public static void init() {
		EmbeddedDatabaseBuilder builder = new EmbeddedDatabaseBuilder();
		builder.addScript("classpath:/org/cloudfoundry/identity/uaa/schema-hsqldb.sql");
		database = builder.build();
		JdbcTemplate jdbcTemplate = new JdbcTemplate(database);
		JdbcScimUserProvisioning dao = new JdbcScimUserProvisioning(jdbcTemplate);
		dao.setPasswordEncoder(NoOpPasswordEncoder.getInstance());
		dao.setPasswordValidator(new NullPasswordValidator());

		endpoints = new PasswordChangeEndpoint(dao);

		joel = new ScimUser(null, "jdsa", "Joel", "D'sa");
		joel.addEmail("jdsa@vmware.com");
		dale = new ScimUser(null, "olds", "Dale", "Olds");
		dale.addEmail("olds@vmware.com");
		joel = dao.createUser(joel, "password");
		dale = dao.createUser(dale, "password");
	}

	@AfterClass
	public static void tearDown() throws Exception {
		TestUtils.deleteFrom(database, "users", "groups", "group_membership");
		if (database != null) {
			database.shutdown();
		}
	}

	private SecurityContextAccessor mockSecurityContext(ScimUser user) {
		SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
		String id = user.getId();
		when(sca.getUserId()).thenReturn(id);
		return sca;
	}

	@Test
	public void userCanChangeTheirOwnPasswordIfTheySupplyCorrectCurrentPassword() {
		endpoints.setSecurityContextAccessor(mockSecurityContext(joel));
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setOldPassword("password");
		change.setPassword("newpassword");
		endpoints.changePassword(joel.getId(), change);
	}

	@Ignore
	@Test(expected = ScimException.class)
	public void userCantChangeAnotherUsersPassword() {
		endpoints.setSecurityContextAccessor(mockSecurityContext(joel));
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setOldPassword("password");
		change.setPassword("newpassword");
		endpoints.changePassword(dale.getId(), change);
	}

	@Test
	public void adminCanChangeAnotherUsersPassword() {
		SecurityContextAccessor sca = mockSecurityContext(dale);
		when(sca.isAdmin()).thenReturn(true);
		endpoints.setSecurityContextAccessor(sca);
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("newpassword");
		endpoints.changePassword(joel.getId(), change);
	}

	@Test(expected = ScimException.class)
	public void changePasswordRequestFailsForUserWithoutCurrentPassword() {
		endpoints.setSecurityContextAccessor(mockSecurityContext(joel));
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("newpassword");
		endpoints.changePassword(joel.getId(), change);
	}

	@Test(expected = ScimException.class)
	public void changePasswordRequestFailsForAdminWithoutOwnCurrentPassword() {
		endpoints.setSecurityContextAccessor(mockSecurityContext(joel));
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("newpassword");
		endpoints.changePassword(joel.getId(), change);
	}

	@Test
	public void clientCanChangeUserPasswordWithoutCurrentPassword() {
		SecurityContextAccessor sca = mockSecurityContext(joel);
		when(sca.isClient()).thenReturn(true);
		endpoints.setSecurityContextAccessor(sca);
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("newpassword");
		endpoints.changePassword(joel.getId(), change);
	}

	@Test(expected = BadCredentialsException.class)
	public void changePasswordFailsForUserIfTheySupplyWrongCurrentPassword() {
		endpoints.setSecurityContextAccessor(mockSecurityContext(joel));
		PasswordChangeRequest change = new PasswordChangeRequest();
		change.setPassword("newpassword");
		change.setOldPassword("wrongpassword");
		endpoints.changePassword(joel.getId(), change);
	}

}
