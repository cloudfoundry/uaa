package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapterFactory;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.test.TestUtils;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.util.FakePasswordEncoder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.flywaydb.core.Flyway;
import org.flywaydb.core.api.MigrationVersion;
import org.junit.jupiter.api.*;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabase;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.security.authentication.BadCredentialsException;

import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

class PasswordChangeEndpointTests {

    private ScimUser joel;

    private ScimUser dale;

    private PasswordChangeEndpoint endpoints;

    private static EmbeddedDatabase database;

    @BeforeAll
    static void init() {
        IdentityZoneHolder.clear();

        EmbeddedDatabaseBuilder builder = new EmbeddedDatabaseBuilder();
        database = builder.build();
        Flyway flyway = new Flyway();
        flyway.setBaselineVersion(MigrationVersion.fromVersion("1.5.2"));
        flyway.setLocations("classpath:/org/cloudfoundry/identity/uaa/db/hsqldb/");
        flyway.setDataSource(database);
        flyway.migrate();
    }

    @BeforeEach
    void setup() {
        JdbcTemplate jdbcTemplate = new JdbcTemplate(database);
        JdbcScimUserProvisioning dao = new JdbcScimUserProvisioning(
                jdbcTemplate,
                new JdbcPagingListFactory(jdbcTemplate, LimitSqlAdapterFactory.getLimitSqlAdapter()),
                new FakePasswordEncoder());

        endpoints = new PasswordChangeEndpoint();
        endpoints.setScimUserProvisioning(dao);

        joel = new ScimUser(null, "jdsa", "Joel", "D'sa");
        joel.addEmail("jdsa@vmware.com");
        dale = new ScimUser(null, "olds", "Dale", "Olds");
        dale.addEmail("olds@vmware.com");
        joel = dao.createUser(joel, "password", IdentityZoneHolder.get().getId());
        dale = dao.createUser(dale, "password", IdentityZoneHolder.get().getId());
    }

    @AfterEach
    void clean() {
        JdbcTemplate jdbcTemplate = new JdbcTemplate(database);
        if (joel != null) {
            jdbcTemplate.update("delete from users where id=?", joel.getId());
        }
        if (dale != null) {
            jdbcTemplate.update("delete from users where id=?", dale.getId());
        }
    }

    @AfterAll
    static void tearDown() {
        TestUtils.deleteFrom(new JdbcTemplate(database), "users", "groups", "group_membership");
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
    void userCanChangeTheirOwnPasswordIfTheySupplyCorrectCurrentPassword() {
        endpoints.setSecurityContextAccessor(mockSecurityContext(joel));
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setOldPassword("password");
        change.setPassword("newpassword");
        endpoints.changePassword(joel.getId(), change);
    }

    @Test
    void passwordIsValidated() {
        endpoints.setSecurityContextAccessor(mockSecurityContext(joel));
        PasswordValidator mockPasswordValidator = mock(PasswordValidator.class);
        endpoints.setPasswordValidator(mockPasswordValidator);
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setOldPassword("password");
        change.setPassword("newpassword");
        endpoints.changePassword(joel.getId(), change);
        verify(mockPasswordValidator).validate("newpassword");
    }

    @Test
    void userCantChangeAnotherUsersPassword() {
        endpoints.setSecurityContextAccessor(mockSecurityContext(joel));
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setOldPassword("password");
        change.setPassword("newpassword");
        assertThrows(ScimException.class, () -> endpoints.changePassword(dale.getId(), change));
    }

    @Test
    void adminCanChangeAnotherUsersPassword() {
        SecurityContextAccessor sca = mockSecurityContext(dale);
        when(sca.isAdmin()).thenReturn(true);
        endpoints.setSecurityContextAccessor(sca);
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");
        endpoints.changePassword(joel.getId(), change);
    }

    @Test
    void changePasswordRequestFailsForUserWithoutCurrentPassword() {
        endpoints.setSecurityContextAccessor(mockSecurityContext(joel));
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");
        assertThrows(ScimException.class, () -> endpoints.changePassword(joel.getId(), change));
    }

    @Test
    void changePasswordRequestFailsForAdminWithoutOwnCurrentPassword() {
        endpoints.setSecurityContextAccessor(mockSecurityContext(joel));
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");
        assertThrows(ScimException.class, () -> endpoints.changePassword(joel.getId(), change));
    }

    @Test
    void clientCanChangeUserPasswordWithoutCurrentPassword() {
        SecurityContextAccessor sca = mockSecurityContext(joel);
        when(sca.isClient()).thenReturn(true);
        endpoints.setSecurityContextAccessor(sca);
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");
        endpoints.changePassword(joel.getId(), change);
    }

    @Test
    void changePasswordFailsForUserIfTheySupplyWrongCurrentPassword() {
        endpoints.setSecurityContextAccessor(mockSecurityContext(joel));
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");
        change.setOldPassword("wrongpassword");
        assertThrows(BadCredentialsException.class, () -> endpoints.changePassword(joel.getId(), change));
    }

    @Test
    void changePasswordFailsForNewPasswordIsSameAsCurrentPassword() {
        endpoints.setSecurityContextAccessor(mockSecurityContext(joel));
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("password");
        change.setOldPassword("password");
        assertThrowsWithMessageThat(InvalidPasswordException.class,
                () -> endpoints.changePassword(joel.getId(), change),
                is("Your new password cannot be the same as the old password."));
    }

}
