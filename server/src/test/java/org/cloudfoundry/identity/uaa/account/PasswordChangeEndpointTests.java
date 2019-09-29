package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapterFactory;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.security.beans.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@WithDatabaseContext
class PasswordChangeEndpointTests {

    private ScimUser joel;
    private ScimUser dale;
    private PasswordChangeEndpoint passwordChangeEndpoint;
    private IdentityZoneManager mockIdentityZoneManager;
    private JdbcScimUserProvisioning jdbcScimUserProvisioning;
    private PasswordValidator mockPasswordValidator;
    private SecurityContextAccessor mockSecurityContextAccessor;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @BeforeEach
    void setup(@Autowired JdbcTemplate jdbcTemplate) {
        jdbcScimUserProvisioning = new JdbcScimUserProvisioning(
                jdbcTemplate,
                new JdbcPagingListFactory(jdbcTemplate, LimitSqlAdapterFactory.getLimitSqlAdapter()),
                passwordEncoder);

        final RandomValueStringGenerator generator = new RandomValueStringGenerator();

        final String currentIdentityZoneId = "currentIdentityZoneId-" + generator.generate();
        mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(currentIdentityZoneId);

        mockPasswordValidator = mock(PasswordValidator.class);
        mockSecurityContextAccessor = mock(SecurityContextAccessor.class);
        passwordChangeEndpoint = new PasswordChangeEndpoint(
                mockIdentityZoneManager,
                mockPasswordValidator,
                jdbcScimUserProvisioning,
                mockSecurityContextAccessor);

        joel = new ScimUser(null, "jdsa", "Joel", "D'sa");
        joel.addEmail("jdsa@vmware.com");
        dale = new ScimUser(null, "olds", "Dale", "Olds");
        dale.addEmail("olds@vmware.com");
        joel = jdbcScimUserProvisioning.createUser(joel, "password", currentIdentityZoneId);
        dale = jdbcScimUserProvisioning.createUser(dale, "password", currentIdentityZoneId);
        when(mockSecurityContextAccessor.getUserId()).thenReturn(joel.getId());
    }

    @AfterEach
    void clean(@Autowired JdbcTemplate jdbcTemplate) {
        if (joel != null) {
            jdbcTemplate.update("delete from users where id=?", joel.getId());
        }
        if (dale != null) {
            jdbcTemplate.update("delete from users where id=?", dale.getId());
        }
    }

    @Test
    void userCanChangeTheirOwnPasswordIfTheySupplyCorrectCurrentPassword() {
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setOldPassword("password");
        change.setPassword("newpassword");
        passwordChangeEndpoint.changePassword(joel.getId(), change);
    }

    @Test
    void passwordIsValidated() {
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setOldPassword("password");
        change.setPassword("newpassword");
        passwordChangeEndpoint.changePassword(joel.getId(), change);
        verify(mockPasswordValidator).validate("newpassword");
    }

    @Test
    void userCantChangeAnotherUsersPassword() {
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setOldPassword("password");
        change.setPassword("newpassword");
        assertThrows(ScimException.class, () -> passwordChangeEndpoint.changePassword(dale.getId(), change));
    }

    @Test
    void adminCanChangeAnotherUsersPassword() {
        when(mockSecurityContextAccessor.getUserId()).thenReturn(dale.getId());
        when(mockSecurityContextAccessor.isAdmin()).thenReturn(true);
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");
        passwordChangeEndpoint.changePassword(joel.getId(), change);
    }

    @Test
    void changePasswordRequestFailsForUserWithoutCurrentPassword() {
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");
        assertThrows(ScimException.class, () -> passwordChangeEndpoint.changePassword(joel.getId(), change));
    }

    @Test
    void changePasswordRequestFailsForAdminWithoutOwnCurrentPassword() {
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");
        assertThrows(ScimException.class, () -> passwordChangeEndpoint.changePassword(joel.getId(), change));
    }

    @Test
    void clientCanChangeUserPasswordWithoutCurrentPassword() {
        when(mockSecurityContextAccessor.isClient()).thenReturn(true);
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");
        passwordChangeEndpoint.changePassword(joel.getId(), change);
    }

    @Test
    void changePasswordFailsForUserIfTheySupplyWrongCurrentPassword() {
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");
        change.setOldPassword("wrongpassword");
        assertThrows(BadCredentialsException.class, () -> passwordChangeEndpoint.changePassword(joel.getId(), change));
    }

    @Test
    void changePasswordFailsForNewPasswordIsSameAsCurrentPassword() {
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("password");
        change.setOldPassword("password");
        assertThrowsWithMessageThat(InvalidPasswordException.class,
                () -> passwordChangeEndpoint.changePassword(joel.getId(), change),
                is("Your new password cannot be the same as the old password."));
    }

}
