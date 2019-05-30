package org.cloudfoundry.identity.uaa.account;

import org.cloudfoundry.identity.uaa.annotations.WithDatabaseContext;
import org.cloudfoundry.identity.uaa.resources.jdbc.JdbcPagingListFactory;
import org.cloudfoundry.identity.uaa.resources.jdbc.LimitSqlAdapterFactory;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.scim.exception.ScimException;
import org.cloudfoundry.identity.uaa.scim.jdbc.JdbcScimUserProvisioning;
import org.cloudfoundry.identity.uaa.scim.validate.PasswordValidator;
import org.cloudfoundry.identity.uaa.security.SecurityContextAccessor;
import org.cloudfoundry.identity.uaa.util.FakePasswordEncoder;
import org.cloudfoundry.identity.uaa.zone.beans.IdentityZoneManager;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;

import static org.cloudfoundry.identity.uaa.util.AssertThrowsWithMessage.assertThrowsWithMessageThat;
import static org.hamcrest.Matchers.is;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.*;

@WithDatabaseContext
class PasswordChangeEndpointTests {

    private ScimUser joel;
    private ScimUser dale;

    private PasswordChangeEndpoint passwordChangeEndpoint;

    @BeforeEach
    void setup(@Autowired JdbcTemplate jdbcTemplate) {
        final JdbcScimUserProvisioning jdbcScimUserProvisioning = new JdbcScimUserProvisioning(
                jdbcTemplate,
                new JdbcPagingListFactory(jdbcTemplate, LimitSqlAdapterFactory.getLimitSqlAdapter()),
                new FakePasswordEncoder());

        final RandomValueStringGenerator generator = new RandomValueStringGenerator();

        final String currentIdentityZoneId = "currentIdentityZoneId-" + generator.generate();
        final IdentityZoneManager mockIdentityZoneManager = mock(IdentityZoneManager.class);
        when(mockIdentityZoneManager.getCurrentIdentityZoneId()).thenReturn(currentIdentityZoneId);

        passwordChangeEndpoint = new PasswordChangeEndpoint(mockIdentityZoneManager);
        passwordChangeEndpoint.setScimUserProvisioning(jdbcScimUserProvisioning);

        joel = new ScimUser(null, "jdsa", "Joel", "D'sa");
        joel.addEmail("jdsa@vmware.com");
        dale = new ScimUser(null, "olds", "Dale", "Olds");
        dale.addEmail("olds@vmware.com");
        joel = jdbcScimUserProvisioning.createUser(joel, "password", currentIdentityZoneId);
        dale = jdbcScimUserProvisioning.createUser(dale, "password", currentIdentityZoneId);
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

    private SecurityContextAccessor mockSecurityContext(ScimUser user) {
        SecurityContextAccessor sca = mock(SecurityContextAccessor.class);
        String id = user.getId();
        when(sca.getUserId()).thenReturn(id);
        return sca;
    }

    @Test
    void userCanChangeTheirOwnPasswordIfTheySupplyCorrectCurrentPassword() {
        passwordChangeEndpoint.setSecurityContextAccessor(mockSecurityContext(joel));
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setOldPassword("password");
        change.setPassword("newpassword");
        passwordChangeEndpoint.changePassword(joel.getId(), change);
    }

    @Test
    void passwordIsValidated() {
        passwordChangeEndpoint.setSecurityContextAccessor(mockSecurityContext(joel));
        PasswordValidator mockPasswordValidator = mock(PasswordValidator.class);
        passwordChangeEndpoint.setPasswordValidator(mockPasswordValidator);
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setOldPassword("password");
        change.setPassword("newpassword");
        passwordChangeEndpoint.changePassword(joel.getId(), change);
        verify(mockPasswordValidator).validate("newpassword");
    }

    @Test
    void userCantChangeAnotherUsersPassword() {
        passwordChangeEndpoint.setSecurityContextAccessor(mockSecurityContext(joel));
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setOldPassword("password");
        change.setPassword("newpassword");
        assertThrows(ScimException.class, () -> passwordChangeEndpoint.changePassword(dale.getId(), change));
    }

    @Test
    void adminCanChangeAnotherUsersPassword() {
        SecurityContextAccessor sca = mockSecurityContext(dale);
        when(sca.isAdmin()).thenReturn(true);
        passwordChangeEndpoint.setSecurityContextAccessor(sca);
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");
        passwordChangeEndpoint.changePassword(joel.getId(), change);
    }

    @Test
    void changePasswordRequestFailsForUserWithoutCurrentPassword() {
        passwordChangeEndpoint.setSecurityContextAccessor(mockSecurityContext(joel));
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");
        assertThrows(ScimException.class, () -> passwordChangeEndpoint.changePassword(joel.getId(), change));
    }

    @Test
    void changePasswordRequestFailsForAdminWithoutOwnCurrentPassword() {
        passwordChangeEndpoint.setSecurityContextAccessor(mockSecurityContext(joel));
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");
        assertThrows(ScimException.class, () -> passwordChangeEndpoint.changePassword(joel.getId(), change));
    }

    @Test
    void clientCanChangeUserPasswordWithoutCurrentPassword() {
        SecurityContextAccessor sca = mockSecurityContext(joel);
        when(sca.isClient()).thenReturn(true);
        passwordChangeEndpoint.setSecurityContextAccessor(sca);
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");
        passwordChangeEndpoint.changePassword(joel.getId(), change);
    }

    @Test
    void changePasswordFailsForUserIfTheySupplyWrongCurrentPassword() {
        passwordChangeEndpoint.setSecurityContextAccessor(mockSecurityContext(joel));
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("newpassword");
        change.setOldPassword("wrongpassword");
        assertThrows(BadCredentialsException.class, () -> passwordChangeEndpoint.changePassword(joel.getId(), change));
    }

    @Test
    void changePasswordFailsForNewPasswordIsSameAsCurrentPassword() {
        passwordChangeEndpoint.setSecurityContextAccessor(mockSecurityContext(joel));
        PasswordChangeRequest change = new PasswordChangeRequest();
        change.setPassword("password");
        change.setOldPassword("password");
        assertThrowsWithMessageThat(InvalidPasswordException.class,
                () -> passwordChangeEndpoint.changePassword(joel.getId(), change),
                is("Your new password cannot be the same as the old password."));
    }

}
