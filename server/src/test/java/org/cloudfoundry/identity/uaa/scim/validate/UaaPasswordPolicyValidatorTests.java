package org.cloudfoundry.identity.uaa.scim.validate;

import org.apache.commons.lang.RandomStringUtils;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mockito;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;

@ExtendWith(PollutionPreventionExtension.class)
class UaaPasswordPolicyValidatorTests {

    private IdentityProviderProvisioning provisioning = mock(IdentityProviderProvisioning.class);

    private UaaPasswordPolicyValidator validator;

    private IdentityProvider internalIDP;

    private PasswordPolicy defaultPolicy = new PasswordPolicy(0,255,0,0,0,0,0);
    private PasswordPolicy policy;

    @BeforeEach
    void setUp() {
        IdentityZoneHolder.set(IdentityZone.getUaa());
        validator = new UaaPasswordPolicyValidator(defaultPolicy, provisioning);

        internalIDP = new IdentityProvider();
        policy = new PasswordPolicy(10, 23, 1, 1, 1, 1, 6);
        UaaIdentityProviderDefinition idpDefinition = new UaaIdentityProviderDefinition(policy, null);
        internalIDP.setConfig(idpDefinition);

        Mockito.when(provisioning.retrieveByOriginIgnoreActiveFlag(OriginKeys.UAA, IdentityZone.getUaaZoneId()))
                .thenReturn(internalIDP);
    }

    @Test
    void min_password_length_is_always_1_if_set_to_0() {
        policy.setMinLength(0);
        validatePassword("", "Password must be at least 1 characters in length.");
        validatePassword(null, "Password must be at least 1 characters in length.");
    }

    @Test
    void min_password_length_is_always_1_if_not_set() {
        policy.setMinLength(-1);
        validatePassword("", "Password must be at least 1 characters in length.");
        validatePassword(null, "Password must be at least 1 characters in length.");
    }


    @Test
    void testValidateSuccess() {
        validatePassword("Password2&");
    }

    @Test
    void specialCharacterNotInListFailsValidation() {
        validatePassword("Passsss1\u007F", "Password must contain at least 1 special characters.");
    }

    @Test
    void testValidateWithNullPassword() {
        validatePassword(null, "Password must be at least 10 characters in length.");
    }

    @Test
    void testValidateShortPassword() {
        validatePassword("Pas1", "Password must be at least 10 characters in length.");
    }

    @Test
    void testValidateLongPassword() {
        validatePassword(RandomStringUtils.randomAlphanumeric(23) + "aA9", "Password must be no more than 23 characters in length.");
    }

    @Test
    void testValidateAllLowerCase() {
        validatePassword("password2", "Password must contain at least 1 uppercase characters.");
    }

    @Test
    void testValidateAllUpperCase() {
        validatePassword("PASSWORD2", "Password must contain at least 1 lowercase characters.");
    }

    @Test
    void testValidateNoDigits() {
        validatePassword("Password", "Password must contain at least 1 digit characters.");
    }

    @Test
    void testValidateWithNoSpecialCharacter() {
        validatePassword("Password123", "Password must contain at least 1 special characters.");
    }

    @Test
    void testValidationDisabledWhenZoneIsNotDefault() {
        IdentityZone identityZone = new IdentityZone();
        identityZone.setId("foo");
        IdentityZoneHolder.set(identityZone);
        validatePassword("Password123");
    }

    @Test
    void testValidateSpaceNotSpecialCharacter() {
        validatePassword("Password123 ", "Password must contain at least 1 special characters.");
    }

    private void validatePassword(String password, String ... expectedErrors) {
        ScimUser user = new ScimUser();
        user.setOrigin(OriginKeys.UAA);
        try {
            validator.validate(password);
            if (expectedErrors != null && expectedErrors.length > 0) {
                fail();
            }
        } catch (InvalidPasswordException e) {
            if (expectedErrors.length == 0) {
                fail("Didn't expect InvalidPasswordException, but messages were " + e.getErrorMessages());
            }
            for (String expectedError : expectedErrors) {
                assertTrue("Errors should contain:" + expectedError, e.getErrorMessages().contains(expectedError));
            }
        }
    }
}
