/**
 * ****************************************************************************
 * Cloud Foundry
 * Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 * <p/>
 * This product is licensed to you under the Apache License, Version 2.0 (the "License").
 * You may not use this product except in compliance with the License.
 * <p/>
 * This product includes a number of subcomponents with
 * separate copyright notices and license terms. Your use of these
 * subcomponents is subject to the terms and conditions of the
 * subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.scim.validate;

import org.apache.commons.lang.RandomStringUtils;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

@RunWith(MockitoJUnitRunner.class)
public class UaaPasswordPolicyValidatorTests {

    @Mock
    private IdentityProviderProvisioning provisioning;

    private UaaPasswordPolicyValidator validator;

    private IdentityProvider internalIDP;

    private PasswordPolicy defaultPolicy = new PasswordPolicy(0,255,0,0,0,0,0);
    private PasswordPolicy policy;

    @Before
    public void setUp() {
        IdentityZoneHolder.set(IdentityZone.getUaa());
        validator = new UaaPasswordPolicyValidator(defaultPolicy, provisioning);

        internalIDP = new IdentityProvider();
        policy = new PasswordPolicy(10, 23, 1, 1, 1, 1, 6);
        UaaIdentityProviderDefinition idpDefinition = new UaaIdentityProviderDefinition(policy, null);
        internalIDP.setConfig(idpDefinition);

        Mockito.when(provisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaa().getId()))
                .thenReturn(internalIDP);
    }

    @Test
    public void min_password_length_is_always_1_if_set_to_0() {
        policy.setMinLength(0);
        validatePassword("", "Password must be at least 1 characters in length.");
        validatePassword(null, "Password must be at least 1 characters in length.");
    }

    @Test
    public void min_password_length_is_always_1_if_not_set() {
        policy.setMinLength(-1);
        validatePassword("", "Password must be at least 1 characters in length.");
        validatePassword(null, "Password must be at least 1 characters in length.");
    }


    @Test
    public void testValidateSuccess() {
        validatePassword("Password2&");
    }

    @Test
    public void specialCharacterNotInListFailsValidation() {
        validatePassword("Passsss1\u007F", "Password must contain at least 1 special characters.");
    }

    @Test
    public void testValidateWithNullPassword() {
        validatePassword(null, "Password must be at least 10 characters in length.");
    }

    @Test
    public void testValidateShortPassword() {
        validatePassword("Pas1", "Password must be at least 10 characters in length.");
    }

    @Test
    public void testValidateLongPassword() {
        validatePassword(RandomStringUtils.randomAlphanumeric(23) + "aA9", "Password must be no more than 23 characters in length.");
    }

    @Test
    public void testValidateAllLowerCase() {
        validatePassword("password2", "Password must contain at least 1 uppercase characters.");
    }

    @Test
    public void testValidateAllUpperCase() {
        validatePassword("PASSWORD2", "Password must contain at least 1 lowercase characters.");
    }

    @Test
    public void testValidateNoDigits() {
        validatePassword("Password", "Password must contain at least 1 digit characters.");
    }

    @Test
    public void testValidateWithNoSpecialCharacter() {
        validatePassword("Password123", "Password must contain at least 1 special characters.");
    }

    @Test
    public void testValidationDisabledWhenZoneIsNotDefault() {
        IdentityZoneHolder.set(new IdentityZone().setId("foo"));
        validatePassword("Password123");
    }

    @Test
    public void testValidateSpaceNotSpecialCharacter() throws Exception {
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
            for (int i = 0; i < expectedErrors.length; i++) {
                assertTrue("Errors should contain:"+expectedErrors[i], e.getErrorMessages().contains(expectedErrors[i]));
            }
        }
    }
}
