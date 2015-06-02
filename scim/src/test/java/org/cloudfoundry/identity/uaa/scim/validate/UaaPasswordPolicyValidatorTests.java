package org.cloudfoundry.identity.uaa.scim.validate;

import org.apache.commons.lang.RandomStringUtils;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.config.PasswordPolicy;
import org.cloudfoundry.identity.uaa.scim.ScimUser;
import org.cloudfoundry.identity.uaa.scim.exception.InvalidPasswordException;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import java.util.HashMap;
import java.util.Map;

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
@RunWith(MockitoJUnitRunner.class)
public class UaaPasswordPolicyValidatorTests {

    @Mock
    private IdentityProviderProvisioning provisioning;

    private UaaPasswordPolicyValidator validator;

    private final PasswordPolicy PASSWORD_POLICY = PasswordPolicy.getDefault();

    @Before
    public void setUp() {
        PASSWORD_POLICY.setRequireAtLeastOneSpecialCharacter(true);
        IdentityZoneHolder.set(IdentityZone.getUaa());
        validator = new UaaPasswordPolicyValidator(provisioning);

        IdentityProvider internalIDP = new IdentityProvider();
        Map<String, Object> config = new HashMap<>();
        config.put(PasswordPolicy.PASSWORD_POLICY_FIELD, JsonUtils.convertValue(PASSWORD_POLICY, Map.class));
        internalIDP.setConfig(JsonUtils.writeValueAsString(config));

        Mockito.when(provisioning.retrieveByOrigin(Origin.UAA, IdentityZone.getUaa().getId()))
                .thenReturn(internalIDP);
    }

    @Test
    public void testValidateSuccess() {
        validatePassword("Password2&");
    }

    @Test(expected = IllegalArgumentException.class)
    public void testValidateWithNullPassword() {
        validatePassword(null);
    }

    @Test
    public void testValidateShortPassword() {
        validatePassword("Pas1", "Password must be greater than " + PASSWORD_POLICY.getMinLength() + " characters.");
    }

    @Test
    public void testValidateLongPassword() {
        validatePassword(RandomStringUtils.randomAlphanumeric(PASSWORD_POLICY.getMaxLength()) + "aA9", "Password must be shorter than " + PASSWORD_POLICY.getMaxLength() + " characters");
    }

    @Test
    public void testValidateAllLowerCase() {
        validatePassword("password2", "Password must contain at least one upper case character.");
    }

    @Test
    public void testValidateAllUpperCase() {
        validatePassword("PASSWORD2", "Password must contain at least one lower case character.");
    }

    @Test
    public void testValidateNoDigits() {
        validatePassword("Password", "Password must contain at least one digit.");
    }

    @Test
    public void tesValidateWithNoSpecialCharacter() {
        validatePassword("Password123", "Password must contain at least one non-alphanumeric character");
    }

    @Test
    public void testValidateWithUserFromAnotherOrigin() {
        ScimUser user = new ScimUser();
        user.setOrigin("simplesaml");
        validator.validate("");
    }

    @Test
    public void testInvalidPasswordForZone() {
        IdentityProvider zoneIDP = new IdentityProvider();
        Map<String, Object> config = new HashMap<>();
        config.put(PasswordPolicy.PASSWORD_POLICY_FIELD, JsonUtils.convertValue(PASSWORD_POLICY, Map.class));
        zoneIDP.setConfig(JsonUtils.writeValueAsString(config));

        IdentityZone zone = new IdentityZone();
        zone.setId("zone");

        Mockito.when(provisioning.retrieveByOrigin(Origin.UAA, zone.getId())).thenReturn(zoneIDP);
        IdentityZoneHolder.set(zone);

        ScimUser user = new ScimUser();
        validator.validate("a");
    }

    private void validatePassword(String password, String ... expectedErrors) {
        ScimUser user = new ScimUser();
        user.setOrigin(Origin.UAA);
        try {
            validator.validate(password);
            if (expectedErrors != null && expectedErrors.length > 0) {
                Assert.fail();
            }
        } catch (InvalidPasswordException e) {
            for (int i = 0; i < expectedErrors.length; i++) {
                Assert.assertTrue(e.getMessage().contains(expectedErrors[i]));
            }
        }
    }
}
