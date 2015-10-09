package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.junit.Test;

import static org.junit.Assert.*;

/*******************************************************************************
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
 *******************************************************************************/
public class IdentityProviderTest {

    @Test
    public void configIsAlwaysValidWhenOriginIsOtherThanUaa() {
        IdentityProvider identityProvider = new IdentityProvider().setOriginKey(Origin.LDAP).setConfig("abcde");
        assertTrue(identityProvider.configIsValid());
    }

    @Test
    public void uaaConfigMustContainAllPasswordPolicyFields() {
        assertValidity(true, "");
        assertValidity(true, "{\"passwordPolicy\": null}");
        assertValidity(false, "{\"passwordPolicy\": {}}");
        assertValidity(false, "{\"passwordPolicy\":{\"minLength\":6}}");
        assertValidity(false, "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128}}");
        assertValidity(false, "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1}}");
        assertValidity(false, "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1}}");
        assertValidity(false, "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1}}");
        assertValidity(false, "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0}}");
        assertValidity(true, "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}");
    }

    @Test
    public void uaaConfigDoesNotAllowNegativeNumbersForPasswordPolicy() {
        assertValidity(false, "{\"passwordPolicy\":{\"minLength\":-6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}");
        assertValidity(false, "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":-128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}");
        assertValidity(false, "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":-1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}");
        assertValidity(false, "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":-1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}");
        assertValidity(false, "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":-1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}");
        assertValidity(false, "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":-1,\"expirePasswordInMonths\":0}}");
        assertValidity(false, "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":-1}}");
    }

    @Test
    public void uaaConfigMustContainAllLockoutPolicyFieldsIfSpecified() throws Exception {
        assertValidity(true, "");
        assertValidity(true, "{\"lockoutPolicy\": null}");
        assertValidity(false, "{\"lockoutPolicy\": {}}");
        assertValidity(false, "{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":900}}");
        assertValidity(false, "{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":900,\"lockoutAfterFailures\":128}}");
        assertValidity(true, "{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":900,\"lockoutAfterFailures\":128,\"countFailuresWithin\":1800}}");
    }

    @Test
    public void uaaConfigDoesNotAllNegativeNumbersForLockoutPolicy() throws Exception {
        assertValidity(false, "{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":-6,\"lockoutAfterFailures\":128,\"countFailuresWithin\":1}}");
        assertValidity(false, "{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":6,\"lockoutAfterFailures\":-128,\"countFailuresWithin\":1}}");
        assertValidity(false, "{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":6,\"lockoutAfterFailures\":128,\"countFailuresWithin\":-1}}");
    }

    private void assertValidity(boolean expected, String config) {
        IdentityProvider identityProvider = new IdentityProvider().setOriginKey(Origin.UAA).setConfig(config);
        assertEquals(expected, identityProvider.configIsValid());
    }
}
