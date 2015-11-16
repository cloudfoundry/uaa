/**
 *******************************************************************************
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
 *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.zone;

import org.cloudfoundry.identity.uaa.AbstractIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.KeystoneIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.saml.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class IdentityProviderTests {

    @Test
    public void configIsAlwaysValidWhenOriginIsOtherThanUaa() {
        IdentityProvider identityProvider = new IdentityProvider().setOriginKey(Origin.LDAP).setConfig(new LdapIdentityProviderDefinition());
        assertTrue(identityProvider.configIsValid());
    }

    @Test
    public void uaaConfigMustContainAllPasswordPolicyFields() {
        assertValidity(true, JsonUtils.readValue("",UaaIdentityProviderDefinition.class));
        assertValidity(true, JsonUtils.readValue("{\"passwordPolicy\": null}",UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"passwordPolicy\": {}}",UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"passwordPolicy\":{\"minLength\":6}}",UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128}}",UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1}}",UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1}}",UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1}}",UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0}}",UaaIdentityProviderDefinition.class));
        assertValidity(true, JsonUtils.readValue("{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}",UaaIdentityProviderDefinition.class));
    }

    @Test
    public void uaaConfigDoesNotAllowNegativeNumbersForPasswordPolicy() {
        assertValidity(false, JsonUtils.readValue("{\"passwordPolicy\":{\"minLength\":-6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}", UaaIdentityProviderDefinition.class));
        assertValidity(false, JsonUtils.readValue("{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":-128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}", UaaIdentityProviderDefinition.class));
        assertValidity(false, JsonUtils.readValue("{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":-1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}", UaaIdentityProviderDefinition.class));
        assertValidity(false, JsonUtils.readValue("{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":-1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}", UaaIdentityProviderDefinition.class));
        assertValidity(false, JsonUtils.readValue("{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":-1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":0}}", UaaIdentityProviderDefinition.class));
        assertValidity(false, JsonUtils.readValue("{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":-1,\"expirePasswordInMonths\":0}}", UaaIdentityProviderDefinition.class));
        assertValidity(false, JsonUtils.readValue("{\"passwordPolicy\":{\"minLength\":6,\"maxLength\":128,\"requireUpperCaseCharacter\":1,\"requireLowerCaseCharacter\":1,\"requireDigit\":1,\"requireSpecialCharacter\":0,\"expirePasswordInMonths\":-1}}", UaaIdentityProviderDefinition.class));
    }

    @Test
    public void uaaConfigMustContainAllLockoutPolicyFieldsIfSpecified() throws Exception {
        assertValidity(true, JsonUtils.readValue("", UaaIdentityProviderDefinition.class));
        assertValidity(true, JsonUtils.readValue("{\"lockoutPolicy\": null}", UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"lockoutPolicy\": {}}", UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":900}}", UaaIdentityProviderDefinition.class));
        assertValidity(false,JsonUtils.readValue( "{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":900,\"lockoutAfterFailures\":128}}", UaaIdentityProviderDefinition.class));
        assertValidity(true, JsonUtils.readValue("{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":900,\"lockoutAfterFailures\":128,\"countFailuresWithin\":1800}}", UaaIdentityProviderDefinition.class));
    }

    @Test
    public void uaaConfigDoesNotAllNegativeNumbersForLockoutPolicy() throws Exception {
        assertValidity(false, JsonUtils.readValue("{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":-6,\"lockoutAfterFailures\":128,\"countFailuresWithin\":1}}", UaaIdentityProviderDefinition.class));
        assertValidity(false, JsonUtils.readValue("{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":6,\"lockoutAfterFailures\":-128,\"countFailuresWithin\":1}}", UaaIdentityProviderDefinition.class));
        assertValidity(false, JsonUtils.readValue("{\"lockoutPolicy\":{\"lockoutPeriodSeconds\":6,\"lockoutAfterFailures\":128,\"countFailuresWithin\":-1}}", UaaIdentityProviderDefinition.class));
    }

    @Test
    public void test_serialize_uaa() {
        UaaIdentityProviderDefinition definition = new UaaIdentityProviderDefinition();
        IdentityProvider identityProvider = new IdentityProvider().setOriginKey(Origin.UAA).setConfig(definition);
        test_serialization(identityProvider);
    }

    @Test
    public void test_serialize_saml() {
        SamlIdentityProviderDefinition definition = new SamlIdentityProviderDefinition();
        definition.setMetaDataLocation("http://test.org");
        definition.setIdpEntityAlias(Origin.SAML);
        definition.setZoneId(IdentityZone.getUaa().getId());
        IdentityProvider identityProvider =
            new IdentityProvider()
                .setOriginKey(definition.getIdpEntityAlias())
                .setConfig(definition)
                .setIdentityZoneId(definition.getZoneId());
        test_serialization(identityProvider);
    }

    protected IdentityProvider test_serialization(IdentityProvider identityProvider) {
        String json = JsonUtils.writeValueAsString(identityProvider);
        IdentityProvider identityProvider2 = JsonUtils.readValue(json, IdentityProvider.class);
        assertNotNull(identityProvider2);
        assertEquals(identityProvider.getConfig(), identityProvider2.getConfig());
        return identityProvider2;
    }

    @Test
    public void test_serialize_ldap() {
        LdapIdentityProviderDefinition definition = new LdapIdentityProviderDefinition();
        IdentityProvider identityProvider = new IdentityProvider().setOriginKey(Origin.LDAP).setConfig(definition);
        test_serialization(identityProvider);
    }

    @Test
    public void test_serialize_keystone() {
        KeystoneIdentityProviderDefinition definition = new KeystoneIdentityProviderDefinition();
        IdentityProvider identityProvider = new IdentityProvider().setOriginKey(Origin.LDAP).setConfig(definition);
        test_serialization(identityProvider);
    }

    @Test
    public void test_serialize_other_origin() {
        AbstractIdentityProviderDefinition definition = new AbstractIdentityProviderDefinition();
        IdentityProvider identityProvider = new IdentityProvider().setOriginKey("other").setConfig(definition);
        IdentityProvider other = test_serialization(identityProvider);
        assertEquals("unknown", other.getType());
        assertEquals("other", other.getOriginKey());
        assertTrue(other.getConfig() instanceof AbstractIdentityProviderDefinition);
    }

    private void assertValidity(boolean expected, AbstractIdentityProviderDefinition config) {
        IdentityProvider identityProvider = new IdentityProvider().setOriginKey(Origin.UAA).setConfig(config);
        assertEquals(expected, identityProvider.configIsValid());
    }
}
