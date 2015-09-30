/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */

package org.cloudfoundry.identity.uaa.config;

import com.fasterxml.jackson.core.type.TypeReference;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.ldap.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.saml.SamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.login.saml.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.UaaIdentityProviderDefinition;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.AbstractIdentityProviderDefinition.EMAIL_DOMAIN_ATTR;
import static org.cloudfoundry.identity.uaa.ExternalIdentityProviderDefinition.EXTERNAL_GROUPS_WHITELIST;
import static org.cloudfoundry.identity.uaa.ExternalIdentityProviderDefinition.ATTRIBUTE_MAPPINGS;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class IdentityProviderBootstrapTest extends JdbcTestBase {

    @After
    @Before
    public void clearIdentityHolder() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void testLdapProfileBootstrap() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        environment.setActiveProfiles(Origin.LDAP);
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, environment);
        bootstrap.afterPropertiesSet();

        IdentityProvider ldapProvider = provisioning.retrieveByOrigin(Origin.LDAP, IdentityZoneHolder.get().getId());
        assertNotNull(ldapProvider);
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(Origin.LDAP, ldapProvider.getType());
        LdapIdentityProviderDefinition definition = ldapProvider.getConfigValue(LdapIdentityProviderDefinition.class);
        assertNotNull(definition);
        assertFalse(definition.isConfigured());
    }

    @Test
    public void testLdapBootstrap() throws Exception {
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, new MockEnvironment());
        HashMap<String, Object> ldapConfig = new HashMap<>();
        ldapConfig.put(EMAIL_DOMAIN_ATTR, Arrays.asList("test.domain"));
        List<String> attrMap = new ArrayList<>();
        attrMap.add("value");
        ldapConfig.put(EXTERNAL_GROUPS_WHITELIST, attrMap);

        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "first_name");
        ldapConfig.put(ATTRIBUTE_MAPPINGS, attributeMappings);

        bootstrap.setLdapConfig(ldapConfig);
        bootstrap.afterPropertiesSet();

        IdentityProvider ldapProvider = provisioning.retrieveByOrigin(Origin.LDAP, IdentityZoneHolder.get().getId());
        assertNotNull(ldapProvider);
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(Origin.LDAP, ldapProvider.getType());
        assertEquals("test.domain", ldapProvider.getConfigValue(LdapIdentityProviderDefinition.class).getEmailDomain().get(0));
        assertEquals(Arrays.asList("value"), ldapProvider.getConfigValue(LdapIdentityProviderDefinition.class).getExternalGroupsWhitelist());
        assertEquals("first_name", ldapProvider.getConfigValue(LdapIdentityProviderDefinition.class).getAttributeMappings().get("given_name"));
    }

    @Test
    public void testRemovedLdapBootstrapIsInactive() throws Exception {
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, new MockEnvironment());
        HashMap<String, Object> ldapConfig = new HashMap<>();
        ldapConfig.put("testkey","testvalue");
        bootstrap.setLdapConfig(ldapConfig);
        bootstrap.afterPropertiesSet();

        IdentityProvider ldapProvider = provisioning.retrieveByOrigin(Origin.LDAP, IdentityZoneHolder.get().getId());
        assertNotNull(ldapProvider);
        assertEquals(JsonUtils.writeValueAsString(LdapIdentityProviderDefinition.fromConfig(new HashMap<>())), ldapProvider.getConfig());
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(Origin.LDAP, ldapProvider.getType());
        assertTrue(ldapProvider.isActive());

        bootstrap.setLdapConfig(null);
        bootstrap.afterPropertiesSet();
        ldapProvider = provisioning.retrieveByOrigin(Origin.LDAP, IdentityZoneHolder.get().getId());
        assertNotNull(ldapProvider);
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(Origin.LDAP, ldapProvider.getType());
        assertFalse(ldapProvider.isActive());

        bootstrap.setLdapConfig(ldapConfig);
        bootstrap.afterPropertiesSet();
        ldapProvider = provisioning.retrieveByOrigin(Origin.LDAP, IdentityZoneHolder.get().getId());
        assertNotNull(ldapProvider);
        assertEquals(JsonUtils.writeValueAsString(new LdapIdentityProviderDefinition()), ldapProvider.getConfig());
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(Origin.LDAP, ldapProvider.getType());
        assertTrue(ldapProvider.isActive());
    }

    @Test
    public void testKeystoneProfileBootstrap() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        environment.setActiveProfiles(Origin.KEYSTONE);
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, environment);
        bootstrap.afterPropertiesSet();

        IdentityProvider keystoneProvider = provisioning.retrieveByOrigin(Origin.KEYSTONE, IdentityZoneHolder.get().getId());
        assertNotNull(keystoneProvider);
        assertEquals(IdentityProviderBootstrap.DEFAULT_MAP, keystoneProvider.getConfig());
        assertNotNull(keystoneProvider.getCreated());
        assertNotNull(keystoneProvider.getLastModified());
        assertEquals(Origin.KEYSTONE, keystoneProvider.getType());
        Map<String,Object> defaultMap = keystoneProvider.getConfigValue(new TypeReference<Map<String, Object>>() {});
        assertNotNull(defaultMap);
        assertEquals("default", defaultMap.get("default"));

    }

    @Test
    public void testKeystoneBootstrap() throws Exception {
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, new MockEnvironment());
        HashMap<String, Object> keystoneConfig = new HashMap<>();
        keystoneConfig.put("testkey", "testvalue");
        bootstrap.setKeystoneConfig(keystoneConfig);
        bootstrap.afterPropertiesSet();

        IdentityProvider keystoneProvider = provisioning.retrieveByOrigin(Origin.KEYSTONE, IdentityZoneHolder.get().getId());
        assertNotNull(keystoneProvider);
        assertEquals(JsonUtils.writeValueAsString(keystoneConfig), keystoneProvider.getConfig());
        assertNotNull(keystoneProvider.getCreated());
        assertNotNull(keystoneProvider.getLastModified());
        assertEquals(Origin.KEYSTONE, keystoneProvider.getType());
    }

    @Test
    public void testRemovedKeystoneBootstrapIsInactive() throws Exception {
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, new MockEnvironment());
        HashMap<String, Object> keystoneConfig = new HashMap<>();
        keystoneConfig.put("testkey", "testvalue");
        bootstrap.setKeystoneConfig(keystoneConfig);
        bootstrap.afterPropertiesSet();

        IdentityProvider keystoneProvider = provisioning.retrieveByOrigin(Origin.KEYSTONE, IdentityZoneHolder.get().getId());
        assertNotNull(keystoneProvider);
        assertEquals(JsonUtils.writeValueAsString(keystoneConfig), keystoneProvider.getConfig());
        assertNotNull(keystoneProvider.getCreated());
        assertNotNull(keystoneProvider.getLastModified());
        assertEquals(Origin.KEYSTONE, keystoneProvider.getType());
        assertTrue(keystoneProvider.isActive());

        bootstrap.setKeystoneConfig(null);
        bootstrap.afterPropertiesSet();
        keystoneProvider = provisioning.retrieveByOrigin(Origin.KEYSTONE, IdentityZoneHolder.get().getId());
        assertNotNull(keystoneProvider);
        assertNotNull(keystoneProvider.getCreated());
        assertNotNull(keystoneProvider.getLastModified());
        assertEquals(Origin.KEYSTONE, keystoneProvider.getType());
        assertFalse(keystoneProvider.isActive());

        bootstrap.setKeystoneConfig(keystoneConfig);
        bootstrap.afterPropertiesSet();
        keystoneProvider = provisioning.retrieveByOrigin(Origin.KEYSTONE, IdentityZoneHolder.get().getId());
        assertNotNull(keystoneProvider);
        assertEquals(JsonUtils.writeValueAsString(keystoneConfig), keystoneProvider.getConfig());
        assertNotNull(keystoneProvider.getCreated());
        assertNotNull(keystoneProvider.getLastModified());
        assertEquals(Origin.KEYSTONE, keystoneProvider.getType());
        assertTrue(keystoneProvider.isActive());
    }

    @Test
    public void testSamlBootstrap() throws Exception {
        SamlIdentityProviderDefinition definition = new SamlIdentityProviderDefinition();
        definition.setAssertionConsumerIndex(0);
        definition.setIconUrl("iconUrl");
        definition.setIdpEntityAlias("alias");
        definition.setLinkText("text");
        definition.setMetaDataLocation("http://location");
        definition.setNameID("nameId");
        definition.setShowSamlLink(true);
        definition.setMetadataTrustCheck(true);
        definition.setEmailDomain(Arrays.asList("test.domain"));
        List<String> externalGroupsWhitelist = new ArrayList<>();
        externalGroupsWhitelist.add("value1");
        externalGroupsWhitelist.add("value2");
        definition.setExternalGroupsWhitelist(externalGroupsWhitelist);

        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "first_name");
        definition.setAttributeMappings(attributeMappings);

        SamlIdentityProviderConfigurator configurator = mock(SamlIdentityProviderConfigurator.class);
        when(configurator.getIdentityProviderDefinitions()).thenReturn(Arrays.asList(definition));

        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, new MockEnvironment());
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        IdentityProvider samlProvider = provisioning.retrieveByOrigin(definition.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider);
        definition.setZoneId(IdentityZoneHolder.get().getId());
        assertEquals(JsonUtils.writeValueAsString(definition), samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(Origin.SAML, samlProvider.getType());
    }

    @Test
    public void testRemovedSamlBootstrapIsInactive() throws Exception {
        SamlIdentityProviderDefinition definition = new SamlIdentityProviderDefinition();
        definition.setAssertionConsumerIndex(0);
        definition.setIconUrl("iconUrl");
        definition.setIdpEntityAlias("alias");
        definition.setLinkText("text");
        definition.setMetaDataLocation("http://location");
        definition.setNameID("nameId");
        definition.setShowSamlLink(true);
        definition.setMetadataTrustCheck(true);

        SamlIdentityProviderDefinition definition2 = definition.clone();
        definition.setIdpEntityAlias("alias2");
        definition.setMetaDataLocation("http://location2");

        SamlIdentityProviderConfigurator configurator = mock(SamlIdentityProviderConfigurator.class);
        when(configurator.getIdentityProviderDefinitions()).thenReturn(Arrays.asList(definition, definition2));

        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, new MockEnvironment());
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        IdentityProvider samlProvider = provisioning.retrieveByOrigin(definition.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider);
        definition.setZoneId(IdentityZoneHolder.get().getId());
        assertEquals(JsonUtils.writeValueAsString(definition), samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(Origin.SAML, samlProvider.getType());
        assertTrue(samlProvider.isActive());

        IdentityProvider samlProvider2 = provisioning.retrieveByOrigin(definition2.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider2);
        definition2.setZoneId(IdentityZoneHolder.get().getId());
        assertEquals(JsonUtils.writeValueAsString(definition2), samlProvider2.getConfig());
        assertNotNull(samlProvider2.getCreated());
        assertNotNull(samlProvider2.getLastModified());
        assertEquals(Origin.SAML, samlProvider2.getType());
        assertTrue(samlProvider2.isActive());

        configurator = mock(SamlIdentityProviderConfigurator.class);
        when(configurator.getIdentityProviderDefinitions()).thenReturn(Arrays.asList(definition));
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        samlProvider = provisioning.retrieveByOrigin(definition.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider);
        assertEquals(JsonUtils.writeValueAsString(definition), samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(Origin.SAML, samlProvider.getType());
        assertTrue(samlProvider.isActive());

        samlProvider2 = provisioning.retrieveByOrigin(definition2.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider2);
        assertEquals(JsonUtils.writeValueAsString(definition2), samlProvider2.getConfig());
        assertNotNull(samlProvider2.getCreated());
        assertNotNull(samlProvider2.getLastModified());
        assertEquals(Origin.SAML, samlProvider2.getType());
        assertFalse(samlProvider2.isActive());

        configurator = mock(SamlIdentityProviderConfigurator.class);
        when(configurator.getIdentityProviderDefinitions()).thenReturn(Arrays.asList(definition2));
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        samlProvider = provisioning.retrieveByOrigin(definition.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider);
        assertEquals(JsonUtils.writeValueAsString(definition), samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(Origin.SAML, samlProvider.getType());
        assertFalse(samlProvider.isActive());

        samlProvider2 = provisioning.retrieveByOrigin(definition2.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider2);
        assertEquals(JsonUtils.writeValueAsString(definition2), samlProvider2.getConfig());
        assertNotNull(samlProvider2.getCreated());
        assertNotNull(samlProvider2.getLastModified());
        assertEquals(Origin.SAML, samlProvider2.getType());
        assertTrue(samlProvider2.isActive());

        configurator = mock(SamlIdentityProviderConfigurator.class);
        when(configurator.getIdentityProviderDefinitions()).thenReturn(new LinkedList<SamlIdentityProviderDefinition>());
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        samlProvider = provisioning.retrieveByOrigin(definition.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider);
        assertEquals(JsonUtils.writeValueAsString(definition), samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(Origin.SAML, samlProvider.getType());
        assertFalse(samlProvider.isActive());

        samlProvider2 = provisioning.retrieveByOrigin(definition2.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider2);
        assertEquals(JsonUtils.writeValueAsString(definition2), samlProvider2.getConfig());
        assertNotNull(samlProvider2.getCreated());
        assertNotNull(samlProvider2.getLastModified());
        assertEquals(Origin.SAML, samlProvider2.getType());
        assertFalse(samlProvider2.isActive());

        configurator = mock(SamlIdentityProviderConfigurator.class);
        when(configurator.getIdentityProviderDefinitions()).thenReturn(Arrays.asList(definition2,definition));
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        samlProvider = provisioning.retrieveByOrigin(definition.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider);
        assertEquals(JsonUtils.writeValueAsString(definition), samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(Origin.SAML, samlProvider.getType());
        assertTrue(samlProvider.isActive());

        samlProvider2 = provisioning.retrieveByOrigin(definition2.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider2);
        assertEquals(JsonUtils.writeValueAsString(definition2), samlProvider2.getConfig());
        assertNotNull(samlProvider2.getCreated());
        assertNotNull(samlProvider2.getLastModified());
        assertEquals(Origin.SAML, samlProvider2.getType());
        assertTrue(samlProvider2.isActive());

    }

    @Test
    public void setInternalUserManagementEnabled() throws Exception {
        setDisableInternalUserManagement("false");
    }

    @Test
    public void setInternalUserManagementDisabled() throws Exception {
        setDisableInternalUserManagement("true");
    }

    @Test
    public void setInternalUserManagementNotSet() throws Exception {
        setDisableInternalUserManagement(null);
    }

    private void setDisableInternalUserManagement(String expectedValue) throws Exception {
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);

        MockEnvironment mock = new MockEnvironment();

        if (expectedValue != null) {
            mock.withProperty("disableInternalUserManagement", expectedValue);
        }

        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, mock);

        IdentityProvider internalIDP = provisioning.retrieveByOrigin(Origin.UAA, IdentityZone.getUaa().getId());
        assertFalse(internalIDP.isDisableInternalUserManagement());
        bootstrap.afterPropertiesSet();

        internalIDP = provisioning.retrieveByOrigin(Origin.UAA, IdentityZone.getUaa().getId());

        if (expectedValue == null) {
            expectedValue = "false";
        }
        assertEquals(Boolean.valueOf(expectedValue), internalIDP.isDisableInternalUserManagement());
    }

    @Test
    public void setPasswordPolicyToInternalIDP() throws Exception {
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, new MockEnvironment());
        bootstrap.setDefaultPasswordPolicy(new PasswordPolicy(123, 4567, 1, 0, 1, 0, 6));
        bootstrap.afterPropertiesSet();

        IdentityProvider internalIDP = provisioning.retrieveByOrigin(Origin.UAA, IdentityZone.getUaa().getId());
        PasswordPolicy passwordPolicy = internalIDP.getConfigValue(UaaIdentityProviderDefinition.class).getPasswordPolicy();
        assertEquals(123, passwordPolicy.getMinLength());
        assertEquals(4567, passwordPolicy.getMaxLength());
        assertEquals(1, passwordPolicy.getRequireUpperCaseCharacter());
        assertEquals(0, passwordPolicy.getRequireLowerCaseCharacter());
        assertEquals(1, passwordPolicy.getRequireDigit());
        assertEquals(0, passwordPolicy.getRequireSpecialCharacter());
        assertEquals(6, passwordPolicy.getExpirePasswordInMonths());
    }

    @Test
    public void setLockoutPolicyToInternalIDP() throws Exception {
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, new MockEnvironment());
        LockoutPolicy lockoutPolicy = new LockoutPolicy();
        lockoutPolicy.setLockoutPeriodSeconds(123);
        lockoutPolicy.setLockoutAfterFailures(3);
        lockoutPolicy.setCountFailuresWithin(343);
        bootstrap.setDefaultLockoutPolicy(lockoutPolicy);
        bootstrap.afterPropertiesSet();

        IdentityProvider internalIDP = provisioning.retrieveByOrigin(Origin.UAA, IdentityZone.getUaa().getId());
        lockoutPolicy = internalIDP.getConfigValue(UaaIdentityProviderDefinition.class).getLockoutPolicy();

        assertEquals(123, lockoutPolicy.getLockoutPeriodSeconds());
        assertEquals(3, lockoutPolicy.getLockoutAfterFailures());
        assertEquals(343, lockoutPolicy.getCountFailuresWithin());
    }

    @Test
    public void deactivate_and_activate_InternalIDP() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        environment.setProperty("disableInternalAuth", "true");
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, environment);
        bootstrap.afterPropertiesSet();

        IdentityProvider internalIdp =  provisioning.retrieveByOrigin(Origin.UAA, IdentityZone.getUaa().getId());
        assertFalse(internalIdp.isActive());

        environment.setProperty("disableInternalAuth", "false");
        bootstrap.afterPropertiesSet();

        internalIdp =  provisioning.retrieveByOrigin(Origin.UAA, IdentityZone.getUaa().getId());
        assertTrue(internalIdp.isActive());
    }

    @Test
    public void defaultActiveFlagOnInternalIDP() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, environment);
        bootstrap.afterPropertiesSet();

        IdentityProvider internalIdp =  provisioning.retrieveByOrigin(Origin.UAA, IdentityZone.getUaa().getId());
        assertTrue(internalIdp.isActive());
    }
}
