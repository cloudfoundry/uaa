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
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityProviderProvisioning;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.Map;

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
        assertEquals(IdentityProviderBootstrap.DEFAULT_MAP, ldapProvider.getConfig());
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(Origin.LDAP, ldapProvider.getType());
        Map<String,Object> defaultMap = ldapProvider.getConfigValue(new TypeReference<Map<String, Object>>() {});
        assertNotNull(defaultMap);
        assertEquals("default", defaultMap.get("default"));
    }

    @Test
    public void testLdapBootstrap() throws Exception {
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, new MockEnvironment());
        HashMap<String, Object> ldapConfig = new HashMap<>();
        ldapConfig.put("testkey","testvalue");
        bootstrap.setLdapConfig(ldapConfig);
        bootstrap.afterPropertiesSet();

        IdentityProvider ldapProvider = provisioning.retrieveByOrigin(Origin.LDAP, IdentityZoneHolder.get().getId());
        assertNotNull(ldapProvider);
        assertEquals(JsonUtils.writeValueAsString(ldapConfig), ldapProvider.getConfig());
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(Origin.LDAP, ldapProvider.getType());
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
        assertEquals(JsonUtils.writeValueAsString(ldapConfig), ldapProvider.getConfig());
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
        assertEquals(JsonUtils.writeValueAsString(ldapConfig), ldapProvider.getConfig());
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
        IdentityProviderDefinition definition = new IdentityProviderDefinition();
        definition.setAssertionConsumerIndex(0);
        definition.setIconUrl("iconUrl");
        definition.setIdpEntityAlias("alias");
        definition.setLinkText("text");
        definition.setMetaDataLocation("http://location");
        definition.setNameID("nameId");
        definition.setShowSamlLink(true);
        definition.setMetadataTrustCheck(true);
        IdentityProviderConfigurator configurator = mock(IdentityProviderConfigurator.class);
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
        IdentityProviderDefinition definition = new IdentityProviderDefinition();
        definition.setAssertionConsumerIndex(0);
        definition.setIconUrl("iconUrl");
        definition.setIdpEntityAlias("alias");
        definition.setLinkText("text");
        definition.setMetaDataLocation("http://location");
        definition.setNameID("nameId");
        definition.setShowSamlLink(true);
        definition.setMetadataTrustCheck(true);

        IdentityProviderDefinition definition2 = definition.clone();
        definition.setIdpEntityAlias("alias2");
        definition.setMetaDataLocation("http://location2");

        IdentityProviderConfigurator configurator = mock(IdentityProviderConfigurator.class);
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

        configurator = mock(IdentityProviderConfigurator.class);
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

        configurator = mock(IdentityProviderConfigurator.class);
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

        configurator = mock(IdentityProviderConfigurator.class);
        when(configurator.getIdentityProviderDefinitions()).thenReturn(new LinkedList<IdentityProviderDefinition>());
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

        configurator = mock(IdentityProviderConfigurator.class);
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
}