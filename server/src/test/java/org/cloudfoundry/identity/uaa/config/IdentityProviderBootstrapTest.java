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

import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.impl.config.IdentityProviderBootstrap;
import org.cloudfoundry.identity.uaa.provider.AbstractXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.JdbcIdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.KeystoneIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LdapIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.LockoutPolicy;
import org.cloudfoundry.identity.uaa.provider.PasswordPolicy;
import org.cloudfoundry.identity.uaa.provider.RawXOAuthIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.UaaIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.OIDCIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import static org.cloudfoundry.identity.uaa.constants.OriginKeys.KEYSTONE;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OAUTH20;
import static org.cloudfoundry.identity.uaa.constants.OriginKeys.OIDC10;
import static org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition.EMAIL_DOMAIN_ATTR;
import static org.cloudfoundry.identity.uaa.provider.AbstractIdentityProviderDefinition.PROVIDER_DESCRIPTION;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.ATTRIBUTE_MAPPINGS;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.EXTERNAL_GROUPS_WHITELIST;
import static org.cloudfoundry.identity.uaa.provider.ExternalIdentityProviderDefinition.STORE_CUSTOM_ATTRIBUTES_NAME;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;
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
    public void testUpgradeLDAPProvider() throws Exception {
        String insertSQL = "INSERT INTO identity_provider (id,identity_zone_id,name,origin_key,type,config)VALUES ('ldap','uaa','ldap','ldap2','ldap','{\"ldapdebug\":\"Test debug\",\"profile\":{\"file\":\"ldap/ldap-search-and-bind.xml\"},\"base\":{\"url\":\"ldap://localhost:389/\",\"userDn\":\"cn=admin,dc=test,dc=com\",\"password\":\"password\",\"searchBase\":\"dc=test,dc=com\",\"searchFilter\":\"cn={0}\",\"referral\":\"follow\"},\"groups\":{\"file\":\"ldap/ldap-groups-map-to-scopes.xml\",\"searchBase\":\"dc=test,dc=com\",\"groupSearchFilter\":\"member={0}\",\"searchSubtree\":true,\"maxSearchDepth\":10,\"autoAdd\":true,\"ignorePartialResultException\":true}}')";
        jdbcTemplate.update(insertSQL);
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, environment);
        bootstrap.afterPropertiesSet();
    }

    @Test
    public void testLdapProfileBootstrap() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        environment.setActiveProfiles(OriginKeys.LDAP);
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, environment);
        bootstrap.afterPropertiesSet();

        IdentityProvider<LdapIdentityProviderDefinition> ldapProvider = provisioning.retrieveByOrigin(OriginKeys.LDAP, IdentityZoneHolder.get().getId());
        assertNotNull(ldapProvider);
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(OriginKeys.LDAP, ldapProvider.getType());
        LdapIdentityProviderDefinition definition = ldapProvider.getConfig();
        assertNotNull(definition);
        assertFalse(definition.isConfigured());
    }

    @Test
    public void testLdapBootstrap() throws Exception {
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, new MockEnvironment());
        HashMap<String, Object> ldapConfig = new HashMap<>();

        ldapConfig.put(EMAIL_DOMAIN_ATTR, Arrays.asList("test.domain"));
        ldapConfig.put(STORE_CUSTOM_ATTRIBUTES_NAME, false);
        final String idpDescription = "Test LDAP Provider Description";
        ldapConfig.put(PROVIDER_DESCRIPTION, idpDescription);
        List<String> attrMap = new ArrayList<>();
        attrMap.add("value");
        ldapConfig.put(EXTERNAL_GROUPS_WHITELIST, attrMap);

        Map<String, Object> attributeMappings = new HashMap<>();
        attributeMappings.put("given_name", "first_name");
        ldapConfig.put(ATTRIBUTE_MAPPINGS, attributeMappings);

        bootstrap.setLdapConfig(ldapConfig);
        bootstrap.afterPropertiesSet();

        IdentityProvider<LdapIdentityProviderDefinition> ldapProvider = provisioning.retrieveByOrigin(OriginKeys.LDAP, IdentityZoneHolder.get().getId());
        assertNotNull(ldapProvider);
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(OriginKeys.LDAP, ldapProvider.getType());
        assertEquals("test.domain", ldapProvider.getConfig().getEmailDomain().get(0));
        assertEquals(Arrays.asList("value"), ldapProvider.getConfig().getExternalGroupsWhitelist());
        assertEquals("first_name", ldapProvider.getConfig().getAttributeMappings().get("given_name"));
        assertEquals(idpDescription, ldapProvider.getConfig().getProviderDescription());
        assertFalse(ldapProvider.getConfig().isStoreCustomAttributes());
    }

    @Test
    public void testRemovedLdapBootstrapIsInactive() throws Exception {
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles(OriginKeys.LDAP);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, env);
        HashMap<String, Object> ldapConfig = new HashMap<>();
        ldapConfig.put("base.url","ldap://localhost:389/");
        bootstrap.setLdapConfig(ldapConfig);
        bootstrap.afterPropertiesSet();

        IdentityProvider ldapProvider = provisioning.retrieveByOrigin(OriginKeys.LDAP, IdentityZoneHolder.get().getId());
        assertNotNull(ldapProvider);
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(OriginKeys.LDAP, ldapProvider.getType());
        assertTrue(ldapProvider.isActive());

        bootstrap.setLdapConfig(null);
        bootstrap.afterPropertiesSet();
        ldapProvider = provisioning.retrieveByOrigin(OriginKeys.LDAP, IdentityZoneHolder.get().getId());
        assertNotNull(ldapProvider);
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(OriginKeys.LDAP, ldapProvider.getType());
        assertFalse(ldapProvider.isActive());

        bootstrap.setLdapConfig(ldapConfig);
        bootstrap.afterPropertiesSet();
        ldapProvider = provisioning.retrieveByOrigin(OriginKeys.LDAP, IdentityZoneHolder.get().getId());
        assertNotNull(ldapProvider);
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(OriginKeys.LDAP, ldapProvider.getType());
        assertTrue(ldapProvider.isActive());
    }

    @Test
    public void testKeystoneProfileBootstrap() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        environment.setActiveProfiles(KEYSTONE);
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, environment);
        bootstrap.afterPropertiesSet();

        IdentityProvider<KeystoneIdentityProviderDefinition> keystoneProvider = provisioning.retrieveByOrigin(KEYSTONE, IdentityZoneHolder.get().getId());
        assertNotNull(keystoneProvider);
        assertEquals(new KeystoneIdentityProviderDefinition(), keystoneProvider.getConfig());
        assertNotNull(keystoneProvider.getCreated());
        assertNotNull(keystoneProvider.getLastModified());
        assertEquals(KEYSTONE, keystoneProvider.getType());
        assertNotNull(keystoneProvider.getConfig());
        assertNull(keystoneProvider.getConfig().getAdditionalConfiguration());
    }

    @Test
    public void testKeystoneBootstrap() throws Exception {
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, new MockEnvironment());
        HashMap<String, Object> keystoneConfig = new HashMap<>();
        keystoneConfig.put("testkey", "testvalue");
        bootstrap.setKeystoneConfig(keystoneConfig);
        bootstrap.afterPropertiesSet();

        IdentityProvider keystoneProvider = provisioning.retrieveByOrigin(KEYSTONE, IdentityZoneHolder.get().getId());
        assertNotNull(keystoneProvider);
        assertEquals(new KeystoneIdentityProviderDefinition(keystoneConfig), keystoneProvider.getConfig());
        assertNotNull(keystoneProvider.getCreated());
        assertNotNull(keystoneProvider.getLastModified());
        assertEquals(KEYSTONE, keystoneProvider.getType());
    }

    @Test
    public void testRemovedKeystoneBootstrapIsInactive() throws Exception {
        MockEnvironment env = new MockEnvironment();
        env.setActiveProfiles(KEYSTONE);
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, env);
        HashMap<String, Object> keystoneConfig = new HashMap<>();
        keystoneConfig.put("testkey", "testvalue");
        bootstrap.setKeystoneConfig(keystoneConfig);
        bootstrap.afterPropertiesSet();

        IdentityProvider<KeystoneIdentityProviderDefinition> keystoneProvider = provisioning.retrieveByOrigin(KEYSTONE, IdentityZoneHolder.get().getId());
        assertNotNull(keystoneProvider);
        assertEquals(new KeystoneIdentityProviderDefinition(keystoneConfig), keystoneProvider.getConfig());
        assertNotNull(keystoneProvider.getCreated());
        assertNotNull(keystoneProvider.getLastModified());
        assertEquals(KEYSTONE, keystoneProvider.getType());
        assertTrue(keystoneProvider.isActive());

        bootstrap.setKeystoneConfig(null);
        bootstrap.afterPropertiesSet();
        keystoneProvider = provisioning.retrieveByOrigin(KEYSTONE, IdentityZoneHolder.get().getId());
        assertNotNull(keystoneProvider);
        assertNotNull(keystoneProvider.getCreated());
        assertNotNull(keystoneProvider.getLastModified());
        assertEquals(KEYSTONE, keystoneProvider.getType());
        assertFalse(keystoneProvider.isActive());

        bootstrap.setKeystoneConfig(keystoneConfig);
        bootstrap.afterPropertiesSet();
        keystoneProvider = provisioning.retrieveByOrigin(KEYSTONE, IdentityZoneHolder.get().getId());
        assertNotNull(keystoneProvider);
        assertEquals(new KeystoneIdentityProviderDefinition(keystoneConfig), keystoneProvider.getConfig());
        assertNotNull(keystoneProvider.getCreated());
        assertNotNull(keystoneProvider.getLastModified());
        assertEquals(KEYSTONE, keystoneProvider.getType());
        assertTrue(keystoneProvider.isActive());
    }


    @Test
    public void testRemovedOAuthIdentityProviderIsInactive() throws Exception {
        AbstractXOAuthIdentityProviderDefinition oauthProvider = new RawXOAuthIdentityProviderDefinition();
        setCommonProperties(oauthProvider);
        AbstractXOAuthIdentityProviderDefinition oidcProvider = new OIDCIdentityProviderDefinition();
        setCommonProperties(oidcProvider);
        oidcProvider.setResponseType("code id_token");
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);

        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, new MockEnvironment());
        HashMap<String, AbstractXOAuthIdentityProviderDefinition> oauthProviderConfig = new HashMap<>();
        oauthProviderConfig.put(OAUTH20, oauthProvider);
        oauthProviderConfig.put(OIDC10, oidcProvider);
        bootstrap.setOauthIdpDefinitions(oauthProviderConfig);
        bootstrap.afterPropertiesSet();

        for (Map.Entry<String, AbstractXOAuthIdentityProviderDefinition> provider : oauthProviderConfig.entrySet()) {
            IdentityProvider<AbstractXOAuthIdentityProviderDefinition> bootstrapOauthProvider = provisioning.retrieveByOrigin(provider.getKey(), IdentityZoneHolder.get().getId());
            assertNotNull(bootstrapOauthProvider);
            assertThat(oauthProviderConfig.values(), PredicateMatcher.<AbstractXOAuthIdentityProviderDefinition>has(c -> c.equals(bootstrapOauthProvider.getConfig())));
            assertNotNull(bootstrapOauthProvider.getCreated());
            assertNotNull(bootstrapOauthProvider.getLastModified());
            assertEquals(provider.getKey(), bootstrapOauthProvider.getType());
            assertTrue(bootstrapOauthProvider.isActive());
            assertTrue(bootstrapOauthProvider.getConfig().isStoreCustomAttributes()); //default
            if (OIDC10.equals(provider.getKey())) {
                assertEquals("code id_token", bootstrapOauthProvider.getConfig().getResponseType());
            } else {
                assertEquals("code", bootstrapOauthProvider.getConfig().getResponseType());
            }

        }

        bootstrap.setOauthIdpDefinitions(null);
        bootstrap.afterPropertiesSet();
        for (Map.Entry<String, AbstractXOAuthIdentityProviderDefinition> provider : oauthProviderConfig.entrySet()) {
            IdentityProvider<AbstractXOAuthIdentityProviderDefinition> bootstrapOauthProvider = provisioning.retrieveByOrigin(provider.getKey(), IdentityZoneHolder.get().getId());
            assertNotNull(bootstrapOauthProvider);
            assertThat(oauthProviderConfig.values(), PredicateMatcher.<AbstractXOAuthIdentityProviderDefinition>has(c -> c.equals(bootstrapOauthProvider.getConfig())));
            assertNotNull(bootstrapOauthProvider.getCreated());
            assertNotNull(bootstrapOauthProvider.getLastModified());
            assertEquals(provider.getKey(), bootstrapOauthProvider.getType());
            assertFalse(bootstrapOauthProvider.isActive());
        }
    }

    @Test(expected = IllegalArgumentException.class)
    public void bootstrap_failsIf_samlAndOauth_haveTheSameAlias() throws Exception {
        AbstractXOAuthIdentityProviderDefinition oauthProvider = setCommonProperties(new RawXOAuthIdentityProviderDefinition());
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, new MockEnvironment());
        HashMap<String, AbstractXOAuthIdentityProviderDefinition> oauthProviderConfig = new HashMap<>();
        oauthProviderConfig.put("same-alias", oauthProvider);

        SamlIdentityProviderDefinition definition = new SamlIdentityProviderDefinition();
        definition.setIdpEntityAlias("same-alias");
        definition.setLinkText("text");
        definition.setMetaDataLocation("http://location");
        definition.setNameID("nameId");
        definition.setShowSamlLink(true);
        definition.setMetadataTrustCheck(true);

        BootstrapSamlIdentityProviderConfigurator configurator = mock(BootstrapSamlIdentityProviderConfigurator.class);
        when(configurator.getIdentityProviderDefinitions()).thenReturn(Arrays.asList(definition));

        bootstrap.setOauthIdpDefinitions(oauthProviderConfig);
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();
    }

    protected AbstractXOAuthIdentityProviderDefinition setCommonProperties(AbstractXOAuthIdentityProviderDefinition definition) throws MalformedURLException {
        return definition
            .setAuthUrl(new URL("http://auth.url"))
            .setLinkText("link text")
            .setRelyingPartyId("relaying party id")
            .setRelyingPartySecret("relaying party secret")
            .setShowLinkText(true)
            .setSkipSslValidation(true)
            .setTokenKey("key")
            .setTokenKeyUrl(new URL("http://token.key.url"));
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

        BootstrapSamlIdentityProviderConfigurator configurator = mock(BootstrapSamlIdentityProviderConfigurator.class);
        when(configurator.getIdentityProviderDefinitions()).thenReturn(Arrays.asList(definition));

        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, new MockEnvironment());
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        IdentityProvider samlProvider = provisioning.retrieveByOrigin(definition.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider);
        definition.setZoneId(IdentityZoneHolder.get().getId());
        assertEquals(definition, samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider.getType());
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

        BootstrapSamlIdentityProviderConfigurator configurator = mock(BootstrapSamlIdentityProviderConfigurator.class);
        when(configurator.getIdentityProviderDefinitions()).thenReturn(Arrays.asList(definition, definition2));

        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, new MockEnvironment());
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        IdentityProvider samlProvider = provisioning.retrieveByOrigin(definition.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider);
        definition.setZoneId(IdentityZoneHolder.get().getId());
        assertEquals(definition, samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider.getType());
        assertTrue(samlProvider.isActive());

        IdentityProvider samlProvider2 = provisioning.retrieveByOrigin(definition2.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider2);
        definition2.setZoneId(IdentityZoneHolder.get().getId());
        assertEquals(definition2, samlProvider2.getConfig());
        assertNotNull(samlProvider2.getCreated());
        assertNotNull(samlProvider2.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider2.getType());
        assertTrue(samlProvider2.isActive());

        configurator = mock(BootstrapSamlIdentityProviderConfigurator.class);
        when(configurator.getIdentityProviderDefinitions()).thenReturn(Arrays.asList(definition));
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        samlProvider = provisioning.retrieveByOrigin(definition.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider);
        assertEquals(definition, samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider.getType());
        assertTrue(samlProvider.isActive());

        samlProvider2 = provisioning.retrieveByOrigin(definition2.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider2);
        assertEquals(definition2, samlProvider2.getConfig());
        assertNotNull(samlProvider2.getCreated());
        assertNotNull(samlProvider2.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider2.getType());
        assertFalse(samlProvider2.isActive());

        configurator = mock(BootstrapSamlIdentityProviderConfigurator.class);
        when(configurator.getIdentityProviderDefinitions()).thenReturn(Arrays.asList(definition2));
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        samlProvider = provisioning.retrieveByOrigin(definition.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider);
        assertEquals(definition, samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider.getType());
        assertFalse(samlProvider.isActive());

        samlProvider2 = provisioning.retrieveByOrigin(definition2.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider2);
        assertEquals(definition2, samlProvider2.getConfig());
        assertNotNull(samlProvider2.getCreated());
        assertNotNull(samlProvider2.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider2.getType());
        assertTrue(samlProvider2.isActive());

        configurator = mock(BootstrapSamlIdentityProviderConfigurator.class);
        when(configurator.getIdentityProviderDefinitions()).thenReturn(new LinkedList<>());
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        samlProvider = provisioning.retrieveByOrigin(definition.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider);
        assertEquals(definition, samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider.getType());
        assertFalse(samlProvider.isActive());

        samlProvider2 = provisioning.retrieveByOrigin(definition2.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider2);
        assertEquals(definition2, samlProvider2.getConfig());
        assertNotNull(samlProvider2.getCreated());
        assertNotNull(samlProvider2.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider2.getType());
        assertFalse(samlProvider2.isActive());

        configurator = mock(BootstrapSamlIdentityProviderConfigurator.class);
        when(configurator.getIdentityProviderDefinitions()).thenReturn(Arrays.asList(definition2,definition));
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        samlProvider = provisioning.retrieveByOrigin(definition.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider);
        assertEquals(definition, samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider.getType());
        assertTrue(samlProvider.isActive());

        samlProvider2 = provisioning.retrieveByOrigin(definition2.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider2);
        assertEquals(definition2, samlProvider2.getConfig());
        assertNotNull(samlProvider2.getCreated());
        assertNotNull(samlProvider2.getLastModified());
        assertEquals(OriginKeys.SAML, samlProvider2.getType());
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

        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, mock);
        bootstrap.setDisableInternalUserManagement(Boolean.valueOf(expectedValue));

        bootstrap.afterPropertiesSet();
        IdentityProvider<UaaIdentityProviderDefinition> internalIDP = provisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaa().getId());

        if (expectedValue == null) {
            expectedValue = "false";
        }
        assertEquals(Boolean.valueOf(expectedValue), internalIDP.getConfig().isDisableInternalUserManagement());
    }

    @Test
    public void setPasswordPolicyToInternalIDP() throws Exception {
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, new MockEnvironment());
        bootstrap.setDefaultPasswordPolicy(new PasswordPolicy(123, 4567, 1, 0, 1, 0, 6));
        bootstrap.afterPropertiesSet();

        IdentityProvider<UaaIdentityProviderDefinition> internalIDP = provisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaa().getId());
        PasswordPolicy passwordPolicy = internalIDP.getConfig().getPasswordPolicy();
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

        IdentityProvider<UaaIdentityProviderDefinition> internalIDP = provisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaa().getId());
        lockoutPolicy = internalIDP.getConfig().getLockoutPolicy();

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

        IdentityProvider internalIdp =  provisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaa().getId());
        assertFalse(internalIdp.isActive());

        environment.setProperty("disableInternalAuth", "false");
        bootstrap.afterPropertiesSet();

        internalIdp =  provisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaa().getId());
        assertTrue(internalIdp.isActive());
    }

    @Test
    public void defaultActiveFlagOnInternalIDP() throws Exception {
        MockEnvironment environment = new MockEnvironment();
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning, environment);
        bootstrap.afterPropertiesSet();

        IdentityProvider internalIdp =  provisioning.retrieveByOrigin(OriginKeys.UAA, IdentityZone.getUaa().getId());
        assertTrue(internalIdp.isActive());
    }
}
