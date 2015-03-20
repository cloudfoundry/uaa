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

import java.util.Arrays;
import java.util.HashMap;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.test.JdbcTestBase;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.JdbcIdentityProviderProvisioning;
import org.codehaus.jackson.map.ObjectMapper;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class IdentityProviderBootstrapTest extends JdbcTestBase {

    @After
    @Before
    public void clearIdentityHolder() {
        IdentityZoneHolder.clear();
    }

    @Test
    public void testLdapBootstrap() throws Exception {
        IdentityProviderProvisioning provisioning = new JdbcIdentityProviderProvisioning(jdbcTemplate);
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning);
        HashMap<String, Object> ldapConfig = new HashMap<>();
        ldapConfig.put("testkey","testvalue");
        bootstrap.setLdapConfig(ldapConfig);
        bootstrap.afterPropertiesSet();

        IdentityProvider ldapProvider = provisioning.retrieveByOrigin(Origin.LDAP, IdentityZoneHolder.get().getId());
        assertNotNull(ldapProvider);
        assertEquals(new ObjectMapper().writeValueAsString(ldapConfig), ldapProvider.getConfig());
        assertNotNull(ldapProvider.getCreated());
        assertNotNull(ldapProvider.getLastModified());
        assertEquals(Origin.LDAP, ldapProvider.getType());
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
        IdentityProviderBootstrap bootstrap = new IdentityProviderBootstrap(provisioning);
        bootstrap.setSamlProviders(configurator);
        bootstrap.afterPropertiesSet();

        IdentityProvider samlProvider = provisioning.retrieveByOrigin(definition.getIdpEntityAlias(), IdentityZoneHolder.get().getId());
        assertNotNull(samlProvider);
        assertEquals(new ObjectMapper().writeValueAsString(definition), samlProvider.getConfig());
        assertNotNull(samlProvider.getCreated());
        assertNotNull(samlProvider.getLastModified());
        assertEquals(Origin.SAML, samlProvider.getType());
    }
}