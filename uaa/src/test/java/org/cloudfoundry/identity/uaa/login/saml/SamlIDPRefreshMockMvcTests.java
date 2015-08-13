/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.login.saml;

import org.apache.commons.io.FileUtils;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.JsonUtils;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityProvider;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

import java.io.File;

import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.fail;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.xpath;

/**
 * This test ensures that UAA instances properly refresh the SAML providers from the database.
 */
public class SamlIDPRefreshMockMvcTests extends InjectedMockContextTest {

    private static final String DEFAULT_SIMPLE_SAML_METADATA = String.format(MockMvcUtils.IDP_META_DATA, "http://simplesamlphp.cfapps.io/saml2/idp/metadata.php");

    private UaaTestAccounts testAccounts;

    private JdbcTemplate jdbcTemplate;

    private IdentityProviderProvisioning providerProvisioning;

    private ZoneAwareMetadataManager zoneAwareMetadataManager;

    private IdentityZoneProvisioning zoneProvisioning;

    private IdentityProviderConfigurator configurator;

    @Before
    public void setUpContext() throws Exception {
        SecurityContextHolder.clearContext();
        testAccounts = UaaTestAccounts.standard(null);
        jdbcTemplate = getWebApplicationContext().getBean(JdbcTemplate.class);
        providerProvisioning = getWebApplicationContext().getBean(IdentityProviderProvisioning.class);
        zoneAwareMetadataManager = getWebApplicationContext().getBean(ZoneAwareMetadataManager.class);
        zoneProvisioning = getWebApplicationContext().getBean(IdentityZoneProvisioning.class);
        configurator = getWebApplicationContext().getBean(IdentityProviderConfigurator.class);
        //ensure that we don't fire the listener, we want to test the DB refresh
        getWebApplicationContext().getBean(ProviderChangedListener.class).setMetadataManager(null);
        cleanSamlProviders();

    }

    @After
    public void cleanSamlProviders() throws Exception {
        for (IdentityZone zone : zoneProvisioning.retrieveAll()) {
            for (IdentityProvider provider : providerProvisioning.retrieveAll(false, zone.getId())) {
                if (Origin.SAML.equals(provider.getType())) {
                    ZoneAwareMetadataManager.ExtensionMetadataManager manager = zoneAwareMetadataManager.getManager(zone);
                    IdentityProviderDefinition definition = provider.getConfigValue(IdentityProviderDefinition.class);
                    ExtendedMetadataDelegate delegate = configurator.getExtendedMetadataDelegateFromCache(definition);
                    configurator.removeIdentityProviderDefinition(definition);
                    if (delegate!=null) {
                        manager.removeMetadataProvider(delegate);
                    }
                    jdbcTemplate.update("delete from identity_provider where id='"+provider.getId()+"'");
                }
            }
            getMockMvc().perform(post("/saml/metadata").with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")));
            //all we have left is the local provider
            assertEquals(1, zoneAwareMetadataManager.getManager(zone).getAvailableProviders().size());
        }
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    public void testThatDBAddedXMLProviderShowsOnLoginPage() throws Exception {
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        IdentityProvider provider = createSamlProvider(DEFAULT_SIMPLE_SAML_METADATA, "simplesamlphp", "Log in with Simple Saml PHP Config");
        IdentityProviderDefinition definition = provider.getConfigValue(IdentityProviderDefinition.class);
        //ensure that the listener was not the one who created the provider
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that we have an actual SAML provider created


        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());
    }

    @Test
    public void test_Reject_Duplicate_Alias_and_Duplicate_Entity_ID() throws Exception {
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        IdentityProvider provider = createSamlProvider(DEFAULT_SIMPLE_SAML_METADATA, "simplesamlphp", "Log in with Simple Saml PHP Config");
        IdentityProviderDefinition definition = provider.getConfigValue(IdentityProviderDefinition.class);
        //ensure that the listener was not the one who created the provider
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that we have an actual SAML provider created

        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());

        //
        try {
            createSamlProvider(DEFAULT_SIMPLE_SAML_METADATA, "simplesamlphp", "Log in with Simple Saml PHP Config");
            fail("Should not be able to create a duplicate provider using alias 'simplesamlphp'");
        } catch (Exception e) {
            //expected
        }

        //adding another SAML provider - this one has the same entityID
        provider = createSamlProvider(DEFAULT_SIMPLE_SAML_METADATA, "simplesamlphp2", "Log in with Simple Saml PHP Config 2");
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());
        zoneAwareMetadataManager.refreshAllProviders();
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());

        definition = provider.getConfigValue(IdentityProviderDefinition.class);
        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").doesNotExist());
    }

    @Test
    public void testThatDBXMLDisabledProvider() throws Exception {
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        IdentityProvider provider = createSamlProvider(DEFAULT_SIMPLE_SAML_METADATA, "simplesamlphp", "Log in with Simple Saml PHP Config");
        IdentityProviderDefinition definition = provider.getConfigValue(IdentityProviderDefinition.class);
        //ensure that the listener was not the one who created the provider
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());

        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();

        //ensure that we have an actual SAML provider created
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());

        provider.setActive(false);
        provider = providerProvisioning.update(provider);
        definition = provider.getConfigValue(IdentityProviderDefinition.class);

        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();

        //ensure that we have an actual SAML provider created
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").doesNotExist());
    }

    @Test
    public void testThatDBAddedFileProviderShowsOnLoginPage() throws Exception {
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        IdentityProvider provider = createSamlProvider(getMetadataFile(DEFAULT_SIMPLE_SAML_METADATA).getAbsolutePath(), "simplesamlphp", "Log in with Simple Saml PHP File");
        IdentityProviderDefinition definition = provider.getConfigValue(IdentityProviderDefinition.class);
        //ensure that the listener was not the one who created the provider
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());

        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that we have an actual SAML provider created


        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());
    }

    @Test
    public void testThatDBFileDisabledProvider() throws Exception {
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        IdentityProvider provider = createSamlProvider(getMetadataFile(DEFAULT_SIMPLE_SAML_METADATA).getAbsolutePath(), "simplesamlphp", "Log in with Simple Saml PHP File");
        IdentityProviderDefinition definition = provider.getConfigValue(IdentityProviderDefinition.class);
        //ensure that the listener was not the one who created the provider
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());

        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();

        //ensure that we have an actual SAML provider created
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());

        provider.setActive(false);
        provider = providerProvisioning.update(provider);
        definition = provider.getConfigValue(IdentityProviderDefinition.class);

        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();

        //ensure that we have an actual SAML provider created
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").doesNotExist());
    }

    @Test
    public void testThatDBAddedUrlProviderShowsOnLoginPage() throws Exception {
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        IdentityProvider provider = createSamlProvider("http://simplesamlphp.cfapps.io/saml2/idp/metadata.php", "simplesamlphp", "Log in with Simple Saml PHP URL");
        IdentityProviderDefinition definition = provider.getConfigValue(IdentityProviderDefinition.class);
        //ensure that the listener was not the one who created the provider
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());

        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that we have an actual SAML provider created


        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());
    }

    @Test
    public void testThatDBFileUrlProvider() throws Exception {
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        IdentityProvider provider = createSamlProvider("http://simplesamlphp.cfapps.io/saml2/idp/metadata.php", "simplesamlphpurl", "Log in with Simple Saml PHP URL");
        IdentityProviderDefinition definition = provider.getConfigValue(IdentityProviderDefinition.class);
        //ensure that the listener was not the one who created the provider
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());

        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();

        //ensure that we have an actual SAML provider created
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());

        provider.setActive(false);
        provider = providerProvisioning.update(provider);
        definition = provider.getConfigValue(IdentityProviderDefinition.class);

        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();

        //ensure that we have an actual SAML provider created
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());

        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").doesNotExist());
    }

    @Test
    public void testThatDifferentMetadataLocationsShowsOnLoginPage() throws Exception {
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        IdentityProvider provider = createSamlProvider(DEFAULT_SIMPLE_SAML_METADATA, "simplesamlphp", "Log in with Simple Saml PHP Config");
        IdentityProviderDefinition definition = provider.getConfigValue(IdentityProviderDefinition.class);
        //ensure that the listener was not the one who created the provider
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());
        assertThat(zoneAwareMetadataManager.getAvailableProviders().get(1).getDelegate(), Matchers.instanceOf(ComparableProvider.class));
        assertThat(zoneAwareMetadataManager.getAvailableProviders().get(1).getDelegate(), Matchers.instanceOf(ConfigMetadataProvider.class));


        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());

        //change from XML content to a URL provider
        definition.setMetaDataLocation("http://simplesamlphp.cfapps.io/saml2/idp/metadata.php");
        provider.setConfig(JsonUtils.writeValueAsString(definition));
        providerProvisioning.update(provider);
        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());
        assertThat(zoneAwareMetadataManager.getAvailableProviders().get(1).getDelegate(), Matchers.instanceOf(ComparableProvider.class));
        assertThat(zoneAwareMetadataManager.getAvailableProviders().get(1).getDelegate(), Matchers.instanceOf(ConfigMetadataProvider.class));

        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());

        //change from URL content to a  File provider
        definition.setMetaDataLocation(getMetadataFile(DEFAULT_SIMPLE_SAML_METADATA).getAbsolutePath());
        provider.setConfig(JsonUtils.writeValueAsString(definition));
        providerProvisioning.update(provider);
        //this simulates what the timer does
        zoneAwareMetadataManager.refreshAllProviders();
        assertEquals(2, zoneAwareMetadataManager.getAvailableProviders().size());
        assertThat(zoneAwareMetadataManager.getAvailableProviders().get(1).getDelegate(), Matchers.instanceOf(ComparableProvider.class));
        assertThat(zoneAwareMetadataManager.getAvailableProviders().get(1).getDelegate(), Matchers.instanceOf(ConfigMetadataProvider.class));

        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());
    }

    @Test
    public void metadataInZoneGeneratesCorrectId() throws Exception {
        String zone1Name = "zone1";
        String zone2Name = "zone2";

        IdentityZone zone1 = new IdentityZone();
        zone1.setName(zone1Name);
        zone1.setSubdomain(zone1Name);
        zone1.setId(zone1Name);
        zone1 = zoneProvisioning.create(zone1);

        IdentityZone zone2 = new IdentityZone();
        zone2.setName(zone2Name);
        zone2.setSubdomain(zone2Name);
        zone2.setId(zone2Name);
        zone2 = zoneProvisioning.create(zone2);

        getMockMvc().perform(
            get("/saml/metadata")
                .with(new SetServerNameRequestPostProcessor(zone1.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("ID=\"zone1.cloudfoundry-saml-login\" entityID=\"zone1.cloudfoundry-saml-login\"")));

        getMockMvc().perform(
            get("/saml/metadata")
                .with(new SetServerNameRequestPostProcessor(zone2.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("ID=\"zone2.cloudfoundry-saml-login\" entityID=\"zone2.cloudfoundry-saml-login\"")));

    }

    public File getMetadataFile(String metadata) throws Exception {
        File f = File.createTempFile("saml-metadata", ".xml");
        FileUtils.write(f, metadata);
        return f;
    }

    public IdentityProvider createSamlProvider(String metadata, String alias, String linkText) {
        IdentityProviderDefinition definition = createSimplePHPSamlIDP(IdentityZone.getUaa().getId(), metadata, alias, linkText);
        IdentityProvider provider = new IdentityProvider();
        provider.setActive(true);
        provider.setConfig(JsonUtils.writeValueAsString(definition));
        provider.setIdentityZoneId(IdentityZone.getUaa().getId());
        provider.setOriginKey(alias);
        provider.setName("DB Added SAML Provider");
        provider.setType(Origin.SAML);
        provider = providerProvisioning.create(provider);
        return provider;
    }


    public IdentityProviderDefinition createSimplePHPSamlIDP(String zoneId, String metaData, String alias, String linkText) {
        IdentityProviderDefinition def = new IdentityProviderDefinition();
        def.setZoneId(zoneId);
        def.setMetaDataLocation(metaData);
        def.setNameID("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress");
        def.setAssertionConsumerIndex(0);
        def.setMetadataTrustCheck(false);
        def.setShowSamlLink(true);
        def.setIdpEntityAlias(alias);
        def.setLinkText(linkText);
        return def;
    }



}
