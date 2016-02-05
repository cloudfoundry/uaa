/*******************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2016] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 *******************************************************************************/
package org.cloudfoundry.identity.uaa.provider.saml;

import org.cloudfoundry.identity.uaa.audit.event.EntityDeletedEvent;
import org.cloudfoundry.identity.uaa.constants.OriginKeys;
import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.mock.util.MockMvcUtils;
import org.cloudfoundry.identity.uaa.provider.IdentityProvider;
import org.cloudfoundry.identity.uaa.provider.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.test.MockAuthentication;
import org.cloudfoundry.identity.uaa.test.UaaTestAccounts;
import org.cloudfoundry.identity.uaa.util.SetServerNameRequestPostProcessor;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.hamcrest.Matchers;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.saml.metadata.ExtendedMetadataDelegate;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.Matchers.containsString;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertThat;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.springframework.http.MediaType.TEXT_HTML;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.redirectedUrl;
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

    private SamlIdentityProviderConfigurator configurator;

    private final String serviceProviderKey =
        "-----BEGIN RSA PRIVATE KEY-----\n" +
        "MIICXQIBAAKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5\n" +
        "L39WqS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vA\n" +
        "fpOwznoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQAB\n" +
        "AoGAVOj2Yvuigi6wJD99AO2fgF64sYCm/BKkX3dFEw0vxTPIh58kiRP554Xt5ges\n" +
        "7ZCqL9QpqrChUikO4kJ+nB8Uq2AvaZHbpCEUmbip06IlgdA440o0r0CPo1mgNxGu\n" +
        "lhiWRN43Lruzfh9qKPhleg2dvyFGQxy5Gk6KW/t8IS4x4r0CQQD/dceBA+Ndj3Xp\n" +
        "ubHfxqNz4GTOxndc/AXAowPGpge2zpgIc7f50t8OHhG6XhsfJ0wyQEEvodDhZPYX\n" +
        "kKBnXNHzAkEAyCA76vAwuxqAd3MObhiebniAU3SnPf2u4fdL1EOm92dyFs1JxyyL\n" +
        "gu/DsjPjx6tRtn4YAalxCzmAMXFSb1qHfwJBAM3qx3z0gGKbUEWtPHcP7BNsrnWK\n" +
        "vw6By7VC8bk/ffpaP2yYspS66Le9fzbFwoDzMVVUO/dELVZyBnhqSRHoXQcCQQCe\n" +
        "A2WL8S5o7Vn19rC0GVgu3ZJlUrwiZEVLQdlrticFPXaFrn3Md82ICww3jmURaKHS\n" +
        "N+l4lnMda79eSp3OMmq9AkA0p79BvYsLshUJJnvbk76pCjR28PK4dV1gSDUEqQMB\n" +
        "qy45ptdwJLqLJCeNoR0JUcDNIRhOCuOPND7pcMtX6hI/\n" +
        "-----END RSA PRIVATE KEY-----";

    private final String serviceProviderKeyPassword = "password";

    private final String serviceProviderCertificate =
        "-----BEGIN CERTIFICATE-----\n" +
        "MIIDSTCCArKgAwIBAgIBADANBgkqhkiG9w0BAQQFADB8MQswCQYDVQQGEwJhdzEO\n" +
        "MAwGA1UECBMFYXJ1YmExDjAMBgNVBAoTBWFydWJhMQ4wDAYDVQQHEwVhcnViYTEO\n" +
        "MAwGA1UECxMFYXJ1YmExDjAMBgNVBAMTBWFydWJhMR0wGwYJKoZIhvcNAQkBFg5h\n" +
        "cnViYUBhcnViYS5hcjAeFw0xNTExMjAyMjI2MjdaFw0xNjExMTkyMjI2MjdaMHwx\n" +
        "CzAJBgNVBAYTAmF3MQ4wDAYDVQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAM\n" +
        "BgNVBAcTBWFydWJhMQ4wDAYDVQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAb\n" +
        "BgkqhkiG9w0BCQEWDmFydWJhQGFydWJhLmFyMIGfMA0GCSqGSIb3DQEBAQUAA4GN\n" +
        "ADCBiQKBgQDHtC5gUXxBKpEqZTLkNvFwNGnNIkggNOwOQVNbpO0WVHIivig5L39W\n" +
        "qS9u0hnA+O7MCA/KlrAR4bXaeVVhwfUPYBKIpaaTWFQR5cTR1UFZJL/OF9vAfpOw\n" +
        "znoD66DDCnQVpbCjtDYWX+x6imxn8HCYxhMol6ZnTbSsFW6VZjFMjQIDAQABo4Ha\n" +
        "MIHXMB0GA1UdDgQWBBTx0lDzjH/iOBnOSQaSEWQLx1syGDCBpwYDVR0jBIGfMIGc\n" +
        "gBTx0lDzjH/iOBnOSQaSEWQLx1syGKGBgKR+MHwxCzAJBgNVBAYTAmF3MQ4wDAYD\n" +
        "VQQIEwVhcnViYTEOMAwGA1UEChMFYXJ1YmExDjAMBgNVBAcTBWFydWJhMQ4wDAYD\n" +
        "VQQLEwVhcnViYTEOMAwGA1UEAxMFYXJ1YmExHTAbBgkqhkiG9w0BCQEWDmFydWJh\n" +
        "QGFydWJhLmFyggEAMAwGA1UdEwQFMAMBAf8wDQYJKoZIhvcNAQEEBQADgYEAYvBJ\n" +
        "0HOZbbHClXmGUjGs+GS+xC1FO/am2suCSYqNB9dyMXfOWiJ1+TLJk+o/YZt8vuxC\n" +
        "KdcZYgl4l/L6PxJ982SRhc83ZW2dkAZI4M0/Ud3oePe84k8jm3A7EvH5wi5hvCkK\n" +
        "RpuRBwn3Ei+jCRouxTbzKPsuCVB+1sNyxMTXzf0=\n" +
        "-----END CERTIFICATE-----\n";

    @Before
    public void setUpContext() throws Exception {
        SecurityContextHolder.clearContext();
        testAccounts = UaaTestAccounts.standard(null);
        jdbcTemplate = getWebApplicationContext().getBean(JdbcTemplate.class);
        providerProvisioning = getWebApplicationContext().getBean(IdentityProviderProvisioning.class);
        zoneAwareMetadataManager = getWebApplicationContext().getBean(ZoneAwareMetadataManager.class);
        zoneProvisioning = getWebApplicationContext().getBean(IdentityZoneProvisioning.class);
        configurator = getWebApplicationContext().getBean(SamlIdentityProviderConfigurator.class);
        //ensure that we don't fire the listener, we want to test the DB refresh
        getWebApplicationContext().getBean(ProviderChangedListener.class).setMetadataManager(null);
        cleanSamlProviders();

    }

    @After
    public void cleanSamlProviders() throws Exception {
        jdbcTemplate.update("UPDATE identity_provider SET active=? WHERE type=?", false, OriginKeys.SAML);
        for (SamlIdentityProviderDefinition definition : configurator.getIdentityProviderDefinitions()) {
            configurator.removeIdentityProviderDefinition(definition);
        }
        for (SamlIdentityProviderDefinition definition : configurator.getIdentityProviderDefinitions()) {
            configurator.removeIdentityProviderDefinition(definition);
        }
        assertEquals(0, configurator.getIdentityProviderDefinitions().size());
        for (IdentityZone zone : zoneProvisioning.retrieveAll()) {
            for (ExtendedMetadataDelegate metadata : zoneAwareMetadataManager.getManager(zone).getAvailableProviders()) {
                String hostedSPName = zoneAwareMetadataManager.getManager(zone).getHostedSPName();
                if (metadata.getExtendedMetadata(hostedSPName)==null ||
                    !metadata.getExtendedMetadata(hostedSPName).isLocal()) {
                    zoneAwareMetadataManager.getManager(zone).removeMetadataProvider(metadata);
                }
            }
            zoneAwareMetadataManager.getManager(zone).setRefreshRequired(true);
            getMockMvc().perform(post("/saml/metadata").with(new SetServerNameRequestPostProcessor(zone.getSubdomain() + ".localhost")));
            //all we have left is the local provider
            assertEquals(1, zoneAwareMetadataManager.getManager(zone).getAvailableProviders().size());
        }
        jdbcTemplate.update("delete from identity_provider where type=?", OriginKeys.SAML);
        SecurityContextHolder.clearContext();
        IdentityZoneHolder.clear();
    }

    @Test
    public void testFallbackIDP_shows_Error_Message_Instead_Of_Default() throws Exception {
        String nonExistentIDPDiscovery = "/saml/discovery?returnIDParam=idp&entityID=cloudfoundry-saml-login&idp=NON-EXISTENT-ALIAS&isPassive=true";
        getMockMvc().perform(get(nonExistentIDPDiscovery))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login?error=idp_not_found"));

        nonExistentIDPDiscovery = "/saml/discovery?returnIDParam=idp&entityID=cloudfoundry-saml-login&idp=NON-EXISTENT-ALIAS&isPassive=false";
        getMockMvc().perform(get(nonExistentIDPDiscovery))
            .andExpect(status().isFound())
            .andExpect(redirectedUrl("/login?error=idp_not_found"));
    }

    @Test
    public void testThatDBAddedXMLProviderShowsOnLoginPage() throws Exception {
        addXmlProviderToDatabase();
    }

    @Test
    public void testThatDBDeletedXMLProviderDoesNotShowOnLoginPage() throws Exception {
        IdentityProvider<SamlIdentityProviderDefinition> provider = addXmlProviderToDatabase();
        SamlIdentityProviderDefinition definition = provider.getConfig();
        //delete from DB
        EntityDeletedEvent event = new EntityDeletedEvent(provider, new MockAuthentication());
        getWebApplicationContext().publishEvent(event);
        //verify that provider is deleted
        assertThat(getWebApplicationContext().getBean(JdbcTemplate.class).queryForObject("select count(*) from identity_provider where id=?", new Object[] {provider.getId()}, Integer.class), is(0));
        //issue a timer
        zoneAwareMetadataManager.refreshAllProviders();
        //ensure that it the link doesn't show up
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").doesNotExist());
        //and provider should be gone
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
    }


    protected IdentityProvider<SamlIdentityProviderDefinition> addXmlProviderToDatabase() throws Exception {
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        IdentityProvider<SamlIdentityProviderDefinition> provider = createSamlProvider(DEFAULT_SIMPLE_SAML_METADATA, "simplesamlphp", "Log in with Simple Saml PHP Config");
        SamlIdentityProviderDefinition definition = provider.getConfig();
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

        return provider;
    }

    @Test
    public void test_Reject_Duplicate_Alias_and_Duplicate_Entity_ID() throws Exception {
        IdentityProvider<SamlIdentityProviderDefinition> provider = addXmlProviderToDatabase();

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

        SamlIdentityProviderDefinition definition = provider.getConfig();
        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").doesNotExist());
    }

    @Test
    public void testThatDBXMLDisabledProvider() throws Exception {
        IdentityProvider<SamlIdentityProviderDefinition> provider = addXmlProviderToDatabase();

        provider.setActive(false);
        provider = providerProvisioning.update(provider);
        SamlIdentityProviderDefinition definition = provider.getConfig();

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
        IdentityProvider<SamlIdentityProviderDefinition> provider = addXmlProviderToDatabase();
        SamlIdentityProviderDefinition definition = provider.getConfig();
        //ensure that it exists in the link
        getMockMvc().perform(get("/login").accept(TEXT_HTML))
            .andExpect(status().isOk())
            .andExpect(xpath("//a[text()='" + definition.getLinkText() + "']").exists());
    }


    @Test
    public void testThatDBAddedUrlProviderShowsOnLoginPage() throws Exception {
        assertEquals(1, zoneAwareMetadataManager.getAvailableProviders().size());
        IdentityProvider<SamlIdentityProviderDefinition> provider = createSamlProvider("http://simplesamlphp.cfapps.io/saml2/idp/metadata.php", "simplesamlphp", "Log in with Simple Saml PHP URL");
        SamlIdentityProviderDefinition definition = provider.getConfig();
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
        IdentityProvider<SamlIdentityProviderDefinition> provider = createSamlProvider("http://simplesamlphp.cfapps.io/saml2/idp/metadata.php", "simplesamlphpurl", "Log in with Simple Saml PHP URL");
        SamlIdentityProviderDefinition definition = provider.getConfig();
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
        definition = provider.getConfig();

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
        IdentityProvider<SamlIdentityProviderDefinition> provider = createSamlProvider(DEFAULT_SIMPLE_SAML_METADATA, "simplesamlphp", "Log in with Simple Saml PHP Config");
        SamlIdentityProviderDefinition definition = provider.getConfig();
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
        provider.setConfig(definition);
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
        definition.setMetaDataLocation(DEFAULT_SIMPLE_SAML_METADATA);
        provider.setConfig(definition);
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
        IdentityZoneConfiguration config1 = new IdentityZoneConfiguration(null);
        config1.getSamlConfig().setRequestSigned(true);
        config1.getSamlConfig().setWantAssertionSigned(true);
        zone1.setConfig(config1);
        zone1 = zoneProvisioning.create(zone1);
        assertTrue(zone1.getConfig().getSamlConfig().isRequestSigned());
        assertTrue(zone1.getConfig().getSamlConfig().isWantAssertionSigned());

        IdentityZone zone2 = new IdentityZone();
        zone2.setName(zone2Name);
        zone2.setSubdomain(zone2Name);
        zone2.setId(zone2Name);
        IdentityZoneConfiguration config2 = new IdentityZoneConfiguration(null);
        config2.getSamlConfig().setRequestSigned(false);
        config2.getSamlConfig().setWantAssertionSigned(false);
        zone2.setConfig(config2);
        zone2 = zoneProvisioning.create(zone2);
        assertFalse(zone2.getConfig().getSamlConfig().isRequestSigned());
        assertFalse(zone2.getConfig().getSamlConfig().isWantAssertionSigned());

        getMockMvc().perform(
            get("/saml/metadata")
                .with(new SetServerNameRequestPostProcessor(zone1.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("ID=\"zone1.cloudfoundry-saml-login\" entityID=\"zone1.cloudfoundry-saml-login\"")))
            .andExpect(content().string(containsString("<md:SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">")));

        getMockMvc().perform(
            get("/saml/metadata")
                .with(new SetServerNameRequestPostProcessor(zone2.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("ID=\"zone2.cloudfoundry-saml-login\" entityID=\"zone2.cloudfoundry-saml-login\"")))
            .andExpect(content().string(containsString("<md:SPSSODescriptor AuthnRequestsSigned=\"false\" WantAssertionsSigned=\"false\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">")));

        config2.getSamlConfig().setRequestSigned(true);
        config2.getSamlConfig().setWantAssertionSigned(true);
        zone2.setConfig(config2);
        zone2 = zoneProvisioning.update(zone2);
        assertTrue(zone2.getConfig().getSamlConfig().isRequestSigned());
        assertTrue(zone2.getConfig().getSamlConfig().isWantAssertionSigned());

        getMockMvc().perform(
            get("/saml/metadata")
                .with(new SetServerNameRequestPostProcessor(zone2.getSubdomain() + ".localhost")))
            .andExpect(status().isOk())
            .andExpect(content().string(containsString("ID=\"zone2.cloudfoundry-saml-login\" entityID=\"zone2.cloudfoundry-saml-login\"")))
            .andExpect(content().string(containsString("<md:SPSSODescriptor AuthnRequestsSigned=\"true\" WantAssertionsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\">")));

    }

    @Test
    public void test_zone_saml_properties() throws Exception {
        String zone1Name = new RandomValueStringGenerator().generate();
        String zone2Name = new RandomValueStringGenerator().generate();

        SamlConfig config1 = new SamlConfig();
        config1. setWantAssertionSigned(true);
        config1. setRequestSigned(true);
        config1.setPrivateKey(serviceProviderKey);
        config1.setPrivateKeyPassword(serviceProviderKeyPassword);
        config1.setCertificate(serviceProviderCertificate);

        IdentityZoneConfiguration zoneConfig1 = new IdentityZoneConfiguration(null);
        zoneConfig1.setSamlConfig(config1);

        IdentityZone zone1 = new IdentityZone();
        zone1.setName(zone1Name);
        zone1.setSubdomain(zone1Name);
        zone1.setId(zone1Name);
        zone1.setConfig(zoneConfig1);
        zone1 = zoneProvisioning.create(zone1);

        assertEquals(serviceProviderCertificate, zone1.getConfig().getSamlConfig().getCertificate());
        assertEquals(serviceProviderKey, zone1.getConfig().getSamlConfig().getPrivateKey());
        assertEquals(serviceProviderKeyPassword, zone1.getConfig().getSamlConfig().getPrivateKeyPassword());

        SamlConfig config2 = new SamlConfig();
        config2. setWantAssertionSigned(false);
        config2. setRequestSigned(false);
        IdentityZoneConfiguration zoneConfig2 = new IdentityZoneConfiguration(null);
        zoneConfig2.setSamlConfig(config2);

        IdentityZone zone2 = new IdentityZone();
        zone2.setName(zone2Name);
        zone2.setSubdomain(zone2Name);
        zone2.setId(zone2Name);
        zone2.setConfig(zoneConfig2);
        zone2 = zoneProvisioning.create(zone2);

        ZoneAwareMetadataGenerator generator = getWebApplicationContext().getBean(ZoneAwareMetadataGenerator.class);
        IdentityZoneHolder.set(zone1);
        assertTrue(generator.isRequestSigned());
        assertTrue(generator.isWantAssertionSigned());
        assertTrue(generator.generateMetadata().getSPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol").getWantAssertionsSigned());
        assertTrue(generator.generateMetadata().getSPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol").isAuthnRequestsSigned());

        IdentityZoneHolder.set(zone2);
        assertFalse(generator.isRequestSigned());
        assertFalse(generator.isWantAssertionSigned());
        assertFalse(generator.generateMetadata().getSPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol").getWantAssertionsSigned());
        assertFalse(generator.generateMetadata().getSPSSODescriptor("urn:oasis:names:tc:SAML:2.0:protocol").isAuthnRequestsSigned());

    }

    public IdentityProvider<SamlIdentityProviderDefinition> createSamlProvider(String metadata, String alias, String linkText) {
        SamlIdentityProviderDefinition definition = createSimplePHPSamlIDP(IdentityZone.getUaa().getId(), metadata, alias, linkText);
        IdentityProvider provider = new IdentityProvider();
        provider.setActive(true);
        provider.setConfig(definition);
        provider.setIdentityZoneId(IdentityZone.getUaa().getId());
        provider.setOriginKey(alias);
        provider.setName("DB Added SAML Provider");
        provider.setType(OriginKeys.SAML);
        provider = providerProvisioning.create(provider);
        return provider;
    }


    public SamlIdentityProviderDefinition createSimplePHPSamlIDP(String zoneId, String metaData, String alias, String linkText) {
        SamlIdentityProviderDefinition def = new SamlIdentityProviderDefinition();
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
