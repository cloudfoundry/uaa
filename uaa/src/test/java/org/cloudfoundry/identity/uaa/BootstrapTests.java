package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.impl.config.IdentityZoneConfigurationBootstrap;
import org.cloudfoundry.identity.uaa.login.SamlLoginServerKeyManagerTests;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderData;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.FilterType;
import org.springframework.context.annotation.PropertySource;
import org.springframework.context.support.PropertySourcesPlaceholderConfigurer;
import org.springframework.core.env.Environment;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit.jupiter.SpringExtension;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.servlet.ViewResolver;

import java.util.List;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class BootstrapTests {

    @PropertySource(value = {
            "classpath:test/bootstrap/deprecated_properties_still_work.yml",
    }, factory = NestedMapPropertySourceFactory.class)
    @ComponentScan(excludeFilters = {
            @ComponentScan.Filter(type = FilterType.ASSIGNABLE_TYPE, classes = WebConfiguration.class)
    })
    static class XLegacyTestDeprecatedPropertiesConfig {

        @Bean
        public static PropertySourcesPlaceholderConfigurer properties() {
            return new PropertySourcesPlaceholderConfigurer();
        }

    }

    @ExtendWith(SpringExtension.class)
    @ExtendWith(PollutionPreventionExtension.class)
    @ActiveProfiles("default")
    @WebAppConfiguration
    @ContextConfiguration(classes = {
            XLegacyTestDeprecatedPropertiesConfig.class,
            TestClientAndMockMvcTestConfig.class
    })
    @Nested
    class XlegacyTestDeprecatedProperties {

        @Test
        void xlegacyTestDeprecatedProperties(
                @Autowired Environment environment,
                @Autowired ScimGroupProvisioning scimGroupProvisioning,
                @Autowired IdentityZoneConfigurationBootstrap zoneBootstrap,
                @Autowired IdentityZoneProvisioning identityZoneProvisioning
        ) {
            List<ScimGroup> scimGroups = scimGroupProvisioning.retrieveAll(IdentityZoneHolder.get().getId());
            assertThat(scimGroups, PredicateMatcher.has(g -> g.getDisplayName().equals("pony") && "The magic of friendship".equals(g.getDescription())));
            assertThat(scimGroups, PredicateMatcher.has(g -> g.getDisplayName().equals("cat") && "The cat".equals(g.getDescription())));
            assertEquals("https://deprecated.home_redirect.com", zoneBootstrap.getHomeRedirect());
            IdentityZone defaultZone = identityZoneProvisioning.retrieve("uaa");
            IdentityZoneConfiguration defaultConfig = defaultZone.getConfig();
            assertTrue(defaultConfig.getSamlConfig().getKeys().containsKey(SamlConfig.LEGACY_KEY_ID), "Legacy SAML keys should be available");
            assertEquals(SamlLoginServerKeyManagerTests.CERTIFICATE.trim(), defaultConfig.getSamlConfig().getCertificate().trim());
            assertEquals(SamlLoginServerKeyManagerTests.KEY.trim(), defaultConfig.getSamlConfig().getPrivateKey().trim());
            assertEquals(SamlLoginServerKeyManagerTests.PASSWORD.trim(), defaultConfig.getSamlConfig().getPrivateKeyPassword().trim());
        }
    }

    @DefaultTestContext
    @TestPropertySource(properties = {
            "login.saml.metadataTrustCheck=false",
            "login.idpMetadataURL=http://simplesamlphp.uaa.com/saml2/idp/metadata.php",
            "login.idpEntityAlias=testIDPFile",
    })
    @Nested
    class LegacySamlIdpAsTopLevelElement {

        @Test
        void legacySamlIdpAsTopLevelElement(
                @Autowired ViewResolver viewResolver,
                @Autowired SAMLDefaultLogger samlDefaultLogger,
                @Autowired BootstrapSamlIdentityProviderData bootstrapSamlIdentityProviderData
        ) {
            assertNotNull(viewResolver);
            assertNotNull(samlDefaultLogger);
            assertFalse(bootstrapSamlIdentityProviderData.isLegacyMetadataTrustCheck());
            List<SamlIdentityProviderDefinition> defs = bootstrapSamlIdentityProviderData.getIdentityProviderDefinitions();
            assertNotNull(findProvider(defs, "testIDPFile"));
            assertEquals(
                    SamlIdentityProviderDefinition.MetadataLocation.URL,
                    findProvider(defs, "testIDPFile").getType());
            assertEquals(
                    SamlIdentityProviderDefinition.MetadataLocation.URL,
                    defs.get(defs.size() - 1).getType()
            );
        }
    }

    private static final String metadata = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
            "<md:EntityDescriptor xmlns:md=\"urn:oasis:names:tc:SAML:2.0:metadata\" entityID=\"https://www.okta.com/k2lvtem0VAJDMINKEYJW\"><md:IDPSSODescriptor WantAuthnRequestsSigned=\"true\" protocolSupportEnumeration=\"urn:oasis:names:tc:SAML:2.0:protocol\"><md:KeyDescriptor use=\"signing\"><ds:KeyInfo xmlns:ds=\"https://www.w3.org/2000/09/xmldsig#\"><ds:X509Data><ds:X509Certificate>MIICmTCCAgKgAwIBAgIGAUPATqmEMA0GCSqGSIb3DQEBBQUAMIGPMQswCQYDVQQGEwJVUzETMBEG" +
            "  A1UECAwKQ2FsaWZvcm5pYTEWMBQGA1UEBwwNU2FuIEZyYW5jaXNjbzENMAsGA1UECgwET2t0YTEU" +
            "  MBIGA1UECwwLU1NPUHJvdmlkZXIxEDAOBgNVBAMMB1Bpdm90YWwxHDAaBgkqhkiG9w0BCQEWDWlu" +
            "  Zm9Ab2t0YS5jb20wHhcNMTQwMTIzMTgxMjM3WhcNNDQwMTIzMTgxMzM3WjCBjzELMAkGA1UEBhMC" +
            "  VVMxEzARBgNVBAgMCkNhbGlmb3JuaWExFjAUBgNVBAcMDVNhbiBGcmFuY2lzY28xDTALBgNVBAoM" +
            "  BE9rdGExFDASBgNVBAsMC1NTT1Byb3ZpZGVyMRAwDgYDVQQDDAdQaXZvdGFsMRwwGgYJKoZIhvcN" +
            "  AQkBFg1pbmZvQG9rdGEuY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCeil67/TLOiTZU" +
            "  WWgW2XEGgFZ94bVO90v5J1XmcHMwL8v5Z/8qjdZLpGdwI7Ph0CyXMMNklpaR/Ljb8fsls3amdT5O" +
            "  Bw92Zo8ulcpjw2wuezTwL0eC0wY/GQDAZiXL59npE6U+fH1lbJIq92hx0HJSru/0O1q3+A/+jjZL" +
            "  3tL/SwIDAQABMA0GCSqGSIb3DQEBBQUAA4GBAI5BoWZoH6Mz9vhypZPOJCEKa/K+biZQsA4Zqsuk" +
            "  vvphhSERhqk/Nv76Vkl8uvJwwHbQrR9KJx4L3PRkGCG24rix71jEuXVGZUsDNM3CUKnARx4MEab6" +
            "  GFHNkZ6DmoT/PFagngecHu+EwmuDtaG0rEkFrARwe+d8Ru0BN558abFb</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress</md:NameIDFormat><md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST\" Location=\"https://pivotal.oktapreview.com/app/pivotal_pivotalcfdevelopment_1/k2lvtem0VAJDMINKEYJW/sso/saml\"/><md:SingleSignOnService Binding=\"urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect\" Location=\"https://pivotal.oktapreview.com/app/pivotal_pivotalcfdevelopment_1/k2lvtem0VAJDMINKEYJW/sso/saml\"/></md:IDPSSODescriptor></md:EntityDescriptor>";

    @DefaultTestContext
    @ActiveProfiles(profiles = {
            "default",
            "saml",
            "configMetadata"
    })
    @TestPropertySource(properties = {
            "login.idpEntityAlias=testIDPData",
            "login.idpMetadata=" + metadata,
    })
    @Nested
    class LegacySamlMetadataAsXml {

        @Test
        void legacySamlMetadataAsXml(
                @Autowired BootstrapSamlIdentityProviderData bootstrapSamlIdentityProviderData
        ) {
            List<SamlIdentityProviderDefinition> defs = bootstrapSamlIdentityProviderData.getIdentityProviderDefinitions();
            assertEquals(
                    SamlIdentityProviderDefinition.MetadataLocation.DATA,
                    findProvider(defs, "testIDPData").getType());
        }
    }

    @DefaultTestContext
    @TestPropertySource(properties = {
            "login.saml.metadataTrustCheck=false",
            "login.idpMetadataURL=http://simplesamlphp.uaa.com:80/saml2/idp/metadata.php",
            "login.idpEntityAlias=testIDPUrl",
    })
    @Nested
    class LegacySamlMetadataAsUrl {

        @Test
        void legacySamlMetadataAsUrl(
                @Autowired ViewResolver viewResolver,
                @Autowired SAMLDefaultLogger samlDefaultLogger,
                @Autowired BootstrapSamlIdentityProviderData bootstrapSamlIdentityProviderData
        ) {
            assertNotNull(viewResolver);
            assertNotNull(samlDefaultLogger);
            assertFalse(bootstrapSamlIdentityProviderData.isLegacyMetadataTrustCheck());
            List<SamlIdentityProviderDefinition> defs = bootstrapSamlIdentityProviderData.getIdentityProviderDefinitions();
            assertNull(
                    defs.get(defs.size() - 1).getSocketFactoryClassName()
            );
            assertEquals(
                    SamlIdentityProviderDefinition.MetadataLocation.URL,
                    defs.get(defs.size() - 1).getType()
            );
        }
    }

    @DefaultTestContext
    @TestPropertySource(properties = {
            "login.saml.metadataTrustCheck=false",
            "login.idpMetadataURL=http://simplesamlphp.uaa.com/saml2/idp/metadata.php",
            "login.idpEntityAlias=testIDPUrl",
    })
    @Nested
    class LegacySamlUrlWithoutPort {

        @Test
        void legacySamlUrlWithoutPort(
                @Autowired ViewResolver viewResolver,
                @Autowired SAMLDefaultLogger samlDefaultLogger,
                @Autowired BootstrapSamlIdentityProviderData bootstrapSamlIdentityProviderData
        ) {
            assertNotNull(viewResolver);
            assertNotNull(samlDefaultLogger);
            assertFalse(bootstrapSamlIdentityProviderData.isLegacyMetadataTrustCheck());
            List<SamlIdentityProviderDefinition> defs = bootstrapSamlIdentityProviderData.getIdentityProviderDefinitions();
            assertFalse(defs.isEmpty());
            assertNull(
                    defs.get(defs.size() - 1).getSocketFactoryClassName()
            );
            assertEquals(
                    SamlIdentityProviderDefinition.MetadataLocation.URL,
                    defs.get(defs.size() - 1).getType()
            );
        }
    }

    private static SamlIdentityProviderDefinition findProvider(
            final List<SamlIdentityProviderDefinition> defs,
            final String alias) {
        for (SamlIdentityProviderDefinition def : defs) {
            if (alias.equals(def.getIdpEntityAlias())) {
                return def;
            }
        }
        return null;
    }

}
