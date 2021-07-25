package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.extensions.SpringProfileCleanupExtension;
import org.cloudfoundry.identity.uaa.impl.config.IdentityZoneConfigurationBootstrap;
import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
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
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.AfterAllCallback;
import org.junit.jupiter.api.extension.BeforeAllCallback;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.ExtensionContext;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.xml.ResourceEntityResolver;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.lang.NonNull;
import org.springframework.mock.web.MockRequestDispatcher;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.AbstractRefreshableWebApplicationContext;
import org.springframework.web.servlet.ViewResolver;

import javax.servlet.RequestDispatcher;
import java.io.File;
import java.util.Arrays;
import java.util.EventListener;
import java.util.List;
import java.util.Scanner;
import java.util.Set;
import java.util.stream.Collectors;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SystemPropertiesCleanupExtension implements BeforeAllCallback, AfterAllCallback {

    private final Set<String> properties;

    SystemPropertiesCleanupExtension(String... props) {
        this.properties = Arrays.stream(props).collect(Collectors.toUnmodifiableSet());
    }

    @Override
    public void beforeAll(ExtensionContext context) {
        ExtensionContext.Store store = context.getStore(ExtensionContext.Namespace.create(context.getRequiredTestClass()));

        properties.forEach(s -> store.put(s, System.getProperty(s)));
    }

    @Override
    public void afterAll(ExtensionContext context) {
        ExtensionContext.Store store = context.getStore(ExtensionContext.Namespace.create(context.getRequiredTestClass()));

        properties.forEach(key -> {
                    String value = store.get(key, String.class);
                    if (value == null) {
                        System.clearProperty(key);
                    } else {
                        System.setProperty(key, value);
                    }
                }
        );
    }
}

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(SpringProfileCleanupExtension.class)
class BootstrapTests {

    private static final String LOGIN_IDP_METADATA = "login.idpMetadata";
    private static final String LOGIN_IDP_ENTITY_ALIAS = "login.idpEntityAlias";
    private static final String LOGIN_IDP_METADATA_URL = "login.idpMetadataURL";
    private static final String LOGIN_SAML_METADATA_TRUST_CHECK = "login.saml.metadataTrustCheck";
    @RegisterExtension
    static final SystemPropertiesCleanupExtension systemPropertiesCleanupExtension = new SystemPropertiesCleanupExtension(
            LOGIN_IDP_METADATA,
            LOGIN_IDP_ENTITY_ALIAS,
            LOGIN_IDP_METADATA_URL,
            LOGIN_SAML_METADATA_TRUST_CHECK);

    private ConfigurableApplicationContext context;

    @Test
    void xlegacyTestDeprecatedProperties() {
        context = getServletContext(null, "test/bootstrap/deprecated_properties_still_work.yml");
        ScimGroupProvisioning scimGroupProvisioning = context.getBean("scimGroupProvisioning", ScimGroupProvisioning.class);
        List<ScimGroup> scimGroups = scimGroupProvisioning.retrieveAll(IdentityZoneHolder.get().getId());
        assertThat(scimGroups, PredicateMatcher.has(g -> g.getDisplayName().equals("pony") && "The magic of friendship".equals(g.getDescription())));
        assertThat(scimGroups, PredicateMatcher.has(g -> g.getDisplayName().equals("cat") && "The cat".equals(g.getDescription())));
        IdentityZoneConfigurationBootstrap zoneBootstrap = context.getBean(IdentityZoneConfigurationBootstrap.class);
        assertEquals("https://deprecated.home_redirect.com", zoneBootstrap.getHomeRedirect());
        IdentityZone defaultZone = context.getBean(IdentityZoneProvisioning.class).retrieve("uaa");
        IdentityZoneConfiguration defaultConfig = defaultZone.getConfig();
        assertTrue(defaultConfig.getSamlConfig().getKeys().containsKey(SamlConfig.LEGACY_KEY_ID), "Legacy SAML keys should be available");
        assertEquals(SamlLoginServerKeyManagerTests.CERTIFICATE.trim(), defaultConfig.getSamlConfig().getCertificate().trim());
        assertEquals(SamlLoginServerKeyManagerTests.KEY.trim(), defaultConfig.getSamlConfig().getPrivateKey().trim());
        assertEquals(SamlLoginServerKeyManagerTests.PASSWORD.trim(), defaultConfig.getSamlConfig().getPrivateKeyPassword().trim());
    }

    @Test
    void legacySamlIdpAsTopLevelElement() {
        System.setProperty(LOGIN_SAML_METADATA_TRUST_CHECK, "false");
        System.setProperty(LOGIN_IDP_METADATA_URL, "http://simplesamlphp.uaa.com/saml2/idp/metadata.php");
        System.setProperty(LOGIN_IDP_ENTITY_ALIAS, "testIDPFile");

        context = getServletContext("default", "uaa.yml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(BootstrapSamlIdentityProviderData.class).isLegacyMetadataTrustCheck());
        List<SamlIdentityProviderDefinition> defs = context.getBean(BootstrapSamlIdentityProviderData.class).getIdentityProviderDefinitions();
        assertNotNull(findProvider(defs, "testIDPFile"));
        assertEquals(
                SamlIdentityProviderDefinition.MetadataLocation.URL,
                findProvider(defs, "testIDPFile").getType());
        assertEquals(
                SamlIdentityProviderDefinition.MetadataLocation.URL,
                defs.get(defs.size() - 1).getType()
        );
    }

    @Test
    void legacySamlMetadataAsXml() throws Exception {
        String metadataString = new Scanner(new File("./src/test/resources/sample-okta-localhost.xml")).useDelimiter("\\Z").next();
        System.setProperty(LOGIN_IDP_METADATA, metadataString);
        System.setProperty(LOGIN_IDP_ENTITY_ALIAS, "testIDPData");
        context = getServletContext("default,saml,configMetadata", "uaa.yml");
        List<SamlIdentityProviderDefinition> defs = context.getBean(BootstrapSamlIdentityProviderData.class).getIdentityProviderDefinitions();
        assertEquals(
                SamlIdentityProviderDefinition.MetadataLocation.DATA,
                findProvider(defs, "testIDPData").getType());
    }

    @Test
    void legacySamlMetadataAsUrl() {
        System.setProperty(LOGIN_SAML_METADATA_TRUST_CHECK, "false");
        System.setProperty(LOGIN_IDP_METADATA_URL, "http://simplesamlphp.uaa.com:80/saml2/idp/metadata.php");
        System.setProperty(LOGIN_IDP_ENTITY_ALIAS, "testIDPUrl");

        context = getServletContext("default", "uaa.yml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(BootstrapSamlIdentityProviderData.class).isLegacyMetadataTrustCheck());
        List<SamlIdentityProviderDefinition> defs = context.getBean(BootstrapSamlIdentityProviderData.class).getIdentityProviderDefinitions();
        assertNull(
                defs.get(defs.size() - 1).getSocketFactoryClassName()
        );
        assertEquals(
                SamlIdentityProviderDefinition.MetadataLocation.URL,
                defs.get(defs.size() - 1).getType()
        );
    }

    @Test
    void legacySamlUrlWithoutPort() {
        System.setProperty(LOGIN_SAML_METADATA_TRUST_CHECK, "false");
        System.setProperty(LOGIN_IDP_METADATA_URL, "http://simplesamlphp.uaa.com/saml2/idp/metadata.php");
        System.setProperty(LOGIN_IDP_ENTITY_ALIAS, "testIDPUrl");

        context = getServletContext("default", "uaa.yml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(BootstrapSamlIdentityProviderData.class).isLegacyMetadataTrustCheck());
        List<SamlIdentityProviderDefinition> defs = context.getBean(BootstrapSamlIdentityProviderData.class).getIdentityProviderDefinitions();
        assertFalse(
                context.getBean(BootstrapSamlIdentityProviderData.class).getIdentityProviderDefinitions().isEmpty()
        );
        assertNull(
                defs.get(defs.size() - 1).getSocketFactoryClassName()
        );
        assertEquals(
                SamlIdentityProviderDefinition.MetadataLocation.URL,
                defs.get(defs.size() - 1).getType()
        );
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

    private static ConfigurableApplicationContext getServletContext(
            final String profiles,
            final String uaaYamlPath) {
        System.setProperty("LOGIN_CONFIG_URL", "file:" + System.getProperty("user.dir") + "/../scripts/cargo/uaa.yml");
        System.setProperty("UAA_CONFIG_URL", "classpath:" + uaaYamlPath);

        abstractRefreshableWebApplicationContext.setServletContext(mockServletContext);
        MockServletConfig servletConfig = new MockServletConfig(mockServletContext);
        abstractRefreshableWebApplicationContext.setServletConfig(servletConfig);

        YamlServletProfileInitializer initializer = new YamlServletProfileInitializer();
        initializer.initialize(abstractRefreshableWebApplicationContext);
        System.clearProperty("LOGIN_CONFIG_URL");
        System.clearProperty("UAA_CONFIG_URL");

        if (profiles != null) {
            abstractRefreshableWebApplicationContext.getEnvironment().setActiveProfiles(StringUtils.commaDelimitedListToStringArray(profiles));
        }

        abstractRefreshableWebApplicationContext.refresh();

        return abstractRefreshableWebApplicationContext;
    }

    private final static MockServletContext mockServletContext = new MockServletContext() {
        @Override
        public RequestDispatcher getNamedDispatcher(String path) {
            return new MockRequestDispatcher("/");
        }

        @Override
        public String getVirtualServerName() {
            return "localhost";
        }

        @Override
        public <Type extends EventListener> void addListener(Type t) {
            //no op
        }
    };

    private static final AbstractRefreshableWebApplicationContext abstractRefreshableWebApplicationContext = new AbstractRefreshableWebApplicationContext() {

        @Override
        protected void loadBeanDefinitions(@NonNull DefaultListableBeanFactory beanFactory) throws BeansException {
            XmlBeanDefinitionReader beanDefinitionReader = new XmlBeanDefinitionReader(beanFactory);

            // Configure the bean definition reader with this context's
            // resource loading environment.
            beanDefinitionReader.setEnvironment(this.getEnvironment());
            beanDefinitionReader.setResourceLoader(this);
            beanDefinitionReader.setEntityResolver(new ResourceEntityResolver(this));

            beanDefinitionReader.loadBeanDefinitions("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        }
    };


}
