package org.cloudfoundry.identity.uaa.login;

import org.assertj.core.api.Condition;
import org.cloudfoundry.identity.uaa.extensions.PollutionPreventionExtension;
import org.cloudfoundry.identity.uaa.extensions.SpringProfileCleanupExtension;
import org.cloudfoundry.identity.uaa.extensions.SystemPropertiesCleanupExtension;
import org.cloudfoundry.identity.uaa.extensions.profiles.DisabledIfProfile;
import org.cloudfoundry.identity.uaa.impl.config.IdentityZoneConfigurationBootstrap;
import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderData;
import org.cloudfoundry.identity.uaa.provider.saml.SignatureAlgorithm;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneConfiguration;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneProvisioning;
import org.cloudfoundry.identity.uaa.zone.SamlConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.mock.web.MockRequestDispatcher;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.util.FileCopyUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.AbstractRefreshableWebApplicationContext;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.web.servlet.ViewResolver;

import jakarta.servlet.RequestDispatcher;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.io.UncheckedIOException;
import java.util.EventListener;
import java.util.List;
import java.util.stream.Stream;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.params.provider.Arguments.arguments;

@ExtendWith(PollutionPreventionExtension.class)
@ExtendWith(SpringProfileCleanupExtension.class)
@DisabledIfProfile({"mysql", "postgresql"})
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

    private static final MockServletContext mockServletContext = new MockServletContext() {
        @Override
        @NonNull
        public RequestDispatcher getNamedDispatcher(@Nullable String path) {
            return new MockRequestDispatcher("/");
        }

        @Override
        @NonNull
        public String getVirtualServerName() {
            return "localhost";
        }

        @Override
        public <T extends EventListener> void addListener(@Nullable T t) {
            //no op
        }
    };

    private static final AbstractRefreshableWebApplicationContext abstractRefreshableWebApplicationContext = new AnnotationConfigWebApplicationContext() {

        @Override
        protected void loadBeanDefinitions(@NonNull DefaultListableBeanFactory beanFactory) throws BeansException {
            this.scan("org.cloudfoundry.identity.uaa");
            super.loadBeanDefinitions(beanFactory);
        }
    };

    private ConfigurableApplicationContext context;

    static Stream<Arguments> samlSignatureParameterProvider() {
        final String yamlPath = "test/config/";
        return Stream.of(
                arguments(yamlPath + "saml-algorithm-sha1.yml", SignatureAlgorithm.SHA1),
                arguments(yamlPath + "saml-algorithm-sha256.yml", SignatureAlgorithm.SHA256),
                arguments(yamlPath + "saml-algorithm-sha512.yml", SignatureAlgorithm.SHA512)
        );
    }

    private static SamlIdentityProviderDefinition providerByAlias(
            final List<SamlIdentityProviderDefinition> defs,
            final String alias) {

        return defs.stream()
                .filter(def -> alias.equals(def.getIdpEntityAlias()))
                .findFirst()
                .orElse(null);
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

    @BeforeEach
    void beforeEach() {
        System.clearProperty(LOGIN_IDP_METADATA);
        System.clearProperty(LOGIN_IDP_ENTITY_ALIAS);
        System.clearProperty(LOGIN_IDP_METADATA_URL);
        System.clearProperty(LOGIN_SAML_METADATA_TRUST_CHECK);
    }

    @Test
    void legacyDeprecatedProperties() {
        context = getServletContext("default", "test/bootstrap/deprecated_properties_still_work.yml");
        ScimGroupProvisioning scimGroupProvisioning = context.getBean("scimGroupProvisioning", ScimGroupProvisioning.class);
        List<ScimGroup> scimGroups = scimGroupProvisioning.retrieveAll(IdentityZoneHolder.get().getId());
        assertThat(scimGroups)
                .haveAtLeastOne(new Condition<>(g -> "pony".equals(g.getDisplayName()) && "The magic of friendship".equals(g.getDescription()), "pony group"))
                .haveAtLeastOne(new Condition<>(g -> "cat".equals(g.getDisplayName()) && "The cat".equals(g.getDescription()), "cat group"));

        IdentityZoneConfigurationBootstrap zoneBootstrap = context.getBean(IdentityZoneConfigurationBootstrap.class);
        assertThat(zoneBootstrap.getHomeRedirect()).isEqualTo("https://deprecated.home_redirect.com");
        IdentityZone defaultZone = context.getBean(IdentityZoneProvisioning.class).retrieve("uaa");
        IdentityZoneConfiguration defaultConfig = defaultZone.getConfig();

        assertThat(defaultConfig.getSamlConfig().getKeys()).as("Legacy SAML keys should be available").containsKey(SamlConfig.LEGACY_KEY_ID);
        assertThat(defaultConfig.getSamlConfig().getCertificate().trim()).isEqualTo(SamlKeyManagerFactoryCertificateTests.CERTIFICATE.trim());
        assertThat(defaultConfig.getSamlConfig().getPrivateKey().trim()).isEqualTo(SamlKeyManagerFactoryCertificateTests.KEY.trim());
        assertThat(defaultConfig.getSamlConfig().getPrivateKeyPassword().trim()).isEqualTo(SamlKeyManagerFactoryCertificateTests.PASSWORD.trim());
    }

    @Test
    void legacySamlIdpAsTopLevelElement() {
        System.setProperty(LOGIN_SAML_METADATA_TRUST_CHECK, "false");
        System.setProperty(LOGIN_IDP_METADATA, loadResouceAsString("sample-okta-localhost.xml"));
        System.setProperty(LOGIN_IDP_ENTITY_ALIAS, "testIDPFile");

        context = getServletContext("hsqldb", "uaa.yml");
        assertThat(context.getBean("viewResolver", ViewResolver.class)).isNotNull();
        // assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class))
        assertThat(context.getBean(BootstrapSamlIdentityProviderData.class))
                .returns(false, BootstrapSamlIdentityProviderData::isLegacyMetadataTrustCheck);
        List<SamlIdentityProviderDefinition> defs = context.getBean(BootstrapSamlIdentityProviderData.class).getIdentityProviderDefinitions();
        assertThat(providerByAlias(defs, "testIDPFile"))
                .returns(SamlIdentityProviderDefinition.MetadataLocation.DATA, SamlIdentityProviderDefinition::getType);
    }

    @Test
    void legacySamlMetadataAsXml() {
        String metadataString = loadResouceAsString("sample-okta-localhost.xml");
        System.setProperty(LOGIN_IDP_METADATA, metadataString);
        System.setProperty(LOGIN_IDP_ENTITY_ALIAS, "testIDPData");
        context = getServletContext("hsqldb,saml,configMetadata", "uaa.yml");
        List<SamlIdentityProviderDefinition> defs = context.getBean(BootstrapSamlIdentityProviderData.class).getIdentityProviderDefinitions();
        assertThat(providerByAlias(defs, "testIDPData"))
                .isNotNull()
                .returns(SamlIdentityProviderDefinition.MetadataLocation.DATA, SamlIdentityProviderDefinition::getType);
    }

    @Test
    void legacySamlMetadataAsUrl() {
        System.setProperty(LOGIN_SAML_METADATA_TRUST_CHECK, "false");
        System.setProperty(LOGIN_IDP_METADATA_URL, "http://simplesamlphp.uaa-acceptance.cf-app.com/saml2/idp/metadata.php");
        System.setProperty(LOGIN_IDP_ENTITY_ALIAS, "testIDPUrl");

        context = getServletContext("hsqldb", "uaa.yml");
        assertThat(context.getBean("viewResolver", ViewResolver.class)).isNotNull();
        // assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class))
        assertThat(context.getBean(BootstrapSamlIdentityProviderData.class))
                .returns(false, BootstrapSamlIdentityProviderData::isLegacyMetadataTrustCheck);
        List<SamlIdentityProviderDefinition> defs = context.getBean(BootstrapSamlIdentityProviderData.class).getIdentityProviderDefinitions();
        assertThat(providerByAlias(defs, "testIDPUrl"))
                .isNotNull()
                .returns(null, SamlIdentityProviderDefinition::getSocketFactoryClassName)
                .returns(SamlIdentityProviderDefinition.MetadataLocation.URL, SamlIdentityProviderDefinition::getType);
    }

    @ParameterizedTest
    @MethodSource("samlSignatureParameterProvider")
    void samlSignatureAlgorithmsWereBootstrapped(String yamlFile, SignatureAlgorithm algorithm) {
        // When we override the SHA1 default for login.saml.signatureAlgorithm in the yaml, make sure it works.
        context = getServletContext("hsqldb", yamlFile);

        SignatureAlgorithm signatureAlgorithm = context.getBean(SignatureAlgorithm.class);
        assertThat(signatureAlgorithm)
                .as("The SAML signature algorithm in the yaml file is set in the bean")
                .isEqualTo(algorithm);
    }

    @Test
    void samlSignatureAlgorithmIsInvalid() {
        context = getServletContext("hsqldb", "test/config/saml-algorithm-invalid.yml");
        // When we override the SHA1 default for login.saml.signatureAlgorithm in the yaml, make sure it works.
        SignatureAlgorithm signatureAlgorithm = context.getBean(SignatureAlgorithm.class);
        assertThat(signatureAlgorithm).isSameAs(SignatureAlgorithm.INVALID);
    }

    private static String loadResouceAsString(String resourceLocation) {
        ResourceLoader resourceLoader = new DefaultResourceLoader();
        Resource resource = resourceLoader.getResource(resourceLocation);

        try (Reader reader = new InputStreamReader(resource.getInputStream(), UTF_8)) {
            return FileCopyUtils.copyToString(reader);
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }
}
