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
package org.cloudfoundry.identity.uaa.login;

import org.cloudfoundry.identity.uaa.impl.config.IdentityZoneConfigurationBootstrap;
import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.provider.SamlIdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.provider.saml.BootstrapSamlIdentityProviderData;
import org.cloudfoundry.identity.uaa.scim.ScimGroup;
import org.cloudfoundry.identity.uaa.scim.ScimGroupProvisioning;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.util.PredicateMatcher;
import org.cloudfoundry.identity.uaa.zone.*;
import org.flywaydb.core.Flyway;
import org.junit.*;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.xml.ResourceEntityResolver;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockRequestDispatcher;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.AbstractRefreshableWebApplicationContext;
import org.springframework.web.servlet.ViewResolver;

import javax.servlet.RequestDispatcher;
import java.io.File;
import java.util.*;

import static org.junit.Assert.*;

public class BootstrapTests {

    private ConfigurableApplicationContext context;

    private static String systemConfiguredProfiles;

    @BeforeClass
    public static void saveProfiles() {
        systemConfiguredProfiles = System.getProperty("spring.profiles.active");
    }

    @AfterClass
    public static void restoreProfiles() {
        if (systemConfiguredProfiles != null) {
            System.setProperty("spring.profiles.active", systemConfiguredProfiles);
        } else {
            System.clearProperty("spring.profiles.active");
        }
    }

    @Before
    public synchronized void setup() {
        System.clearProperty("spring.profiles.active");
        IdentityZoneHolder.clear();
    }

    @Test
    public void xlegacy_test_deprecated_properties() {
        context = getServletContext(null, "login.yml", "test/bootstrap/deprecated_properties_still_work.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        ScimGroupProvisioning scimGroupProvisioning = context.getBean("scimGroupProvisioning", ScimGroupProvisioning.class);
        List<ScimGroup> scimGroups = scimGroupProvisioning.retrieveAll(IdentityZoneHolder.get().getId());
        assertThat(scimGroups, PredicateMatcher.<ScimGroup>has(g -> g.getDisplayName().equals("pony") && "The magic of friendship".equals(g.getDescription())));
        assertThat(scimGroups, PredicateMatcher.<ScimGroup>has(g -> g.getDisplayName().equals("cat") && "The cat".equals(g.getDescription())));
        IdentityZoneConfigurationBootstrap zoneBootstrap = context.getBean(IdentityZoneConfigurationBootstrap.class);
        assertEquals("https://deprecated.home_redirect.com", zoneBootstrap.getHomeRedirect());
        IdentityZone defaultZone = context.getBean(IdentityZoneProvisioning.class).retrieve("uaa");
        IdentityZoneConfiguration defaultConfig = defaultZone.getConfig();
        assertTrue("Legacy SAML keys should be available", defaultConfig.getSamlConfig().getKeys().containsKey(SamlConfig.LEGACY_KEY_ID));
        assertEquals(SamlLoginServerKeyManagerTests.CERTIFICATE.trim(), defaultConfig.getSamlConfig().getCertificate().trim());
        assertEquals(SamlLoginServerKeyManagerTests.KEY.trim(), defaultConfig.getSamlConfig().getPrivateKey().trim());
        assertEquals(SamlLoginServerKeyManagerTests.PASSWORD.trim(), defaultConfig.getSamlConfig().getPrivateKeyPassword().trim());

    }

    @Test
    public void legacy_saml_idp_as_top_level_element() {
        System.setProperty("login.saml.metadataTrustCheck", "false");
        System.setProperty("login.idpMetadataURL", "http://simplesamlphp.uaa.com/saml2/idp/metadata.php");
        System.setProperty("login.idpEntityAlias", "testIDPFile");

        context = getServletContext("default", "login.yml", "uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
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
    public void legacy_saml_metadata_as_xml() throws Exception {
        String metadataString = new Scanner(new File("./src/main/resources/sample-okta-localhost.xml")).useDelimiter("\\Z").next();
        System.setProperty("login.idpMetadata", metadataString);
        System.setProperty("login.idpEntityAlias", "testIDPData");
        context = getServletContext("default,saml,configMetadata", "login.yml", "uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        List<SamlIdentityProviderDefinition> defs = context.getBean(BootstrapSamlIdentityProviderData.class).getIdentityProviderDefinitions();
        assertEquals(
                SamlIdentityProviderDefinition.MetadataLocation.DATA,
                findProvider(defs, "testIDPData").getType());
    }


    @Test
    public void legacy_saml_metadata_as_url() {
        System.setProperty("login.saml.metadataTrustCheck", "false");
        System.setProperty("login.idpMetadataURL", "http://simplesamlphp.uaa.com:80/saml2/idp/metadata.php");
        System.setProperty("login.idpEntityAlias", "testIDPUrl");

        context = getServletContext("default", "login.yml", "uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
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
    public void legacy_saml_url_without_port() {
        System.setProperty("login.saml.metadataTrustCheck", "false");
        System.setProperty("login.idpMetadataURL", "http://simplesamlphp.uaa.com/saml2/idp/metadata.php");
        System.setProperty("login.idpEntityAlias", "testIDPUrl");

        context = getServletContext("default", "login.yml", "uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
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

    protected SamlIdentityProviderDefinition findProvider(List<SamlIdentityProviderDefinition> defs, String alias) {
        for (SamlIdentityProviderDefinition def : defs) {
            if (alias.equals(def.getIdpEntityAlias())) {
                return def;
            }
        }
        return null;
    }

    private ConfigurableApplicationContext getServletContext(String profiles, String loginYmlPath, String uaaYamlPath, String... resources) {
        return getServletContext(profiles, false, new String[]{"required_configuration.yml", loginYmlPath, uaaYamlPath}, false, resources);
    }

    private static ConfigurableApplicationContext getServletContext(String profiles, boolean mergeProfiles, String[] yamlFiles, boolean cleandb, String... resources) {
        String[] resourcesToLoad = resources;
        if (!resources[0].endsWith(".xml")) {
            resourcesToLoad = new String[resources.length - 1];
            System.arraycopy(resources, 1, resourcesToLoad, 0, resourcesToLoad.length);
        }

        final String[] configLocations = resourcesToLoad;

        AbstractRefreshableWebApplicationContext context = new AbstractRefreshableWebApplicationContext() {

            @Override
            protected void loadBeanDefinitions(DefaultListableBeanFactory beanFactory) throws BeansException {
                XmlBeanDefinitionReader beanDefinitionReader = new XmlBeanDefinitionReader(beanFactory);

                // Configure the bean definition reader with this context's
                // resource loading environment.
                beanDefinitionReader.setEnvironment(this.getEnvironment());
                beanDefinitionReader.setResourceLoader(this);
                beanDefinitionReader.setEntityResolver(new ResourceEntityResolver(this));

                if (configLocations != null) {
                    for (String configLocation : configLocations) {
                        beanDefinitionReader.loadBeanDefinitions(configLocation);
                    }
                }
            }

        };

        if (profiles != null) {
            if (mergeProfiles) {
                String[] activeProfiles = context.getEnvironment().getActiveProfiles();
                HashSet<String> envProfiles = new HashSet<>(Arrays.asList(activeProfiles));
                envProfiles.addAll(Arrays.asList(StringUtils.commaDelimitedListToStringArray(profiles)));
                envProfiles.add("strict");
                context.getEnvironment().setActiveProfiles(envProfiles.toArray(new String[0]));
            } else {
                context.getEnvironment().setActiveProfiles(StringUtils.commaDelimitedListToStringArray(profiles));
            }
        }

        MockServletContext servletContext = new MockServletContext() {
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
        context.setServletContext(servletContext);
        MockServletConfig servletConfig = new MockServletConfig(servletContext);
        servletConfig.addInitParameter("environmentConfigLocations", StringUtils.arrayToCommaDelimitedString(yamlFiles));
        context.setServletConfig(servletConfig);

        YamlServletProfileInitializer initializer = new YamlServletProfileInitializer();
        initializer.initialize(context);

        if (profiles != null) {
            context.getEnvironment().setActiveProfiles(StringUtils.commaDelimitedListToStringArray(profiles));
        }

        context.refresh();
        if (cleandb) {
            context.getBean(Flyway.class).clean();
            context.getBean(Flyway.class).migrate();
        }

        return context;
    }
}
