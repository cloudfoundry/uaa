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
package org.cloudfoundry.identity.uaa.login;

import org.apache.commons.httpclient.contrib.ssl.EasySSLProtocolSocketFactory;
import org.apache.commons.httpclient.protocol.DefaultProtocolSocketFactory;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.config.YamlPropertiesFactoryBean;
import org.cloudfoundry.identity.uaa.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.xml.ResourceEntityResolver;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.mock.web.MockRequestDispatcher;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.websso.WebSSOProfileConsumer;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.AbstractRefreshableWebApplicationContext;
import org.springframework.web.servlet.ViewResolver;

import javax.servlet.RequestDispatcher;
import java.io.File;
import java.io.IOException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class BootstrapTests {

    private ConfigurableApplicationContext context;

    @Before
    public void setup() throws Exception {
        System.clearProperty("spring.profiles.active");
        IdentityZoneHolder.clear();
    }

    @After
    public void cleanup() throws Exception {
        System.clearProperty("spring.profiles.active");
        if (context != null) {
            context.close();
        }
        Set<String> removeme = new HashSet<>();
        for ( Map.Entry<Object,Object> entry : System.getProperties().entrySet()) {
            if (entry.getKey().toString().startsWith("login.")) {
                removeme.add(entry.getKey().toString());
            }
        }
        for (String s : removeme) {
            System.clearProperty(s);
        }
        IdentityZoneHolder.clear();
    }

    @Test
    public void testRootContextDefaults() throws Exception {
        context = getServletContext(null, "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("resetPasswordController", ResetPasswordController.class));
        assertEquals(Integer.MAX_VALUE, context.getBean("webSSOprofileConsumer", WebSSOProfileConsumerImpl.class).getMaxAuthenticationAge());
    }

    @Test
    public void testBootstrappedIdps() throws Exception {
        IdentityZoneHolder.set(IdentityZone.getUaa());
        //generate login.yml with SAML and uaa.yml with LDAP

        context = getServletContext("ldap,default", true, "test/bootstrap/login.yml,login.yml","test/bootstrap/uaa.yml,uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("resetPasswordController", ResetPasswordController.class));
        IdentityProviderConfigurator samlProviders = context.getBean("metaDataProviders", IdentityProviderConfigurator.class);
        IdentityProviderProvisioning providerProvisioning = context.getBean("identityProviderProvisioning", IdentityProviderProvisioning.class);
        //ensure that ldap has been loaded up
        assertNotNull(context.getBean("ldapPooled"));
        assertFalse(context.getBean("ldapPooled", Boolean.class).booleanValue());

        //ensure we have some saml providers in login.yml
        //we have provided 4 here, but the original login.yml may add, but not remove some
        assertTrue(samlProviders.getIdentityProviderDefinitions().size() >= 4);

        //verify that they got loaded in the DB
        for (IdentityProviderDefinition def : samlProviders.getIdentityProviderDefinitions()) {
            assertNotNull(providerProvisioning.retrieveByOrigin(def.getIdpEntityAlias()));
        }

        assertNotNull(providerProvisioning.retrieveByOrigin(Origin.LDAP));
    }

    @Test
    public void testSamlProfileNoData() throws Exception {
        System.setProperty("login.saml.maxAuthenticationAge", "3600");
        System.setProperty("login.saml.metadataTrustCheck", "false");
        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertEquals(3600, context.getBean("webSSOprofileConsumer", WebSSOProfileConsumerImpl.class).getMaxAuthenticationAge());
        Assume.assumeTrue(context.getEnvironment().getProperty("login.idpMetadataURL")==null);
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(IdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        assertEquals(0, context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions().size());
    }

    @Test
    public void testLegacySamlHttpMetaUrl() throws Exception {
        System.setProperty("login.saml.metadataTrustCheck", "false");
        System.setProperty("login.idpMetadataURL", "http://localhost:9696/nodata");
        System.setProperty("login.idpEntityAlias", "testIDPFile");

        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(IdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        List<IdentityProviderDefinition> defs = context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions();
        assertEquals(
                DefaultProtocolSocketFactory.class.getName(),
                defs.get(defs.size() - 1).getSocketFactoryClassName()
        );
        assertEquals(
            IdentityProviderDefinition.MetadataLocation.URL,
            defs.get(defs.size() - 1).getType()
        );
    }

    @Test
    public void testLegacySamlProfileMetadataFile() throws Exception {
        System.setProperty("login.idpMetadataFile", "./src/test/resources/test.saml.metadata");
        System.setProperty("login.idpEntityAlias", "testIDPFile");
        System.setProperty("login.saml.metadataTrustCheck", "false");
        context = getServletContext("default,saml,fileMetadata", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(IdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        List<IdentityProviderDefinition> defs = context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions();
        assertEquals(
            IdentityProviderDefinition.MetadataLocation.FILE,
            defs.get(defs.size() - 1).getType());
    }

    @Test
    public void testLegacySamlProfileMetadataConfig() throws Exception {
        String metadataString = new Scanner(new File("./src/main/resources/sample-okta-localhost.xml")).useDelimiter("\\Z").next();
        System.setProperty("login.idpMetadata", metadataString);
        System.setProperty("login.idpEntityAlias", "testIDPData");
        context = getServletContext("default,saml,configMetadata", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        List<IdentityProviderDefinition> defs = context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions();
        assertEquals(
            IdentityProviderDefinition.MetadataLocation.DATA,
            defs.get(defs.size() - 1).getType());
    }


    @Test
    public void testLegacySamlProfileHttpsMetaUrl() throws Exception {
        System.setProperty("login.saml.metadataTrustCheck", "false");
        System.setProperty("login.idpMetadataURL", "https://localhost:9696/nodata");
        System.setProperty("login.idpEntityAlias", "testIDPUrl");

        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(IdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        List<IdentityProviderDefinition> defs = context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions();
        assertEquals(
            EasySSLProtocolSocketFactory.class.getName(),
            defs.get(defs.size() - 1).getSocketFactoryClassName()
        );
        assertEquals(
            IdentityProviderDefinition.MetadataLocation.URL,
            defs.get(defs.size() - 1).getType()
        );

    }

    @Test
    public void testLegacySamlProfileHttpsMetaUrlWithoutPort() throws Exception {
        System.setProperty("login.saml.metadataTrustCheck", "false");
        System.setProperty("login.idpMetadataURL", "https://localhost/nodata");
        System.setProperty("login.idpEntityAlias", "testIDPUrl");

        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(IdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        List<IdentityProviderDefinition> defs = context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions();
        assertFalse(
                context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions().isEmpty()
        );
        assertEquals(
            EasySSLProtocolSocketFactory.class.getName(),
            defs.get(defs.size() - 1).getSocketFactoryClassName()
        );
        assertEquals(
            IdentityProviderDefinition.MetadataLocation.URL,
            defs.get(defs.size() - 1).getType()
        );

    }

    @Test
    public void testSamlProfileWithEntityIDAsURL() throws Exception {
        System.setProperty("login.entityID", "http://some.other.hostname:8080/saml");
        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("extendedMetaData", org.springframework.security.saml.metadata.ExtendedMetadata.class));
        assertEquals("http://some.other.hostname:8080/saml", context.getBean("samlSPAlias", String.class));
        assertEquals("some.other.hostname", context.getBean("extendedMetaData", org.springframework.security.saml.metadata.ExtendedMetadata.class).getAlias());

    }

    @Test
    public void testSamlProfileWithEntityIDAsURLButAliasSet() throws Exception {
        System.setProperty("login.entityID", "http://some.other.hostname:8080/saml");
        System.setProperty("login.saml.entityIDAlias", "spalias");
        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("extendedMetaData", org.springframework.security.saml.metadata.ExtendedMetadata.class));
        assertEquals("spalias", context.getBean("samlSPAlias", String.class));
        assertEquals("spalias", context.getBean("extendedMetaData", org.springframework.security.saml.metadata.ExtendedMetadata.class).getAlias());
    }

    @Test
    public void testMessageService() throws Exception {
        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        Object messageService = context.getBean("messageService");
        assertNotNull(messageService);
        assertEquals(EmailService.class, messageService.getClass());

        System.setProperty("notifications.url", "");
        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        messageService = context.getBean("messageService");
        assertNotNull(messageService);
        assertEquals(EmailService.class, messageService.getClass());

        System.setProperty("notifications.url", "example.com");
        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        messageService = context.getBean("messageService");
        assertNotNull(messageService);
        assertEquals(NotificationsService.class, messageService.getClass());
    }

    private ConfigurableApplicationContext getServletContext(String profiles, String loginYmlPath, String uaaYamlPath, String... resources) {
        return getServletContext(profiles, false, loginYmlPath, uaaYamlPath, resources);
    }
    private ConfigurableApplicationContext getServletContext(String profiles, boolean mergeProfiles, String loginYmlPath, String uaaYamlPath, String... resources) {
        String[] resourcesToLoad = resources;
        if (!resources[0].endsWith(".xml")) {
            resourcesToLoad = new String[resources.length - 1];
            System.arraycopy(resources, 1, resourcesToLoad, 0, resourcesToLoad.length);
        }

        final String[] configLocations = resourcesToLoad;

        AbstractRefreshableWebApplicationContext context = new AbstractRefreshableWebApplicationContext() {

            @Override
            protected void loadBeanDefinitions(DefaultListableBeanFactory beanFactory) throws BeansException,
                    IOException {
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
        };
        context.setServletContext(servletContext);
        MockServletConfig servletConfig = new MockServletConfig(servletContext);
        servletConfig.addInitParameter("environmentConfigLocations", loginYmlPath+","+uaaYamlPath);
        context.setServletConfig(servletConfig);

        YamlServletProfileInitializer initializer = new YamlServletProfileInitializer();
        initializer.initialize(context);

        if (profiles != null) {
            context.getEnvironment().setActiveProfiles(StringUtils.commaDelimitedListToStringArray(profiles));
        }

        context.refresh();

        return context;
    }
}
