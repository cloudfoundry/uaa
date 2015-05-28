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
import org.apache.tomcat.jdbc.pool.DataSource;
import org.cloudfoundry.identity.uaa.authentication.Origin;
import org.cloudfoundry.identity.uaa.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderDefinition;
import org.cloudfoundry.identity.uaa.login.util.FakeJavaMailSender;
import org.cloudfoundry.identity.uaa.rest.jdbc.SimpleSearchQueryConverter;
import org.cloudfoundry.identity.uaa.zone.IdentityProviderProvisioning;
import org.cloudfoundry.identity.uaa.zone.IdentityZone;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneResolvingFilter;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assume;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.xml.ResourceEntityResolver;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.mail.javamail.JavaMailSenderImpl;
import org.springframework.mock.web.MockRequestDispatcher;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.websso.WebSSOProfileConsumerImpl;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.util.ReflectionUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.AbstractRefreshableWebApplicationContext;
import org.springframework.web.servlet.ViewResolver;

import javax.servlet.RequestDispatcher;
import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

public class BootstrapTests {

    private ConfigurableApplicationContext context;

    private static String activeProfiles;

    @BeforeClass
    public static void saveProfiles() {
        activeProfiles = System.getProperty("spring.profiles.active");
    }

    @AfterClass
    public static void restoreProfiles() {
        if (activeProfiles != null) {
            System.setProperty("spring.profiles.active", activeProfiles);
        } else {
            System.clearProperty("spring.profiles.active");
        }
    }

    @Before
    public void setup() throws Exception {
        System.clearProperty("spring.profiles.active");
        IdentityZoneHolder.clear();
    }

    @After
    public void cleanup() throws Exception {
        System.clearProperty("spring.profiles.active");
        System.clearProperty("uaa.url");
        System.clearProperty("login.url");
        if (context != null) {
            context.close();
        }
        Set<String> removeme = new HashSet<>();
        for ( Map.Entry<Object,Object> entry : System.getProperties().entrySet()) {
            if (entry.getKey().toString().startsWith("login.") || entry.getKey().toString().startsWith("database.")) {
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
        String uaa = "uaa.some.test.domain.com";
        String login = uaa.replace("uaa", "login");
        System.setProperty("uaa.url", "https://"+uaa+":555/uaa");
        System.setProperty("login.url", "https://"+login+":555/uaa");
        context = getServletContext(null, "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("resetPasswordController", ResetPasswordController.class));
        assertEquals(864000, context.getBean("webSSOprofileConsumer", WebSSOProfileConsumerImpl.class).getMaxAuthenticationAge());
        IdentityZoneResolvingFilter filter = context.getBean(IdentityZoneResolvingFilter.class);
        Set<String> defaultHostnames = new HashSet<>(Arrays.asList(uaa, login, "localhost"));
        assertEquals(filter.getDefaultZoneHostnames(), defaultHostnames);

        //check java mail sender
        EmailService emailService = context.getBean("emailService", EmailService.class);
        Field f = ReflectionUtils.findField(EmailService.class, "mailSender");
        assertNotNull("Unable to find the JavaMailSender object on EmailService for validation.", f);
        String smtpHost = context.getEnvironment().getProperty("smtp.host");
        if (smtpHost==null || smtpHost.length()==0) {
            assertEquals(FakeJavaMailSender.class, emailService.getMailSender().getClass());
        } else {
            assertEquals(JavaMailSenderImpl.class, emailService.getMailSender().getClass());
        }

    }

    @Test
    public void testInternalHostnamesWithDBSettings() throws Exception {
        try {
            String uaa = "uaa.some.test.domain.com";
            String login = uaa.replace("uaa", "login");
            System.setProperty("smtp.host", "");
            System.setProperty("uaa.url", "https://" + uaa + ":555/uaa");
            System.setProperty("login.url", "https://" + login + ":555/uaa");
            System.setProperty("database.maxactive", "50");
            System.setProperty("database.maxidle", "5");
            System.setProperty("database.removeabandoned", "true");
            System.setProperty("database.logabandoned", "false");
            System.setProperty("database.abandonedtimeout", "45");
            System.setProperty("database.evictionintervalms", "30000");
            System.setProperty("database.caseinsensitive", "true");
            context = getServletContext(null, "login.yml", "test/hostnames/uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
            IdentityZoneResolvingFilter filter = context.getBean(IdentityZoneResolvingFilter.class);
            Set<String> defaultHostnames = new HashSet<>(Arrays.asList(uaa, login, "localhost", "host1.domain.com", "host2", "test3.localhost", "test4.localhost"));
            assertEquals(filter.getDefaultZoneHostnames(), defaultHostnames);
            DataSource ds = context.getBean(DataSource.class);
            assertEquals(50, ds.getMaxActive());
            assertEquals(5, ds.getMaxIdle());
            assertTrue(ds.isRemoveAbandoned());
            assertFalse(ds.isLogAbandoned());
            assertEquals(45, ds.getRemoveAbandonedTimeout());
            assertEquals(30000, ds.getTimeBetweenEvictionRunsMillis());
            assertTrue(context.getBean(SimpleSearchQueryConverter.class).isDbCaseInsensitive());
            //check java mail sender
            EmailService emailService = context.getBean("emailService", EmailService.class);
            assertNotNull("Unable to find the JavaMailSender object on EmailService for validation.", emailService.getMailSender());
            assertEquals(FakeJavaMailSender.class, emailService.getMailSender().getClass());
        } finally {
            System.clearProperty("database.maxactive");
            System.clearProperty("database.maxidle");
            System.clearProperty("database.removeabandoned");
            System.clearProperty("database.logabandoned");
            System.clearProperty("database.abandonedtimeout");
            System.clearProperty("database.evictionintervalms");
            System.clearProperty("smtp.host");
        }
    }

    @Test
    public void testDefaultInternalHostnamesAndNoDBSettings() throws Exception {
        try {
            System.setProperty("smtp.host","localhost");
            //travis profile script overrides these properties
            System.setProperty("database.maxactive", "100");
            System.setProperty("database.maxidle", "10");
            String uaa = "uaa.some.test.domain.com";
            String login = uaa.replace("uaa", "login");
            System.setProperty("uaa.url", "https://" + uaa + ":555/uaa");
            System.setProperty("login.url", "https://" + login + ":555/uaa");
            context = getServletContext(null, "login.yml", "uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
            IdentityZoneResolvingFilter filter = context.getBean(IdentityZoneResolvingFilter.class);
            Set<String> defaultHostnames = new HashSet<>(Arrays.asList(uaa, login, "localhost"));
            assertEquals(filter.getDefaultZoneHostnames(), defaultHostnames);
            DataSource ds = context.getBean(DataSource.class);
            assertEquals(100, ds.getMaxActive());
            assertEquals(10, ds.getMaxIdle());
            assertFalse(ds.isRemoveAbandoned());
            assertTrue(ds.isLogAbandoned());
            assertEquals(300, ds.getRemoveAbandonedTimeout());
            assertEquals(15000, ds.getTimeBetweenEvictionRunsMillis());
            if ("mysql".equals(context.getBean("platform"))) {
                assertTrue(context.getBean(SimpleSearchQueryConverter.class).isDbCaseInsensitive());
            } else {
                assertFalse(context.getBean(SimpleSearchQueryConverter.class).isDbCaseInsensitive());
            }
            //check java mail sender
            EmailService emailService = context.getBean("emailService", EmailService.class);
            assertNotNull("Unable to find the JavaMailSender object on EmailService for validation.", emailService.getMailSender());
            assertEquals(JavaMailSenderImpl.class, emailService.getMailSender().getClass());

        } finally {
            System.clearProperty("database.maxactive");
            System.clearProperty("database.maxidle");
        }
    }

    @Test
    public void testBootstrappedIdps() throws Exception {

        //generate login.yml with SAML and uaa.yml with LDAP
        System.setProperty("database.caseinsensitive", "false");
        context = getServletContext("ldap,default", true, "test/bootstrap/login.yml,login.yml","test/bootstrap/uaa.yml,uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("resetPasswordController", ResetPasswordController.class));
        IdentityProviderConfigurator samlProviders = context.getBean("metaDataProviders", IdentityProviderConfigurator.class);
        IdentityProviderProvisioning providerProvisioning = context.getBean("identityProviderProvisioning", IdentityProviderProvisioning.class);
        //ensure that ldap has been loaded up
        assertNotNull(context.getBean("ldapPooled"));
        assertFalse(context.getBean("ldapPooled", Boolean.class).booleanValue());
        assertFalse(context.getBean(SimpleSearchQueryConverter.class).isDbCaseInsensitive());
        //ensure we have some saml providers in login.yml
        //we have provided 4 here, but the original login.yml may add, but not remove some
        assertTrue(samlProviders.getIdentityProviderDefinitions().size() >= 4);

        //verify that they got loaded in the DB
        for (IdentityProviderDefinition def : samlProviders.getIdentityProviderDefinitions()) {
            assertNotNull(providerProvisioning.retrieveByOrigin(def.getIdpEntityAlias(), IdentityZone.getUaa().getId()));
        }

        assertNotNull(providerProvisioning.retrieveByOrigin(Origin.LDAP, IdentityZone.getUaa().getId()));
    }

    @Test
    public void testSamlProfileNoData() throws Exception {
        System.setProperty("login.saml.maxAuthenticationAge", "3600");
        System.setProperty("login.saml.metadataTrustCheck", "false");
        context = getServletContext("default", "login.yml","uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertEquals(3600, context.getBean("webSSOprofileConsumer", WebSSOProfileConsumerImpl.class).getMaxAuthenticationAge());
        Assume.assumeTrue(context.getEnvironment().getProperty("login.idpMetadataURL") == null);
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(IdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        assertEquals(0, context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions().size());
        SimpleUrlLogoutSuccessHandler handler = context.getBean(SimpleUrlLogoutSuccessHandler.class);
        Method getDefaultTargetUrl = ReflectionUtils.findMethod(SimpleUrlLogoutSuccessHandler.class, "getDefaultTargetUrl");
        getDefaultTargetUrl.setAccessible(true);
        Method isAlwaysUseDefaultTargetUrl = ReflectionUtils.findMethod(SimpleUrlLogoutSuccessHandler.class, "isAlwaysUseDefaultTargetUrl");
        isAlwaysUseDefaultTargetUrl.setAccessible(true);
        assertEquals(true, ReflectionUtils.invokeMethod(isAlwaysUseDefaultTargetUrl, handler));
        assertEquals("/login", ReflectionUtils.invokeMethod(getDefaultTargetUrl, handler));
    }

    @Test
    public void testLogoutRedirectConfiguration() throws Exception {
        System.setProperty("logout.redirect.parameter.disable", "false");
        System.setProperty("logout.redirect.url", "/login?parameter=true");
        try {
            context = getServletContext("default", "login.yml", "uaa.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
            SimpleUrlLogoutSuccessHandler handler = context.getBean(SimpleUrlLogoutSuccessHandler.class);
            Method getDefaultTargetUrl = ReflectionUtils.findMethod(SimpleUrlLogoutSuccessHandler.class, "getDefaultTargetUrl");
            getDefaultTargetUrl.setAccessible(true);
            Method isAlwaysUseDefaultTargetUrl = ReflectionUtils.findMethod(SimpleUrlLogoutSuccessHandler.class, "isAlwaysUseDefaultTargetUrl");
            isAlwaysUseDefaultTargetUrl.setAccessible(true);
            assertEquals(false, ReflectionUtils.invokeMethod(isAlwaysUseDefaultTargetUrl, handler));
            assertEquals("/login?parameter=true", ReflectionUtils.invokeMethod(getDefaultTargetUrl, handler));
        } finally {
            System.clearProperty("logout.redirect.parameter.disable");
            System.clearProperty("logout.redirect.url");
        }
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
        assertNotNull(findProvider(defs, "testIDPFile"));
        assertEquals(
            IdentityProviderDefinition.MetadataLocation.URL,
            findProvider(defs, "testIDPFile").getType());
        assertEquals(
            DefaultProtocolSocketFactory.class.getName(),
            findProvider(defs, "testIDPFile").getSocketFactoryClassName()
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
        assertNotNull(findProvider(defs, "testIDPFile"));
        assertEquals(
            IdentityProviderDefinition.MetadataLocation.FILE,
            findProvider(defs, "testIDPFile").getType());
    }

    protected IdentityProviderDefinition findProvider(List<IdentityProviderDefinition> defs, String alias) {
        for (IdentityProviderDefinition def : defs) {
            if (alias.equals(def.getIdpEntityAlias())) {
                return def;
            }
        }
        return null;
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
            findProvider(defs, "testIDPData").getType());
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