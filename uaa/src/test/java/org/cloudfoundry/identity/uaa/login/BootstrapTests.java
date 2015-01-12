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
import org.cloudfoundry.identity.uaa.config.YamlPropertiesFactoryBean;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderConfigurator;
import org.cloudfoundry.identity.uaa.login.saml.IdentityProviderDefinition;
import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.support.GenericXmlApplicationContext;
import org.springframework.core.env.PropertiesPropertySource;
import org.springframework.core.io.FileSystemResource;
import org.springframework.core.io.Resource;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.util.StringUtils;
import org.springframework.web.servlet.ViewResolver;

import java.io.File;
import java.util.HashSet;
import java.util.Map;
import java.util.Scanner;
import java.util.Set;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;

/**
 * @author Dave Syer
 * 
 */
public class BootstrapTests {

    private GenericXmlApplicationContext context;

    @Before
    public void setup() throws Exception {
        System.clearProperty("spring.profiles.active");
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
    }

    @Test
    public void testRootContextDefaults() throws Exception {
        context = getServletContext(null, "./src/main/resources/login.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("resetPasswordController", ResetPasswordController.class));
    }

    @Test
    public void testSamlProfileNoData() throws Exception {
        System.setProperty("login.saml.metadataTrustCheck", "false");
        context = getServletContext("default", "./src/main/resources/login.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
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

        context = getServletContext("default", "./src/main/resources/login.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(IdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        assertEquals(
            DefaultProtocolSocketFactory.class.getName(),
            context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions().get(0).getSocketFactoryClassName()
        );
        assertEquals(
            IdentityProviderDefinition.MetadataLocation.URL,
            context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions().get(0).getType()
        );

    }

    @Test
    public void testLegacySamlProfileMetadataFile() throws Exception {
        System.setProperty("login.idpMetadataFile", "./src/test/resources/test.saml.metadata");
        System.setProperty("login.idpEntityAlias", "testIDPFile");
        System.setProperty("login.saml.metadataTrustCheck", "false");
        context = getServletContext("default,saml,fileMetadata", "./src/main/resources/login.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(IdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        assertEquals(
            IdentityProviderDefinition.MetadataLocation.FILE,
            context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions().get(0).getType());
    }

    @Test
    public void testLegacySamlProfileMetadataConfig() throws Exception {
        String metadataString = new Scanner(new File("./src/main/resources/sample-okta-localhost.xml")).useDelimiter("\\Z").next();
        System.setProperty("login.idpMetadata", metadataString);
        System.setProperty("login.idpEntityAlias", "testIDPData");
        context = getServletContext("default,saml,configMetadata", "./src/main/resources/login.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertEquals(
            IdentityProviderDefinition.MetadataLocation.DATA,
            context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions().get(0).getType());
    }


    @Test
    public void testLegacySamlProfileHttpsMetaUrl() throws Exception {
        System.setProperty("login.saml.metadataTrustCheck", "false");
        System.setProperty("login.idpMetadataURL", "https://localhost:9696/nodata");
        System.setProperty("login.idpEntityAlias", "testIDPUrl");

        context = getServletContext("default", "./src/main/resources/login.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(IdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        assertEquals(
            1,
            context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions().size()
        );
        assertEquals(
            EasySSLProtocolSocketFactory.class.getName(),
            context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions().get(0).getSocketFactoryClassName()
        );
        assertEquals(
            IdentityProviderDefinition.MetadataLocation.URL,
            context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions().get(0).getType()
        );

    }

    @Test
    public void testLegacySamlProfileHttpsMetaUrlWithoutPort() throws Exception {
        System.setProperty("login.saml.metadataTrustCheck", "false");
        System.setProperty("login.idpMetadataURL", "https://localhost/nodata");
        System.setProperty("login.idpEntityAlias", "testIDPUrl");

        context = getServletContext("default", "./src/main/resources/login.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("viewResolver", ViewResolver.class));
        assertNotNull(context.getBean("samlLogger", SAMLDefaultLogger.class));
        assertFalse(context.getBean(IdentityProviderConfigurator.class).isLegacyMetadataTrustCheck());
        assertEquals(
            1,
            context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions().size()
        );
        assertEquals(
            EasySSLProtocolSocketFactory.class.getName(),
            context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions().get(0).getSocketFactoryClassName()
        );
        assertEquals(
            IdentityProviderDefinition.MetadataLocation.URL,
            context.getBean(IdentityProviderConfigurator.class).getIdentityProviderDefinitions().get(0).getType()
        );

    }


    @Test
    public void testMessageService() throws Exception {
        context = getServletContext("default", "./src/main/resources/login.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        Object messageService = context.getBean("messageService");
        assertNotNull(messageService);
        assertEquals(EmailService.class, messageService.getClass());

        System.setProperty("notifications.url", "");
        context = getServletContext("default", "./src/main/resources/login.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        messageService = context.getBean("messageService");
        assertNotNull(messageService);
        assertEquals(EmailService.class, messageService.getClass());

        System.setProperty("notifications.url", "example.com");
        context = getServletContext("default", "./src/main/resources/login.yml", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        messageService = context.getBean("messageService");
        assertNotNull(messageService);
        assertEquals(NotificationsService.class, messageService.getClass());
    }

    private GenericXmlApplicationContext getServletContext(String profiles, String loginYmlPath, String... resources) {
        System.setProperty("environmentYamlKey", loginYmlPath);
        GenericXmlApplicationContext context = new GenericXmlApplicationContext();

        if (profiles != null) {
            context.getEnvironment().setActiveProfiles(StringUtils.commaDelimitedListToStringArray(profiles));
        }

        context.load(resources);

        // Simulate what happens in the webapp when the
        // YamlServletProfileInitializer kicks in
        YamlPropertiesFactoryBean factory = new YamlPropertiesFactoryBean();
        factory.setResources(new Resource[] { new FileSystemResource(loginYmlPath) });
        context.getEnvironment().getPropertySources()
                        .addLast(new PropertiesPropertySource("servletProperties", factory.getObject()));

        context.refresh();

        return context;
    }
}
