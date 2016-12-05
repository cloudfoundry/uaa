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
package org.cloudfoundry.identity.uaa;

import org.cloudfoundry.identity.uaa.authentication.manager.DynamicZoneAwareAuthenticationManager;
import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.client.ClientAdminBootstrap;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.user.JdbcUaaUserDatabase;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.xml.ResourceEntityResolver;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockRequestDispatcher;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.context.support.AbstractRefreshableWebApplicationContext;

import javax.servlet.RequestDispatcher;
import javax.sql.DataSource;
import java.io.IOException;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * @author Dave Syer
 *
 */
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
    }

    @After
    public void cleanup() throws Exception {
        System.clearProperty("spring.profiles.active");
        System.clearProperty("CLOUD_FOUNDRY_CONFIG_PATH");
        System.clearProperty("UAA_CONFIG_FILE");
        if (context != null) {
            if (context.containsBean("scimEndpoints")) {
                TestUtils.deleteFrom(context.getBean("dataSource", DataSource.class), "sec_audit");
            }
            context.close();
        }
    }

    @Test
    public void testRootContextDefaults() throws Exception {
        context = getServletContext("hsqldb", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        assertNotNull(context.getBean("userDatabase", JdbcUaaUserDatabase.class));
        FilterChainProxy filterChain = (FilterChainProxy)context.getBean("org.springframework.security.filterChainProxy");
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/Users");
        request.setServletPath("");
        request.setPathInfo("/Users");
        filterChain.doFilter(request, response, new MockFilterChain());
        assertEquals(401, response.getStatus());
    }

    @Test
    public void testOverrideYmlConfigPath() throws Exception {
        System.setProperty("UAA_CONFIG_PATH", "./src/test/resources/test/config");
        context = getServletContext("file:./src/main/webapp/WEB-INF/spring-servlet.xml",
                        "classpath:/test/config/test-override.xml");
        assertEquals("/tmp/uaa/logs", context.getBean("foo", String.class));
        assertEquals("[cf, my, support]",
                        ReflectionTestUtils.getField(context.getBean(ClientAdminBootstrap.class), "autoApproveClients")
                                        .toString());
        ScimUserProvisioning users = context.getBean(ScimUserProvisioning.class);
        assertTrue(users.retrieveAll().size() > 0);
    }

    @Test
    public void testLdapProfile() throws Exception {
        context = getServletContext("ldap,default", "file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        AuthenticationManager authenticationManager = null;
        try {
            authenticationManager = context.getBean("zoneAwareAuthzAuthenticationManager", AuthenticationManager.class);
        } catch (NoSuchBeanDefinitionException e) {
        }
        assertNotNull(authenticationManager);
        assertEquals(DynamicZoneAwareAuthenticationManager.class, authenticationManager.getClass());
    }

    private ConfigurableApplicationContext getServletContext(String... resources) {
        String profiles = null;
        String[] resourcesToLoad = resources;
        if (!resources[0].endsWith(".xml")) {
            profiles = resources[0];
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
        MockServletContext servletContext = new MockServletContext() {
            @Override
            public RequestDispatcher getNamedDispatcher(String path) {
                return new MockRequestDispatcher("/");
            }

            public String getVirtualServerName() {
                return null;
            }
        };
        context.setServletContext(servletContext);
        MockServletConfig servletConfig = new MockServletConfig(servletContext);
        servletConfig.addInitParameter("environmentConfigLocations", "required_configuration.yml,file:${UAA_CONFIG_PATH}/uaa.yml,login.yml");
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
