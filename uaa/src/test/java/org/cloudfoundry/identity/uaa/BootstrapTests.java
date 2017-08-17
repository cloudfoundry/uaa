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

import org.apache.commons.codec.binary.Base64;
import org.cloudfoundry.identity.uaa.client.ClientAdminBootstrap;
import org.cloudfoundry.identity.uaa.impl.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.scim.ScimUserProvisioning;
import org.cloudfoundry.identity.uaa.test.TestUtils;
import org.cloudfoundry.identity.uaa.zone.BrandingInformation.Banner;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneHolder;
import org.flywaydb.core.Flyway;
import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.springframework.beans.BeansException;
import org.springframework.beans.factory.support.DefaultListableBeanFactory;
import org.springframework.beans.factory.xml.ResourceEntityResolver;
import org.springframework.beans.factory.xml.XmlBeanDefinitionReader;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.mock.web.MockRequestDispatcher;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
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
            context.getBean(Flyway.class).clean();
            context.close();
        }
    }



    @Test
    public void testOverrideYmlConfigPath() throws Exception {
        dotestOverrideYmlConfigPath("UAA_CONFIG_PATH", "./src/test/resources/test/config");
        dotestOverrideYmlConfigPath("UAA_CONFIG_FILE", "./src/test/resources/test/config/uaa.yml");
    }

    public void dotestOverrideYmlConfigPath(String configVariable, String configValue) throws Exception {
        System.setProperty(configVariable, configValue);
        try {
            context = getServletContext("file:./src/main/webapp/WEB-INF/spring-servlet.xml",
                                        "classpath:/test/config/test-override.xml");
            assertEquals("/tmp/uaa/logs", context.getBean("foo", String.class));
            assertEquals("[cf, my, support]",
                            ReflectionTestUtils.getField(context.getBean(ClientAdminBootstrap.class), "autoApproveClients")
                                            .toString());
            ScimUserProvisioning users = context.getBean(ScimUserProvisioning.class);
            assertNotNull(users.query("username eq \"paul\"", IdentityZoneHolder.get().getId()).get(0));
            assertNotNull(users.query("username eq \"stefan\"", IdentityZoneHolder.get().getId()).get(0));
        } finally {
            System.clearProperty(configVariable);
        }
    }

    @Test
    public void testBrandingProperties() {
        System.setProperty("UAA_CONFIG_FILE", "./src/test/resources/test/config/uaa.yml");
        System.setProperty("environmentYamlKey", "environmentYamlKey");
        try {
            context = getServletContext("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
            Banner banner = IdentityZoneHolder.resolveBranding().getBanner();
            assertTrue(Base64.isBase64(banner.getLogo().getBytes()));
            assertEquals("cool beagle", banner.getText());
            assertEquals("data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAGXRFWHRTb2Z0d2FyZQBBZG9iZSBJbWFnZVJlYWR5ccllPAAAATBJREFUeNqk008og3Ecx/HNnrJSu63kIC5qKRe7KeUiOSulTHJUTrsr0y5ycFaEgyQXElvt5KDYwU0uO2hSUy4KoR7v7/qsfmjPHvzq1e/XU8/39/3zPFHf9yP/WV7jED24nGRbxDFWUAsToM05zyKFLG60d/wmQBxWzwyOlMU1phELEyCmtPeRQRoVbKOM0VYB6q0QW+3IYQpJFFDEYFCAiMqwNY857Ko3SxjGBTbRXb+xMUamcMbWh148YwJvOHSCdyqTAdxZo72ADGwKT98C9CChcxUPQSVYLz50toae4Fy9WcAISl7AiN/RhS1N5RV5rOLxx5eom90pvGAI/VjHMm6bfspK18a1gXvsqM41XDVL052C1Tim56cYd/rR+mdSrXGluxfm5S8Z/HV9CjAAvQZLXoa5mpgAAAAASUVORK5CYII=", banner.getLogo());
            assertEquals("F2345", banner.getTextColor());
            assertEquals("F9999", banner.getBackgroundColor());
            assertEquals("http://example.com", banner.getLink());
        } finally {
            System.clearProperty("UAA_CONFIG_FILE");
        }
    }

    private ConfigurableApplicationContext getServletContext(String... resources) {
        String environmentConfigLocations = "required_configuration.yml,${LOGIN_CONFIG_URL},file:${LOGIN_CONFIG_PATH}/login.yml,file:${CLOUD_FOUNDRY_CONFIG_PATH}/login.yml,${UAA_CONFIG_URL},file:${UAA_CONFIG_FILE},file:${UAA_CONFIG_PATH}/uaa.yml,file:${CLOUD_FOUNDRY_CONFIG_PATH}/uaa.yml";
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
        servletConfig.addInitParameter("environmentConfigLocations", environmentConfigLocations);
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
