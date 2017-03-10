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
package org.cloudfoundry.identity.uaa.mock;

import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.flywaydb.core.Flyway;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.util.Arrays;

@RunWith(UaaJunitSuiteRunner.class)
public class DefaultConfigurationTestSuite extends UaaBaseSuite {

    private static volatile XmlWebApplicationContext webApplicationContext;

    public static Class<?>[] suiteClasses() {
        Class<?>[] result = UaaJunitSuiteRunner.allSuiteClasses();
        //Class<?>[] result = new Class[] {IdentityProviderEndpointsMockMvcTests.class, SamlIDPRefreshMockMvcTests.class};
        //for now, sort the test classes until we have figured out all
        //test poisoning that is occurring
        Arrays.sort(result, (o1, o2) -> o1.getSimpleName().compareTo(o2.getSimpleName()));
        return result;
    }

    public DefaultConfigurationTestSuite() {
    }


    public static void clearDatabase() throws Exception {
        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setEnvironment(getMockEnvironment());
        webApplicationContext.setConfigLocations(new String[]{"classpath:spring/env.xml", "classpath:spring/data-source.xml"});
        webApplicationContext.refresh();
        webApplicationContext.getBean(Flyway.class).clean();
        webApplicationContext.destroy();
    }

    @BeforeClass
    public static void setUpContextVoid() throws Exception {
        setUpContext();
    }
    public static XmlWebApplicationContext setUpContext() throws Exception {
        webApplicationContext = new XmlWebApplicationContext();
        MockEnvironment mockEnvironment = getMockEnvironment();
        webApplicationContext.setEnvironment(mockEnvironment);
        webApplicationContext.setServletContext(new MockServletContext());
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "uaa.yml,login.yml,required_configuration.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();
        webApplicationContext.registerShutdownHook();

        return webApplicationContext;
    }

    protected static MockEnvironment getMockEnvironment() {
        MockEnvironment mockEnvironment = new MockEnvironment();
        if (System.getProperty("spring.profiles.active")!=null) {
            mockEnvironment.setProperty("spring_profiles", System.getProperty("spring.profiles.active"));
        } else {
            mockEnvironment.setProperty("spring_profiles", "default");
        }
        return mockEnvironment;
    }

    @AfterClass
    public static void destroyMyContext() throws Exception {
        //webApplicationContext.getBean(Flyway.class).clean();
        webApplicationContext.destroy();
        webApplicationContext = null;
    }

}
