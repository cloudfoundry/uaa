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
package org.cloudfoundry.identity.uaa.mock;

import com.googlecode.flyway.core.Flyway;
import junit.framework.JUnit4TestAdapter;
import junit.framework.TestSuite;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Suite;
import org.reflections.Reflections;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.util.Arrays;
import java.util.Comparator;
import java.util.Set;

@RunWith(UaaJunitSuiteRunner.class)
public class DefaultConfigurationTestSuite extends UaaBaseSuite {
    private static XmlWebApplicationContext webApplicationContext;
    private static MockMvc mockMvc;

    public static Class<?>[] suiteClasses() {
        Class<?>[] result = UaaJunitSuiteRunner.allSuiteClasses();
        //for now, sort the test classes until we have figured out all
        //test poisoning that is occurring
        Arrays.sort(result, new Comparator<Class<?>>() {
            @Override
            public int compare(Class<?> o1, Class<?> o2) {
                return o1.getSimpleName().compareTo(o2.getSimpleName());
            }
        });
        return result;
    }

    public DefaultConfigurationTestSuite() {
    }

    @BeforeClass
    public static void setUpContextVoid() throws Exception {
        setUpContext();
    }
    public static Object[] setUpContext() throws Exception {
        webApplicationContext = new XmlWebApplicationContext();
        MockEnvironment mockEnvironment = new MockEnvironment();
        mockEnvironment.setProperty("login.invitationsEnabled", "true");
        webApplicationContext.setEnvironment(mockEnvironment);
        webApplicationContext.setServletContext(new MockServletContext());
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "uaa.yml,login.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();
        webApplicationContext.registerShutdownHook();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilter(springSecurityFilterChain)
            .build();
        return new Object[] {webApplicationContext, mockMvc};
    }

    @AfterClass
    public static void destroyMyContext() throws Exception {
        webApplicationContext.getBean(Flyway.class).clean();
        webApplicationContext.destroy();
        webApplicationContext = null;
        mockMvc = null;
    }

}
