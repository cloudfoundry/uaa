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

import io.honeycomb.libhoney.EventFactory;
import io.honeycomb.libhoney.HoneyClient;
import io.honeycomb.libhoney.LibHoney;
import org.cloudfoundry.identity.uaa.authentication.event.IdentityProviderAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.authentication.event.MfaAuthenticationFailureEvent;
import org.cloudfoundry.identity.uaa.test.HoneycombAuditEventTestListener;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.flywaydb.core.Flyway;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.event.AuthenticationFailureLockedEvent;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.*;

@RunWith(UaaJunitSuiteRunner.class)
public class DefaultConfigurationTestSuite extends UaaBaseSuite {
    private static volatile XmlWebApplicationContext webApplicationContext;

    public static Class<?>[] suiteClasses() {
        Class<?>[] result = UaaJunitSuiteRunner.allSuiteClasses();
        //Class<?>[] result = new Class[] {LimitedModeLoginMockMvcTests.class, LoginMockMvcTests.class};
        //Class<?>[] result = new Class[] {IdentityProviderEndpointsMockMvcTests.class, SamlIDPRefreshMockMvcTests.class};
        //for now, sort the test classes until we have figured out all
        //test poisoning that is occurring
        Arrays.sort(result, Comparator.comparing(Class::getSimpleName));
        return result;
    }

    public DefaultConfigurationTestSuite() {
    }

    public static void clearDatabase() {
        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setEnvironment(getMockEnvironment());
        webApplicationContext.setConfigLocations("classpath:spring/env.xml", "classpath:spring/data-source.xml");
        webApplicationContext.refresh();
        webApplicationContext.getBean(Flyway.class).clean();
        webApplicationContext.destroy();
    }

    @BeforeClass
    public static void setUpContextVoid() {
        setUpContext();
    }

    @AfterClass
    public static void destroyMyContext() {
        webApplicationContext.destroy();
        webApplicationContext = null;
    }

    public static XmlWebApplicationContext setUpContext() {
        webApplicationContext = new XmlWebApplicationContext();
        MockEnvironment mockEnvironment = getMockEnvironment();
        webApplicationContext.setEnvironment(mockEnvironment);
        webApplicationContext.setServletContext(new MockServletContext() {
            @Override
            public <Type extends EventListener> void addListener(Type t) {
                //no op
            }
        });
        new YamlServletProfileInitializerContextInitializer()
          .initializeContext(webApplicationContext, "endpoint_test_config.yml,uaa.yml,login.yml,required_configuration.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();
        webApplicationContext.registerShutdownHook();

        EventFactory honeycombEventFactory = honeycombEventFactory(
                System.getenv("HONEYCOMB_KEY"),
                System.getenv("HONEYCOMB_DATASET"),
                Optional.ofNullable(System.getProperty("testId")).orElse("-1")
        );
        honeycombAuditEventTestListenerAuthenticationFailureLockedEvent(
                webApplicationContext, honeycombEventFactory);
        honeycombAuditEventTestListenerIdentityProviderAuthenticationFailureEvent(
                webApplicationContext, honeycombEventFactory);
        honeycombAuditEventTestListenerMfaAuthenticationFailureEvent(
                webApplicationContext, honeycombEventFactory);

        return webApplicationContext;
    }

    private static MockEnvironment getMockEnvironment() {
        MockEnvironment mockEnvironment = new MockEnvironment();
        if (System.getProperty("spring.profiles.active")!=null) {
            mockEnvironment.setProperty("spring_profiles", System.getProperty("spring.profiles.active"));
        } else {
            mockEnvironment.setProperty("spring_profiles", "default");
        }
        return mockEnvironment;
    }

    private static EventFactory honeycombEventFactory(String honeycombKey, String dataset, String testId) {
        HoneyClient honeyClient = LibHoney.create(
                LibHoney.options()
                        .setWriteKey(honeycombKey)
                        .setDataset(dataset)
                        .build()
        );

        if (honeycombKey == null || dataset == null) {
            return honeyClient.buildEventFactory().build();
        }

        String hostName = "";
        try {
            hostName = InetAddress.getLocalHost().getHostName();

        } catch (UnknownHostException e) {
            e.printStackTrace();
        }

        EventFactory.Builder builder = honeyClient.buildEventFactory()
                .addField("junit", "4")
                .addField("testId", testId)
                .addField("cpuCores", Runtime.getRuntime().availableProcessors())
                .addField("hostname", hostName);

        for (Map.Entry entry : System.getProperties().entrySet()) {
            builder.addField(entry.getKey().toString(), entry.getValue());
        }

        builder.addField("DB", System.getenv().get("DB"));
        builder.addField("SPRING_PROFILE", System.getenv().get("SPRING_PROFILE"));
        builder.addField("JAVA_HOME", System.getenv().get("JAVA_HOME"));

        return builder.build();
    }

    private static HoneycombAuditEventTestListener honeycombAuditEventTestListenerAuthenticationFailureLockedEvent(
            ConfigurableApplicationContext configurableApplicationContext, EventFactory honeycombEventFactory) {

        HoneycombAuditEventTestListener<AuthenticationFailureLockedEvent> listener =
                HoneycombAuditEventTestListener.forEventClass(AuthenticationFailureLockedEvent.class);
        listener.setHoneycombEventFactory(honeycombEventFactory);
        configurableApplicationContext.addApplicationListener(listener);
        return listener;
    }

    private static HoneycombAuditEventTestListener honeycombAuditEventTestListenerIdentityProviderAuthenticationFailureEvent(
            ConfigurableApplicationContext configurableApplicationContext,EventFactory honeycombEventFactory) {

        HoneycombAuditEventTestListener<IdentityProviderAuthenticationFailureEvent> listener =
                HoneycombAuditEventTestListener.forEventClass(IdentityProviderAuthenticationFailureEvent.class);
        listener.setHoneycombEventFactory(honeycombEventFactory);
        configurableApplicationContext.addApplicationListener(listener);
        return listener;
    }

    private static HoneycombAuditEventTestListener honeycombAuditEventTestListenerMfaAuthenticationFailureEvent(
            ConfigurableApplicationContext configurableApplicationContext, EventFactory honeycombEventFactory) {

        HoneycombAuditEventTestListener<MfaAuthenticationFailureEvent> listener =
                HoneycombAuditEventTestListener.forEventClass(MfaAuthenticationFailureEvent.class);
        listener.setHoneycombEventFactory(honeycombEventFactory);
        configurableApplicationContext.addApplicationListener(listener);
        return listener;
    }
}
