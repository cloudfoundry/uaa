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

import org.junit.runner.Description;
import org.junit.runner.Runner;
import org.junit.runner.notification.RunListener;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.Suite;
import org.junit.runners.model.InitializationError;
import org.junit.runners.model.RunnerBuilder;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.lang.reflect.Field;
import java.util.List;

public class UaaJunitSuiteRunner extends Suite {


    public UaaJunitSuiteRunner(RunnerBuilder builder, Class<?>[] classes) throws InitializationError {
        super(builder, classes);
    }

    protected UaaJunitSuiteRunner(RunnerBuilder builder, Class<?> klass, Class<?>[] suiteClasses) throws InitializationError {
        super(builder, klass, suiteClasses);
    }

    public UaaJunitSuiteRunner(final Class<?> klass, RunnerBuilder builder) throws InitializationError {
        super(klass, new RunnerBuilder() {
            @Override
            public Runner runnerForClass(Class<?> testClass) throws Throwable {
                return new BlockJUnit4ClassRunner(testClass) {
                    @Override
                    protected Object createTest() throws Exception {
                        Object context = getFieldValue(klass,"webApplicationContext");
                        Object mockMvc = getFieldValue(klass, "mockMvc");
                        Object test = super.createTest();
                        if (test instanceof Contextable) {
                            ((Contextable)test).inject((XmlWebApplicationContext) context, (MockMvc) mockMvc);
                        }
                        return test;
                    }
                };
            }
        });
    }

    public static Object getFieldValue(Class<?> klass, String name) {
        Field field = ReflectionUtils.findField(klass, name);
        field.setAccessible(true);
        return ReflectionUtils.getField(field, klass);

    }

    protected UaaJunitSuiteRunner(Class<?> klass, List<Runner> runners) throws InitializationError {
        super(klass, runners);
    }

    protected UaaJunitSuiteRunner(Class<?> klass, Class<?>[] suiteClasses) throws InitializationError {
        super(klass, suiteClasses);
    }

    @Override
    protected void runChild(Runner runner, RunNotifier notifier) {
        notifier.addListener(new OurListener());
        super.runChild(runner, notifier);
    }

    public class OurListener extends RunListener {
        @Override
        public void testStarted(Description description) throws Exception {
            super.testStarted(description);
        }

        @Override
        public void testRunStarted(Description description) throws Exception {
            super.testRunStarted(description);
        }
    }
}
