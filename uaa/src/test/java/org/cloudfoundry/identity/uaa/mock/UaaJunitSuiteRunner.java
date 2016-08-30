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

import org.junit.runner.Description;
import org.junit.runner.Runner;
import org.junit.runner.notification.RunListener;
import org.junit.runner.notification.RunNotifier;
import org.junit.runners.BlockJUnit4ClassRunner;
import org.junit.runners.Suite;
import org.junit.runners.model.InitializationError;
import org.junit.runners.model.RunnerBuilder;
import org.reflections.Reflections;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.context.support.XmlWebApplicationContext;

import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Suite that runs classes that extend the
 * org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest base class.
 * by default all sub classes will be run, in random order.
 * For a suite to change the classes to be run, simply implemement a method with the following signature
 * public static Class<?>[] suiteClasses()
 */
public class UaaJunitSuiteRunner extends Suite {

    protected static Class<?>[] allSuiteClasses() {
        Reflections reflections = new Reflections("org.cloudfoundry.identity.uaa");
        Set<Class<? extends InjectedMockContextTest>> subTypes =
            reflections.getSubTypesOf(InjectedMockContextTest.class).stream().filter(
                c -> !Modifier.isAbstract(c.getModifiers())
            ).collect(Collectors.toSet());
        return subTypes.toArray(new Class[subTypes.size()]);
    }

    public static Class<?>[] suiteClasses(Class<?> klass)  {
        try {
            Method suiteMethod = klass.getDeclaredMethod("suiteClasses");
            if (!Modifier.isStatic(suiteMethod.getModifiers())) {
                throw new RuntimeException(klass.getName() + ".suiteClasses() must be static");
            }
            Class<?>[] result = (Class<?>[]) suiteMethod.invoke(null); // static method
            return result;
        } catch (InvocationTargetException e) {
            throw new RuntimeException("unable to invoke suiteClasses",e);
        } catch (NoSuchMethodException e) {
            return allSuiteClasses();
        } catch (IllegalAccessException e) {
            throw new RuntimeException("method suiteClasses is not accessible",e);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    public UaaJunitSuiteRunner(final Class<?> klass, RunnerBuilder builder) throws InitializationError {
        super(new RunnerBuilder() {
                  @Override
                  public Runner runnerForClass(Class<?> testClass) throws Throwable {
                      return new BlockJUnit4ClassRunner(testClass) {
                          @Override
                          protected Object createTest() throws Exception {
                              Object context = getFieldValue(klass, "webApplicationContext");
                              Object test = super.createTest();
                              if (test instanceof Contextable) {
                                  ((Contextable) test).inject((XmlWebApplicationContext) context);
                              }
                              return test;
                          }
                      };
                  }
              },
            klass,
            UaaJunitSuiteRunner.suiteClasses(klass)

        );
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
