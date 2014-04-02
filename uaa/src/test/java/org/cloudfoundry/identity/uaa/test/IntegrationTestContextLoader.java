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
package org.cloudfoundry.identity.uaa.test;

import org.cloudfoundry.identity.uaa.config.YamlServletProfileInitializer;
import org.springframework.context.ApplicationContext;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.context.ContextConfigurationAttributes;
import org.springframework.test.context.MergedContextConfiguration;
import org.springframework.test.context.SmartContextLoader;
import org.springframework.test.context.web.WebMergedContextConfiguration;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

public class IntegrationTestContextLoader implements SmartContextLoader {

    @Override
    public void processContextConfiguration(ContextConfigurationAttributes configAttributes) {

    }

    @Override
    public ApplicationContext loadContext(MergedContextConfiguration mergedConfig) throws Exception {
        if (!(mergedConfig instanceof WebMergedContextConfiguration)) {
            throw new IllegalArgumentException(String.format(
                    "Cannot load WebApplicationContext from non-web merged context configuration %s. "
                            + "Consider annotating your test class with @WebAppConfiguration.", mergedConfig));
        }

        AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();

        ApplicationContext parent = mergedConfig.getParentApplicationContext();
        if (parent != null) {
            context.setParent(parent);
        }
        context.setServletContext(new MockServletContext());
        context.setConfigLocations(mergedConfig.getLocations());
        context.register(mergedConfig.getClasses());
        new YamlServletProfileInitializer().initialize(context);
        context.refresh();
        context.registerShutdownHook();
        return context;
    }

    @Override
    public String[] processLocations(Class<?> clazz, String... locations) {
        return locations;
    }

    @Override
    public final ApplicationContext loadContext(String... locations) throws Exception {
        throw new UnsupportedOperationException(
                getClass().getSimpleName() + " does not support the loadContext(String... locations) method");
    }
}
