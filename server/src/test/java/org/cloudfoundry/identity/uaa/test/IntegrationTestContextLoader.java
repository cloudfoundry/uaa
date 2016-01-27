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
package org.cloudfoundry.identity.uaa.test;

import org.springframework.context.ApplicationContext;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.FileSystemResourceLoader;
import org.springframework.core.io.ResourceLoader;
import org.springframework.mock.web.MockServletContext;
import org.springframework.test.context.ContextConfigurationAttributes;
import org.springframework.test.context.MergedContextConfiguration;
import org.springframework.test.context.SmartContextLoader;
import org.springframework.test.context.web.WebMergedContextConfiguration;
import org.springframework.util.Assert;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import javax.servlet.ServletContext;

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
        WebMergedContextConfiguration webMergedConfig = (WebMergedContextConfiguration) mergedConfig;

        AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();

        ApplicationContext parent = mergedConfig.getParentApplicationContext();
        if (parent != null) {
            context.setParent(parent);
        }
        configureWebResources(context, webMergedConfig);
        context.getEnvironment().setActiveProfiles(mergedConfig.getActiveProfiles());
        new YamlServletProfileInitializerContextInitializer().initializeContext(context, environmentConfigDefaults());
        context.setConfigLocations(mergedConfig.getLocations());
        context.register(mergedConfig.getClasses());
        context.refresh();
        context.registerShutdownHook();
        return context;
    }

    protected String environmentConfigDefaults() {
        return "uaa.yml,login.yml";
    }

    protected void configureWebResources(AnnotationConfigWebApplicationContext context,
                                         WebMergedContextConfiguration webMergedConfig) {

        ApplicationContext parent = context.getParent();

        // if the WAC has no parent or the parent is not a WAC, set the WAC as
        // the Root WAC:
        if (parent == null || (!(parent instanceof WebApplicationContext))) {
            String resourceBasePath = webMergedConfig.getResourceBasePath();
            ResourceLoader resourceLoader = resourceBasePath.startsWith(ResourceLoader.CLASSPATH_URL_PREFIX) ? new DefaultResourceLoader()
                    : new FileSystemResourceLoader();

            ServletContext servletContext = new MockServletContext(resourceBasePath, resourceLoader);
            servletContext.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, context);
            context.setServletContext(servletContext);
        }
        else {
            ServletContext servletContext = null;

            // find the Root WAC
            while (parent != null) {
                if (parent instanceof WebApplicationContext && !(parent.getParent() instanceof WebApplicationContext)) {
                    servletContext = ((WebApplicationContext) parent).getServletContext();
                    break;
                }
                parent = parent.getParent();
            }
            Assert.state(servletContext != null, "Failed to find Root WebApplicationContext in the context hierarchy");
            context.setServletContext(servletContext);
        }
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
