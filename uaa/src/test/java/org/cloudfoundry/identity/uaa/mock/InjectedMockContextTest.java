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

import org.flywaydb.core.Flyway;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Rule;
import org.junit.rules.TestRule;
import org.junit.runner.Description;
import org.junit.runners.model.Statement;
import org.springframework.restdocs.JUnitRestDocumentation;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import static org.junit.Assume.assumeTrue;
import static org.springframework.restdocs.mockmvc.MockMvcRestDocumentation.documentationConfiguration;
import static org.springframework.restdocs.templates.TemplateFormats.markdown;

public class InjectedMockContextTest implements Contextable {

    @ClassRule
    public static SkipWhenNotRunningInSuiteRule skip = new SkipWhenNotRunningInSuiteRule();

    @Rule
    public JUnitRestDocumentation restDocumentation = new JUnitRestDocumentation("build/generated-snippets");

    private static XmlWebApplicationContext webApplicationContext;
    private static MockMvc mockMvc;
    private static volatile boolean mustDestroy = false;

    public static XmlWebApplicationContext getWebApplicationContext() {
        return webApplicationContext;
    }

    public static MockMvc getMockMvc() {
        return mockMvc;
    }

    public static boolean isMustDestroy() {
        return mustDestroy;
    }

    @Before
    public void initContextIfWeNeedIt() throws Exception {
        if (getWebApplicationContext() == null) {
            webApplicationContext = DefaultConfigurationTestSuite.setUpContext();
            mustDestroy = true;
        }

        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilter(springSecurityFilterChain)
            .apply(documentationConfiguration(this.restDocumentation)
                .uris().withPort(80).and()
                .snippets()
                .withTemplateFormat(markdown()))
            .build();
    }

    @AfterClass
    public static void mustDestroy() throws Exception {
        if (isMustDestroy()) {
            webApplicationContext.getBean(Flyway.class).clean();
            webApplicationContext.destroy();
        }
        webApplicationContext = null;
        mockMvc = null;
        mustDestroy = false;
    }

    @Override
    public void inject(XmlWebApplicationContext context) {
        webApplicationContext = context;
    }

    public static class SkipWhenNotRunningInSuiteRule implements TestRule {
        @Override
        public Statement apply(Statement statement, Description description) {
            assumeTrue(UaaBaseSuite.shouldMockTestBeRun());
            return statement;
        }
    }
}
