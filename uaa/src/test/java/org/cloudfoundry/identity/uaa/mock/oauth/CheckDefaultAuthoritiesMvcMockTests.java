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
package org.cloudfoundry.identity.uaa.mock.oauth;

import java.util.Set;

import org.cloudfoundry.identity.uaa.config.YamlServletProfileInitializer;
import org.cloudfoundry.identity.uaa.test.DefaultIntegrationTestConfig;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.mock.web.MockServletConfig;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.oauth2.provider.ClientRegistrationService;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

public class CheckDefaultAuthoritiesMvcMockTests {

    AnnotationConfigWebApplicationContext webApplicationContext;
    ClientRegistrationService clientRegistrationService;
    private MockMvc mockMvc;
    private Set<String> defaultAuthorities;

    @Before
    public void setUp() throws Exception {
        MockServletContext context = new MockServletContext();
        MockServletConfig config = new MockServletConfig(context);
        config.addInitParameter("environmentConfigDefaults", "uaa.yml,login.yml");

        webApplicationContext = new AnnotationConfigWebApplicationContext();
        webApplicationContext.setServletContext(context);
        webApplicationContext.setServletConfig(config);
        new YamlServletProfileInitializer().initialize(webApplicationContext);
        webApplicationContext.register(DefaultIntegrationTestConfig.class);
        webApplicationContext.refresh();
        webApplicationContext.registerShutdownHook();
        FilterChainProxy springSecurityFilterChain = webApplicationContext.getBean("springSecurityFilterChain", FilterChainProxy.class);
        clientRegistrationService = (ClientRegistrationService) webApplicationContext.getBean("clientRegistrationService");
        mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext)
            .addFilter(springSecurityFilterChain)
            .build();

        defaultAuthorities = (Set<String>) webApplicationContext.getBean("defaultUserAuthorities");
    }

    @Test
    public void testDefaultAuthorities() throws Exception {
        Assert.assertEquals(10, defaultAuthorities.size());
        String[] expected = new String[] {
            "openid",
            "scim.me",
            "cloud_controller.read",
            "cloud_controller.write",
            "cloud_controller_service_permissions.read",
            "password.write",
            "scim.userids",
            "uaa.user",
            "approvals.me",
            "oauth.approvals"
        };
        for (String s : expected) {
            Assert.assertTrue("Expecting authority to be present:"+s,defaultAuthorities.contains(s));
        }
    }
}