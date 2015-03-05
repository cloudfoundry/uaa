/*
 * *****************************************************************************
 *      Cloud Foundry
 *      Copyright (c) [2009-2015] Pivotal Software, Inc. All Rights Reserved.
 *      This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *      You may not use this product except in compliance with the License.
 *
 *      This product includes a number of subcomponents with
 *      separate copyright notices and license terms. Your use of these
 *      subcomponents is subject to the terms and conditions of the
 *      subcomponent's license, as noted in the LICENSE file.
 * *****************************************************************************
 */
package org.cloudfoundry.identity.uaa.mock.config;

import com.googlecode.flyway.core.Flyway;
import org.cloudfoundry.identity.uaa.test.YamlServletProfileInitializerContextInitializer;
import org.junit.After;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.env.MockEnvironment;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.support.XmlWebApplicationContext;

import static org.springframework.http.MediaType.APPLICATION_JSON;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultHandlers.print;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class HealthzShouldNotBeProtectedMockMvcTests {


    XmlWebApplicationContext webApplicationContext;

    @Test
    public void testHealthzIsNotRejected() throws Exception {
        MockEnvironment mockEnvironment = new MockEnvironment();
        mockEnvironment.setProperty("require_https", "true");
        webApplicationContext = new XmlWebApplicationContext();
        webApplicationContext.setEnvironment(mockEnvironment);
        new YamlServletProfileInitializerContextInitializer().initializeContext(webApplicationContext, "uaa.yml,login.yml");
        webApplicationContext.setConfigLocation("file:./src/main/webapp/WEB-INF/spring-servlet.xml");
        webApplicationContext.refresh();
        FilterChainProxy springSecurityFilterChain = (FilterChainProxy)webApplicationContext.getBean("org.springframework.security.filterChainProxy");

        MockMvc mockMvc = MockMvcBuilders.webAppContextSetup(webApplicationContext).addFilter(springSecurityFilterChain).build();
        MockHttpServletRequestBuilder get = get("/healthz")
            .accept(MediaType.APPLICATION_JSON);

        mockMvc.perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string("ok\n"));


        get = get("/healthz")
            .accept(MediaType.TEXT_HTML);

        mockMvc.perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string("ok\n"));

        get = get("/healthz")
            .accept(MediaType.ALL);

        mockMvc.perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string("ok\n"));

    }

    @After
    public void tearDown() throws Exception{
        Flyway flyway = webApplicationContext.getBean(Flyway.class);
        flyway.clean();
        webApplicationContext.destroy();
    }


}
