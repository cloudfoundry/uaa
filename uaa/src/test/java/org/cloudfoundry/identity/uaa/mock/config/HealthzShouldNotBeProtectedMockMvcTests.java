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

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.security.web.SecurityFilterChainPostProcessor;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class HealthzShouldNotBeProtectedMockMvcTests extends InjectedMockContextTest {

    SecurityFilterChainPostProcessor chainPostProcessor = null;
    boolean originalSettings;

    @Before
    public void setUp() throws Exception {
        chainPostProcessor = getWebApplicationContext().getBean(SecurityFilterChainPostProcessor.class);
        originalSettings = getWebApplicationContext().getBean(SecurityFilterChainPostProcessor.class).isRequireHttps();
    }

    @After
    public void restore() {
        chainPostProcessor.setRequireHttps(originalSettings);
    }

    @Test
    public void testHealthzIsNotRejected() throws Exception {
        chainPostProcessor.setRequireHttps(true);

        MockHttpServletRequestBuilder get = get("/healthz")
            .accept(MediaType.APPLICATION_JSON);

        getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string("ok\n"));


        get = get("/healthz")
            .accept(MediaType.TEXT_HTML);

        getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string("ok\n"));

        get = get("/healthz")
            .accept(MediaType.ALL);

        getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string("ok\n"));

        get = get("/login")
            .accept(MediaType.TEXT_HTML);

        getMockMvc().perform(get)
            .andExpect(status().is3xxRedirection());

        //non ui gets bad request
        get = get("/saml/metadata")
            .accept(MediaType.ALL);

        getMockMvc().perform(get)
            .andExpect(status().isBadRequest());
    }

    @Test
    public void testNothingIsRejected() throws Exception {
        chainPostProcessor.setRequireHttps(false);

        MockHttpServletRequestBuilder get = get("/healthz")
            .accept(MediaType.APPLICATION_JSON);

        getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string("ok\n"));


        get = get("/healthz")
            .accept(MediaType.TEXT_HTML);

        getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string("ok\n"));

        get = get("/healthz")
            .accept(MediaType.ALL);

        getMockMvc().perform(get)
            .andExpect(status().isOk())
            .andExpect(content().string("ok\n"));

        get = get("/login")
            .accept(MediaType.TEXT_HTML);

        getMockMvc().perform(get)
            .andExpect(status().isOk());

        //non ui gets ok
        get = get("/saml/metadata")
            .accept(MediaType.ALL);

        getMockMvc().perform(get)
            .andExpect(status().isOk());


    }


}
