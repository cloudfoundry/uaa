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

package org.cloudfoundry.identity.uaa.mock.zones;

import org.cloudfoundry.identity.uaa.DefaultTestContext;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneResolvingFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@DefaultTestContext
class IdentityZoneResolvingMockMvcTest {

    private Set<String> originalHostnames;

    private MockMvc mockMvc;
    private IdentityZoneResolvingFilter identityZoneResolvingFilter;

    @BeforeEach
    void storeSettings(
            @Autowired MockMvc mockMvc,
            @Autowired FilterRegistrationBean<IdentityZoneResolvingFilter> identityZoneResolvingFilter
    ) {
        this.mockMvc = mockMvc;
        this.identityZoneResolvingFilter = identityZoneResolvingFilter.getFilter();

        originalHostnames = this.identityZoneResolvingFilter.getDefaultZoneHostnames();
    }

    @AfterEach
    void restoreSettings() {
        identityZoneResolvingFilter.restoreDefaultHostnames(originalHostnames);
    }

    @Test
    void switchingZones() throws Exception {
        // Authenticate with new Client in new Zone
        mockMvc.perform(
                        get("/login")
                                .header("Host", "testsomeother.ip.com")
                )
                .andExpect(status().isOk());
    }

    @Nested
    @DefaultTestContext
    class WithCustomInternalHostnames {

        @BeforeEach
        void setUp() {
            Set<String> hosts = new HashSet<>(Arrays.asList("localhost", "testsomeother.ip.com"));
            identityZoneResolvingFilter.setDefaultInternalHostnames(hosts);
        }

        @ParameterizedTest
        @ValueSource(strings = {"localhost", "testsomeother.ip.com"})
        void isFound(String hostname) throws Exception {
            // Authenticate with new Client in new Zone
            mockMvc.perform(
                            get("/login")
                                    .header("Host", hostname)
                    )
                    .andExpect(status().isOk());

        }

        @ParameterizedTest
        @ValueSource(strings = {"notlocalhost", "testsomeother2.ip.com"})
        void isNotFound(String hostname) throws Exception {
            mockMvc.perform(
                            get("/login")
                                    .header("Host", hostname)
                    )
                    .andExpect(status().isNotFound());
        }
    }
}
