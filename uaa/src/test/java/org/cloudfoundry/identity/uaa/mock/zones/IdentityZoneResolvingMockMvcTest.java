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

import org.cloudfoundry.identity.uaa.mock.InjectedMockContextTest;
import org.cloudfoundry.identity.uaa.zone.IdentityZoneResolvingFilter;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

public class IdentityZoneResolvingMockMvcTest extends InjectedMockContextTest {

    private Set<String> originalHostnames;
    @Before
    public void storeSettings() throws Exception {
        originalHostnames = getWebApplicationContext().getBean(IdentityZoneResolvingFilter.class).getDefaultZoneHostnames();
    }

    @After
    public void restoreSettings() throws Exception {
        getWebApplicationContext().getBean(IdentityZoneResolvingFilter.class).restoreDefaultHostnames(originalHostnames);
    }

    @Test
    public void testSwitchingZones() throws Exception {
        // Authenticate with new Client in new Zone
        getMockMvc().perform(
            get("/login")
                .header("Host", "testsomeother.ip.com")
        )
            .andExpect(status().isOk());
    }

    @Test
    public void testSwitchingZones_When_HostsConfigured() throws Exception {
        Set<String> hosts = new HashSet<>(Arrays.asList("localhost", "testsomeother.ip.com"));
        getWebApplicationContext().getBean(IdentityZoneResolvingFilter.class).setDefaultInternalHostnames(hosts);
        // Authenticate with new Client in new Zone
        getMockMvc().perform(
            get("/login")
                .header("Host", "testsomeother.ip.com")
        )
            .andExpect(status().isOk());
        getMockMvc().perform(
            get("/login")
                .header("Host", "localhost")
        )
            .andExpect(status().isOk());

        getMockMvc().perform(
            get("/login")
                .header("Host", "testsomeother2.ip.com")
        )
            .andExpect(status().isNotFound());
    }



}
