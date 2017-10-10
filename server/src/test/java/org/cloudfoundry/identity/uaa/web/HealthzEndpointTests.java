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
package org.cloudfoundry.identity.uaa.web;

import org.cloudfoundry.identity.uaa.health.HealthzEndpoint;
import org.hamcrest.Matchers;
import org.junit.Test;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class HealthzEndpointTests {

    private static final int SLEEP_UPON_SHUTDOWN = 150;

    private HealthzEndpoint endpoint = new HealthzEndpoint(SLEEP_UPON_SHUTDOWN);
    private MockHttpServletResponse response = new MockHttpServletResponse();

    @Test
    public void testGetHealthz() throws Exception {
        assertEquals("ok\n", endpoint.getHealthz(response));
    }

    @Test
    public void shutdown_sends_stopping() throws Exception {
        long now = System.currentTimeMillis();
        assertEquals("ok\n", endpoint.getHealthz(response));
        runShutdownHook();
        assertEquals("stopping\n", endpoint.getHealthz(response));
        assertEquals(503, response.getStatus());
        long after = System.currentTimeMillis();
        assertThat(after, Matchers.greaterThanOrEqualTo(now+SLEEP_UPON_SHUTDOWN));
    }

    @Test
    public void shutdown_without_sleep() throws Exception {
        long now = System.currentTimeMillis();
        endpoint = new HealthzEndpoint(-1);
        runShutdownHook();
        assertEquals("stopping\n", endpoint.getHealthz(response));
        assertEquals(503, response.getStatus());
        long after = System.currentTimeMillis();
        assertThat(after, Matchers.lessThanOrEqualTo(now+SLEEP_UPON_SHUTDOWN));
    }

    protected void runShutdownHook() {
        Object t = ReflectionTestUtils.getField(endpoint, "shutdownhook");
        ReflectionTestUtils.invokeMethod(t, "run");
        ReflectionTestUtils.invokeMethod(t, "join");
    }

}
