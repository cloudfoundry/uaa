/*
 * ****************************************************************************
 *     Cloud Foundry
 *     Copyright (c) [2009-2017] Pivotal Software, Inc. All Rights Reserved.
 *
 *     This product is licensed to you under the Apache License, Version 2.0 (the "License").
 *     You may not use this product except in compliance with the License.
 *
 *     This product includes a number of subcomponents with
 *     separate copyright notices and license terms. Your use of these
 *     subcomponents is subject to the terms and conditions of the
 *     subcomponent's license, as noted in the LICENSE file.
 * ****************************************************************************
 */

package org.cloudfoundry.identity.uaa.metrics;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import java.util.concurrent.CountDownLatch;

import static org.hamcrest.Matchers.greaterThan;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertThat;

public class IdleTimerTests {

    public static final int LOOP_COUNT = 100000;
    private IdleTimer timer;

    @Rule
    public ExpectedException exception = ExpectedException.none();
    public static final int THREAD_COUNT = 10;

    @Before
    public void setup() {
        timer = new IdleTimer();
    }

    @Test
    public void timer_started() throws Exception {
        Thread.sleep(10);
        assertEquals(0, timer.getInflightRequests());
        assertThat(timer.getRunTime(), greaterThan(0l));
        assertThat(timer.getIdleTime(), greaterThan(0l));
    }

    @Test
    public void illegal_end_request() {
        exception.expect(IllegalStateException.class);
        exception.expectMessage("Illegal end request invocation, no request in flight");
        timer.endRequest();
    }

    @Test
    public void while_inflight() throws Exception {
        timer.startRequest();
        long idleTime = timer.getIdleTime();
        assertEquals(1, timer.getInflightRequests());
        timer.startRequest();
        assertEquals(2, timer.getInflightRequests());
        timer.endRequest();
        assertEquals(1, timer.getInflightRequests());
        Thread.sleep(10);
        assertEquals("Idle time should not have changed.", idleTime, timer.getIdleTime());
        timer.endRequest();
        assertEquals(0, timer.getInflightRequests());
        Thread.sleep(10);
        assertThat("Idle time should have changed.", timer.getIdleTime(), greaterThan(idleTime));
    }

    @Test
    public void concurrency_test() throws Exception {
        final CountDownLatch latch = new CountDownLatch(THREAD_COUNT);
        Thread[] threads = new Thread[THREAD_COUNT];
        for (int i = 0; i< THREAD_COUNT; i++) {
            threads[i] = new Thread(() -> {
               for (int loop = 0; loop< LOOP_COUNT; loop++) {
                   try {
                       timer.startRequest();
                   } finally {
                       timer.endRequest();
                   }
               }
               latch.countDown();
            });
        }
        for (int i = 0; i< THREAD_COUNT; i++) {
            threads[i].start();
        }
        latch.await();
        assertEquals(THREAD_COUNT * LOOP_COUNT, timer.getRequestCount());
        assertEquals(0, timer.getInflightRequests());
    }

}